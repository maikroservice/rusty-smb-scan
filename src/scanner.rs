use std::{
    sync::mpsc,
    thread,
    time::Duration,
};

use crate::{
    backend::SmbBackend,
    credentials::Credentials,
    error::SmbError,
    share::{AccessLevel, Share},
};

/// Configuration for a scan run.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Per-host timeout in seconds.
    pub timeout_secs: u64,
    /// Include shares whose names end with `$`.
    pub include_hidden: bool,
    /// Include well-known admin shares (ADMIN$, C$, IPC$, …).
    pub include_admin: bool,
    /// Probe write access (creates and deletes a temporary probe file).
    pub check_write: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            include_hidden: false,
            include_admin: false,
            check_write: false,
        }
    }
}

/// Results for a single host.
#[derive(Debug)]
pub struct HostResult {
    pub host: String,
    pub shares: Vec<Share>,
    /// Non-fatal errors encountered during the scan of this host.
    pub errors: Vec<SmbError>,
}

pub struct Scanner<B: SmbBackend> {
    backend: B,
    config: ScanConfig,
}

impl<B: SmbBackend + 'static> Scanner<B> {
    pub fn new(backend: B, config: ScanConfig) -> Self {
        Self { backend, config }
    }

    /// Scan a list of hosts, returning one `HostResult` per host.
    /// A failure on one host never aborts the others.
    pub fn scan(&self, hosts: &[String], creds: &Credentials) -> Vec<HostResult> {
        hosts
            .iter()
            .map(|h| self.scan_host(h, creds))
            .collect()
    }

    /// Scan a single host.
    pub fn scan_host(&self, host: &str, creds: &Credentials) -> HostResult {
        let mut result = HostResult {
            host: host.to_string(),
            shares: vec![],
            errors: vec![],
        };

        let raw_shares = match self.list_shares_with_timeout(host, creds) {
            Ok(s) => s,
            Err(e) => {
                result.errors.push(e);
                return result;
            }
        };

        for mut share in raw_shares {
            // Apply filters
            if share.is_admin() && !self.config.include_admin {
                continue;
            }
            if share.is_hidden() && !share.is_admin() && !self.config.include_hidden {
                continue;
            }

            // Probe read access
            match self.backend.check_read(host, &share.name, creds) {
                Ok(true) => share.access |= AccessLevel::READ,
                Ok(false) => {}
                Err(SmbError::AccessDenied { .. }) => {}
                Err(e) => result.errors.push(e),
            }

            // Probe write access (optional)
            if self.config.check_write && share.access.can_read() {
                match self.backend.check_write(host, &share.name, creds) {
                    Ok(true) => share.access |= AccessLevel::WRITE,
                    Ok(false) => {}
                    Err(SmbError::AccessDenied { .. }) => {}
                    Err(e) => result.errors.push(e),
                }
            }

            result.shares.push(share);
        }

        result
    }

    /// Wraps `backend.list_shares` with a hard timeout enforced via a thread.
    fn list_shares_with_timeout(
        &self,
        host: &str,
        creds: &Credentials,
    ) -> crate::error::Result<Vec<Share>> {
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let (tx, rx) = mpsc::channel();

        // We clone what we need into the thread to avoid lifetime issues.
        // The backend must be `Send + Sync`, so we reference it through a
        // pointer — safe because the thread is joined (or abandoned) before
        // this function returns.
        let backend_ptr: *const B = &self.backend;
        let host_owned = host.to_string();
        let creds_owned = creds.clone();

        // SAFETY: `backend_ptr` is valid for the entire duration of this
        // function (the Scanner is not moved/dropped while we block on `rx`).
        let handle = unsafe {
            let backend_ref: &B = &*backend_ptr;
            thread::spawn(move || {
                let r = backend_ref.list_shares(&host_owned, &creds_owned);
                let _ = tx.send(r);
            })
        };

        match rx.recv_timeout(timeout) {
            Ok(result) => {
                let _ = handle.join();
                result
            }
            Err(_) => {
                // Thread is still running; we cannot join without blocking.
                // The thread will eventually finish and the channel will be
                // dropped — that is acceptable for a CLI tool.
                Err(SmbError::HostUnreachable {
                    host: host.to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::MockSmbBackend,
        credentials::AuthMethod,
        error::SmbError,
        share::{Share, ShareType},
    };
    use mockall::predicate::*;
    use pretty_assertions::assert_eq;

    fn null_creds() -> Credentials {
        Credentials::new(AuthMethod::Null)
    }

    fn make_share(host: &str, name: &str) -> Share {
        Share {
            host: host.into(),
            name: name.into(),
            share_type: ShareType::Disk,
            comment: String::new(),
            access: AccessLevel::empty(),
        }
    }

    // ── Basic scanning ────────────────────────────────────────────────────────

    #[test]
    fn scan_host_returns_shares_with_read_access() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares()
            .returning(|host, _| {
                Ok(vec![
                    make_share(host, "docs"),
                    make_share(host, "public"),
                ])
            });

        mock.expect_check_read()
            .returning(|_, share, _| {
                // "docs" is readable, "public" is not
                Ok(share == "docs")
            });

        let scanner = Scanner::new(
            mock,
            ScanConfig {
                include_hidden: true,
                ..Default::default()
            },
        );

        let result = scanner.scan_host("host", &null_creds());
        assert_eq!(result.shares.len(), 2);

        let docs = result.shares.iter().find(|s| s.name == "docs").unwrap();
        assert!(docs.access.can_read(), "docs should be readable");

        let public = result.shares.iter().find(|s| s.name == "public").unwrap();
        assert!(!public.access.can_read(), "public should NOT be readable");
    }

    #[test]
    fn scan_host_probes_write_when_configured() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares()
            .returning(|host, _| Ok(vec![make_share(host, "uploads")]));

        mock.expect_check_read().returning(|_, _, _| Ok(true));
        mock.expect_check_write().returning(|_, _, _| Ok(true));

        let scanner = Scanner::new(
            mock,
            ScanConfig {
                check_write: true,
                include_hidden: true,
                ..Default::default()
            },
        );

        let result = scanner.scan_host("host", &null_creds());
        let share = &result.shares[0];
        assert!(share.access.can_read());
        assert!(share.access.can_write());
    }

    #[test]
    fn scan_host_does_not_probe_write_when_not_configured() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares()
            .returning(|host, _| Ok(vec![make_share(host, "share")]));

        mock.expect_check_read().returning(|_, _, _| Ok(true));
        // check_write must NOT be called
        mock.expect_check_write().never();

        let scanner = Scanner::new(mock, ScanConfig::default());
        scanner.scan_host("host", &null_creds());
    }

    #[test]
    fn scan_host_skips_write_probe_when_read_denied() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares()
            .returning(|host, _| Ok(vec![make_share(host, "locked")]));

        mock.expect_check_read().returning(|_, _, _| Ok(false));
        mock.expect_check_write().never(); // should not be called

        let scanner = Scanner::new(
            mock,
            ScanConfig {
                check_write: true,
                include_hidden: true,
                ..Default::default()
            },
        );
        let result = scanner.scan_host("host", &null_creds());
        assert!(!result.shares[0].access.can_write());
    }

    // ── Error handling ────────────────────────────────────────────────────────

    #[test]
    fn host_unreachable_captured_as_error_not_panic() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares().returning(|host, _| {
            Err(SmbError::HostUnreachable {
                host: host.to_string(),
            })
        });

        let scanner = Scanner::new(mock, ScanConfig::default());
        let result = scanner.scan_host("dead.host", &null_creds());

        assert!(result.shares.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(matches!(result.errors[0], SmbError::HostUnreachable { .. }));
    }

    #[test]
    fn access_denied_on_check_read_is_silent() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares()
            .returning(|host, _| Ok(vec![make_share(host, "private")]));

        mock.expect_check_read().returning(|_, share, _| {
            Err(SmbError::AccessDenied {
                host: "host".into(),
                share: share.to_string(),
            })
        });

        let scanner = Scanner::new(mock, ScanConfig {
            include_hidden: true,
            ..Default::default()
        });
        let result = scanner.scan_host("host", &null_creds());

        // No access level set, but no error propagated either
        assert_eq!(result.errors.len(), 0);
        assert!(!result.shares[0].access.can_read());
    }

    #[test]
    fn backend_error_on_check_read_is_captured() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares()
            .returning(|host, _| Ok(vec![make_share(host, "broken")]));

        mock.expect_check_read().returning(|_, _, _| {
            Err(SmbError::Backend("connection reset".into()))
        });

        let scanner = Scanner::new(mock, ScanConfig {
            include_hidden: true,
            ..Default::default()
        });
        let result = scanner.scan_host("host", &null_creds());

        assert_eq!(result.errors.len(), 1);
        assert!(matches!(result.errors[0], SmbError::Backend(_)));
    }

    // ── Multi-host scanning ───────────────────────────────────────────────────

    #[test]
    fn scan_multiple_hosts_returns_one_result_per_host() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares()
            .returning(|host, _| Ok(vec![make_share(host, "share")]));
        mock.expect_check_read().returning(|_, _, _| Ok(false));

        let scanner = Scanner::new(mock, ScanConfig {
            include_hidden: true,
            ..Default::default()
        });
        let hosts: Vec<String> = vec!["h1".into(), "h2".into(), "h3".into()];
        let results = scanner.scan(&hosts, &null_creds());

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].host, "h1");
        assert_eq!(results[1].host, "h2");
        assert_eq!(results[2].host, "h3");
    }

    #[test]
    fn scan_one_failed_host_does_not_abort_others() {
        let mut mock = MockSmbBackend::new();

        // h1 succeeds, h2 fails, h3 succeeds
        mock.expect_list_shares().returning(|host, _| {
            if host == "h2" {
                Err(SmbError::HostUnreachable { host: host.to_string() })
            } else {
                Ok(vec![make_share(host, "data")])
            }
        });
        mock.expect_check_read().returning(|_, _, _| Ok(true));

        let scanner = Scanner::new(mock, ScanConfig {
            include_hidden: true,
            ..Default::default()
        });
        let hosts: Vec<String> = vec!["h1".into(), "h2".into(), "h3".into()];
        let results = scanner.scan(&hosts, &null_creds());

        assert_eq!(results[0].shares.len(), 1);
        assert_eq!(results[1].errors.len(), 1); // h2 failed
        assert_eq!(results[2].shares.len(), 1);
    }

    // ── Filtering ─────────────────────────────────────────────────────────────

    #[test]
    fn admin_shares_excluded_by_default() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares().returning(|host, _| {
            Ok(vec![
                make_share(host, "public"),
                make_share(host, "ADMIN$"),
                make_share(host, "C$"),
                make_share(host, "IPC$"),
            ])
        });
        mock.expect_check_read().returning(|_, _, _| Ok(true));

        let scanner = Scanner::new(mock, ScanConfig::default());
        let result = scanner.scan_host("host", &null_creds());

        let names: Vec<&str> = result.shares.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"public"), "public should be included");
        assert!(!names.contains(&"ADMIN$"), "ADMIN$ should be excluded");
        assert!(!names.contains(&"C$"), "C$ should be excluded");
        assert!(!names.contains(&"IPC$"), "IPC$ should be excluded");
    }

    #[test]
    fn admin_shares_included_when_configured() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares().returning(|host, _| {
            Ok(vec![
                make_share(host, "public"),
                make_share(host, "ADMIN$"),
            ])
        });
        mock.expect_check_read().returning(|_, _, _| Ok(true));

        let scanner = Scanner::new(mock, ScanConfig {
            include_admin: true,
            include_hidden: true,
            ..Default::default()
        });
        let result = scanner.scan_host("host", &null_creds());

        assert_eq!(result.shares.len(), 2);
    }

    #[test]
    fn hidden_shares_excluded_by_default() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares().returning(|host, _| {
            Ok(vec![
                make_share(host, "public"),
                make_share(host, "backup$"),
            ])
        });
        mock.expect_check_read().returning(|_, _, _| Ok(true));

        let scanner = Scanner::new(mock, ScanConfig::default());
        let result = scanner.scan_host("host", &null_creds());

        let names: Vec<&str> = result.shares.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"public"));
        assert!(!names.contains(&"backup$"), "custom hidden shares excluded by default");
    }

    #[test]
    fn hidden_shares_included_when_configured() {
        let mut mock = MockSmbBackend::new();

        mock.expect_list_shares().returning(|host, _| {
            Ok(vec![
                make_share(host, "public"),
                make_share(host, "backup$"),
            ])
        });
        mock.expect_check_read().returning(|_, _, _| Ok(true));

        let scanner = Scanner::new(mock, ScanConfig {
            include_hidden: true,
            ..Default::default()
        });
        let result = scanner.scan_host("host", &null_creds());

        assert_eq!(result.shares.len(), 2);
    }
}
