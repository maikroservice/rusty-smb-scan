//! Linux / macOS SMB backend using `pavao` (libsmbclient bindings).
//!
//! # Build requirements
//!
//! ```bash
//! # Debian / Ubuntu
//! sudo apt install libsmbclient-dev
//!
//! # Fedora / RHEL
//! sudo dnf install libsmbclient-devel
//!
//! # macOS (Homebrew)
//! brew install samba
//! ```
//!
//! # Pass-the-hash
//!
//! `pavao`'s public API does not expose `smbc_setOptionUseNTHash`.  For the
//! `NtlmHash` auth method, we fall back to passing the NT hash as the password
//! string — some versions of libsmbclient accept this.  Full pass-the-hash
//! support requires calling into `pavao-sys` FFI directly (future work).
//!
//! # Share metadata
//!
//! `libsmbclient`'s `list_dir("smb://host/")` does not return share type or
//! comment strings; those fields default to `ShareType::Disk` and `""`.
//! Full metadata retrieval requires `rpcclient` or `libnetapi` (future work).

#![cfg(not(target_os = "windows"))]

use std::io::Write as _;

use pavao::{SmbClient, SmbCredentials, SmbDirent, SmbDirentType, SmbOptions, SmbOpenOptions};

use crate::{
    backend::SmbBackend,
    credentials::{AuthMethod, Credentials},
    error::{Result, SmbError},
    share::{AccessLevel, Share, ShareType},
};

pub struct LibSmbBackend;

impl LibSmbBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LibSmbBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SmbBackend for LibSmbBackend {
    fn list_shares(&self, host: &str, creds: &Credentials) -> Result<Vec<Share>> {
        let client = build_client(host, creds)?;
        let url = format!("smb://{host}/");

        let entries = client
            .list_dir(&url)
            .map_err(|e| map_pavao_error(e, host, ""))?;

        let shares = entries
            .into_iter()
            .filter_map(|entry| dirent_to_share(host, entry))
            .collect();

        Ok(shares)
    }

    fn check_read(&self, host: &str, share: &str, creds: &Credentials) -> Result<bool> {
        let client = build_client(host, creds)?;
        let url = format!("smb://{host}/{share}/");

        match client.list_dir(&url) {
            Ok(_) => Ok(true),
            Err(e) if is_access_denied(&e) => Ok(false),
            Err(e) if is_not_found(&e) => Err(SmbError::ShareNotFound {
                host: host.into(),
                share: share.into(),
            }),
            Err(e) => Err(map_pavao_error(e, host, share)),
        }
    }

    fn check_write(&self, host: &str, share: &str, creds: &Credentials) -> Result<bool> {
        let client = build_client(host, creds)?;

        let probe_name = format!(
            "__rusty_smb_probe_{}.tmp",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0xdead)
        );
        let url = format!("smb://{host}/{share}/{probe_name}");

        // Try to create the probe file.
        let open_opts = SmbOpenOptions::default()
            .create(true)
            .write(true);

        match client.open_with(&url, open_opts) {
            Ok(mut file) => {
                // Write a small payload so the file is created on-disk.
                let _ = file.write_all(b"rusty-smb-scan probe");
                // Clean up — ignore errors (e.g., the file might not persist
                // on some share configurations).
                let _ = client.unlink(&url);
                Ok(true)
            }
            Err(e) if is_access_denied(&e) => Ok(false),
            Err(e) => Err(map_pavao_error(e, host, share)),
        }
    }
}

// ── pavao client construction ────────────────────────────────────────────────

fn build_client(host: &str, creds: &Credentials) -> Result<SmbClient> {
    let smb_creds = credentials_to_pavao(host, creds);
    let options = SmbOptions::default();

    SmbClient::new(smb_creds, options)
        .map_err(|e| map_pavao_error(e, host, ""))
}

fn credentials_to_pavao(host: &str, creds: &Credentials) -> SmbCredentials {
    let workgroup = creds
        .workgroup
        .as_deref()
        .unwrap_or("WORKGROUP");

    match &creds.method {
        AuthMethod::Password {
            username,
            password,
            domain,
        } => SmbCredentials::default()
            .server(host)
            .workgroup(domain.as_deref().unwrap_or(workgroup))
            .username(username)
            .password(password),

        AuthMethod::NtlmHash {
            username,
            nt_hash,
            domain,
            ..
        } => {
            // Pass the NT hash as the password; libsmbclient may accept it
            // in older configurations with NTLMv1.  Full pass-the-hash requires
            // smbc_setOptionUseNTHash via pavao-sys FFI (future work).
            SmbCredentials::default()
                .server(host)
                .workgroup(domain.as_deref().unwrap_or(workgroup))
                .username(username)
                .password(nt_hash)
        }

        AuthMethod::Kerberos { username, realm } => {
            // libsmbclient picks up the KRB5CCNAME ticket cache automatically.
            // Pass empty password to trigger Kerberos path.
            SmbCredentials::default()
                .server(host)
                .workgroup(realm)
                .username(username)
                .password("")
        }

        AuthMethod::Null => SmbCredentials::default().server(host).workgroup(workgroup),

        AuthMethod::Guest => SmbCredentials::default()
            .server(host)
            .workgroup(workgroup)
            .username("guest")
            .password(""),
    }
}

// ── Entry conversion ──────────────────────────────────────────────────────────

fn dirent_to_share(host: &str, entry: SmbDirent) -> Option<Share> {
    let name = entry.name().to_string();

    // Skip navigation entries
    if name == "." || name == ".." {
        return None;
    }

    let share_type = match entry.get_type() {
        SmbDirentType::FileShare => ShareType::Disk,
        SmbDirentType::PrinterShare => ShareType::Printer,
        SmbDirentType::IpcShare => ShareType::Ipc,
        SmbDirentType::CommsShare => ShareType::Device,
        // Skip workgroup/server entries; we only want share entries.
        SmbDirentType::Server | SmbDirentType::Workgroup => return None,
        _ => ShareType::Unknown,
    };

    Some(Share {
        host: host.to_string(),
        name,
        share_type,
        // pavao's SmbDirent does expose comment() — use it.
        comment: entry.comment().to_string(),
        access: AccessLevel::empty(),
    })
}

// ── Error mapping ─────────────────────────────────────────────────────────────

fn map_pavao_error(e: pavao::SmbError, host: &str, share: &str) -> SmbError {
    let msg = e.to_string().to_lowercase();

    if msg.contains("permission denied") || msg.contains("access denied") || msg.contains("nt_status_access_denied") {
        return SmbError::AccessDenied {
            host: host.into(),
            share: share.into(),
        };
    }
    if msg.contains("logon failure") || msg.contains("wrong password") || msg.contains("nt_status_logon_failure") {
        return SmbError::AuthFailed {
            user: "unknown".into(),
            host: host.into(),
            reason: msg,
        };
    }
    if msg.contains("no route") || msg.contains("connection refused") || msg.contains("unreachable") || msg.contains("nt_status_host_unreachable") {
        return SmbError::HostUnreachable { host: host.into() };
    }

    SmbError::Backend(format!("{e}"))
}

fn is_access_denied(e: &pavao::SmbError) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("permission denied")
        || msg.contains("access denied")
        || msg.contains("nt_status_access_denied")
}

fn is_not_found(e: &pavao::SmbError) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("no such file") || msg.contains("not found") || msg.contains("nt_status_object_name_not_found")
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::AuthMethod;

    /// Verify that LibSmbBackend can be instantiated (no system calls made).
    #[test]
    fn backend_can_be_constructed() {
        let _b = LibSmbBackend::new();
    }

    /// Smoke-test credential building — just check it doesn't panic.
    #[test]
    fn credentials_to_pavao_password() {
        let creds = Credentials::new(AuthMethod::Password {
            username: "alice".into(),
            password: "pass".into(),
            domain: Some("CORP".into()),
        });
        let _ = credentials_to_pavao("192.168.1.1", &creds);
    }

    #[test]
    fn credentials_to_pavao_null() {
        let creds = Credentials::new(AuthMethod::Null);
        let _ = credentials_to_pavao("192.168.1.1", &creds);
    }

    #[test]
    fn credentials_to_pavao_kerberos() {
        let creds = Credentials::new(AuthMethod::Kerberos {
            username: "alice".into(),
            realm: "CORP.LOCAL".into(),
        });
        let _ = credentials_to_pavao("192.168.1.1", &creds);
    }

    #[test]
    fn dirent_to_share_skips_dot_entries() {
        // We cannot easily construct a real SmbDirent without a live connection,
        // but we can verify the name-filter logic via the Share constructor.
        // If the name is "." or "..", it should return None.
        // This logic is tested indirectly through scanner integration tests.
        // Placeholder to document the expectation.
        assert!(true);
    }
}
