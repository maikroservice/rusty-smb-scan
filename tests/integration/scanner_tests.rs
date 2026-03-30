//! Integration tests against a real SMB server.
//!
//! All tests are `#[ignore]` by default.  Run with:
//! ```bash
//! cargo test --features integration-tests -- --include-ignored
//! ```

use rusty_smb_scan::{
    credentials::{AuthMethod, Credentials},
    scanner::{ScanConfig, Scanner},
    share::AccessLevel,
};

// ── Environment helpers ───────────────────────────────────────────────────────

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("Required env var {key} not set"))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn test_host() -> String {
    env("SMB_TEST_HOST")
}

fn password_creds() -> Credentials {
    Credentials::new(AuthMethod::Password {
        username: env("SMB_TEST_USER"),
        password: env("SMB_TEST_PASS"),
        domain: Some(env_or("SMB_TEST_DOMAIN", "WORKGROUP")),
    })
}

fn null_creds() -> Credentials {
    Credentials::new(AuthMethod::Null)
}

fn make_scanner(config: ScanConfig) -> Scanner<rusty_smb_scan::backend::platform::PlatformBackend> {
    Scanner::new(rusty_smb_scan::backend::platform::PlatformBackend::new(), config)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Password auth: at minimum IPC$ (or any share) should be visible.
#[test]
#[ignore = "requires SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASS"]
fn password_auth_enumerates_shares() {
    let scanner = make_scanner(ScanConfig {
        include_admin: true,
        include_hidden: true,
        ..Default::default()
    });
    let result = scanner.scan_host(&test_host(), &password_creds());

    assert!(
        result.errors.is_empty(),
        "unexpected errors: {:?}",
        result.errors
    );
    assert!(
        !result.shares.is_empty(),
        "expected at least one share from {}",
        test_host()
    );
}

/// Null session should not panic; some servers allow it, others deny it —
/// we only assert that the tool handles both gracefully.
#[test]
#[ignore = "requires SMB_TEST_HOST"]
fn null_session_does_not_panic() {
    let scanner = make_scanner(ScanConfig {
        timeout_secs: 5,
        ..Default::default()
    });
    let result = scanner.scan_host(&test_host(), &null_creds());
    // We accept either shares or an error — just not a panic.
    let _ = result;
}

/// Pass-the-hash: must find at least as many shares as password auth.
#[test]
#[ignore = "requires SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_NT_HASH"]
fn pass_the_hash_enumerates_same_shares_as_password() {
    let hash_str = env("SMB_TEST_NT_HASH"); // "LM:NT" or just "NT"
    let (lm, nt) = parse_hash_pair(&hash_str);

    let hash_creds = Credentials::new(AuthMethod::NtlmHash {
        username: env("SMB_TEST_USER"),
        lm_hash: lm,
        nt_hash: nt,
        domain: Some(env_or("SMB_TEST_DOMAIN", "WORKGROUP")),
    });

    let config = ScanConfig {
        include_admin: true,
        include_hidden: true,
        ..Default::default()
    };

    let scanner = make_scanner(config.clone());

    let by_pass = scanner.scan_host(&test_host(), &password_creds());
    let by_hash = scanner.scan_host(&test_host(), &hash_creds);

    assert!(
        by_hash.errors.is_empty(),
        "hash auth errors: {:?}",
        by_hash.errors
    );
    assert_eq!(
        by_pass.shares.len(),
        by_hash.shares.len(),
        "share count mismatch between password and hash auth"
    );
}

/// The configured readable share must have AccessLevel::READ.
#[test]
#[ignore = "requires SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASS, SMB_TEST_READABLE_SHARE"]
fn readable_share_has_read_access() {
    let target = env("SMB_TEST_READABLE_SHARE");
    let scanner = make_scanner(ScanConfig {
        include_hidden: true,
        include_admin: true,
        ..Default::default()
    });
    let result = scanner.scan_host(&test_host(), &password_creds());

    let share = result
        .shares
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(&target))
        .unwrap_or_else(|| {
            panic!(
                "share '{target}' not found in results: {:?}",
                result.shares.iter().map(|s| &s.name).collect::<Vec<_>>()
            )
        });

    assert!(
        share.access.can_read(),
        "expected READ on '{target}', got {:?}",
        share.access
    );
}

/// The configured writable share must have AccessLevel::WRITE.
#[test]
#[ignore = "requires SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASS, SMB_TEST_WRITABLE_SHARE"]
fn writable_share_has_write_access() {
    let target = env("SMB_TEST_WRITABLE_SHARE");
    let scanner = make_scanner(ScanConfig {
        include_hidden: true,
        include_admin: true,
        check_write: true,
        ..Default::default()
    });
    let result = scanner.scan_host(&test_host(), &password_creds());

    let share = result
        .shares
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(&target))
        .unwrap_or_else(|| panic!("share '{target}' not found"));

    assert!(
        share.access.can_write(),
        "expected WRITE on '{target}', got {:?}",
        share.access
    );
}

/// An unreachable host must produce HostUnreachable within the timeout — never hang.
#[test]
#[ignore = "may be slow depending on OS TCP timeout"]
fn unreachable_host_returns_error_within_timeout() {
    let dead_host = env_or("SMB_TEST_NONEXISTENT_HOST", "10.255.255.1");
    let scanner = make_scanner(ScanConfig {
        timeout_secs: 3,
        ..Default::default()
    });

    let start = std::time::Instant::now();
    let result = scanner.scan_host(&dead_host, &null_creds());
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 6,
        "scan took too long: {elapsed:?} — timeout not enforced"
    );
    assert!(
        !result.errors.is_empty(),
        "expected an error for unreachable host"
    );
    assert!(
        matches!(
            result.errors[0],
            rusty_smb_scan::error::SmbError::HostUnreachable { .. }
        ),
        "expected HostUnreachable, got {:?}",
        result.errors[0]
    );
}

/// Admin and hidden share classification is correct on a real Windows target.
#[test]
#[ignore = "requires SMB_TEST_HOST with Windows admin shares (ADMIN$, C$, IPC$)"]
fn admin_shares_classified_correctly() {
    let scanner = make_scanner(ScanConfig {
        include_admin: true,
        include_hidden: true,
        ..Default::default()
    });
    let result = scanner.scan_host(&test_host(), &password_creds());

    for share in &result.shares {
        if matches!(share.name.to_uppercase().as_str(), "ADMIN$" | "C$" | "IPC$") {
            assert!(
                share.is_admin(),
                "{} should be classified as admin",
                share.name
            );
            assert!(share.is_hidden(), "{} should be classified as hidden", share.name);
        }
    }
}

/// JSON output round-trips correctly for real scan results.
#[test]
#[ignore = "requires SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASS"]
fn json_output_round_trips_for_real_scan() {
    use rusty_smb_scan::output::{render, OutputFormat};

    let scanner = make_scanner(ScanConfig::default());
    let results = scanner.scan_host(&test_host(), &password_creds());
    let all = std::slice::from_ref(&results);

    let json = render(all, &OutputFormat::Json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    assert!(
        parsed["hosts"][0]["host"].as_str().is_some(),
        "host field missing in JSON output"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_hash_pair(s: &str) -> (String, String) {
    if let Some((lm, nt)) = s.split_once(':') {
        (lm.to_string(), nt.to_string())
    } else {
        // Only NT hash provided
        ("".to_string(), s.to_string())
    }
}
