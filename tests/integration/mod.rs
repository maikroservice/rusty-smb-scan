/// Integration tests require a real SMB server and are gated behind the
/// `integration-tests` feature flag so they never run in a normal `cargo test`.
///
/// # Running integration tests
///
/// ```bash
/// SMB_TEST_HOST=192.168.1.10 \
/// SMB_TEST_USER=testuser \
/// SMB_TEST_PASS=testpass \
/// SMB_TEST_DOMAIN=WORKGROUP \
/// SMB_TEST_READABLE_SHARE=public \
/// SMB_TEST_WRITABLE_SHARE=uploads \
/// cargo test --features integration-tests -- --include-ignored
/// ```
///
/// # Optional variables
///
/// | Variable                | Purpose                                    |
/// |-------------------------|--------------------------------------------|
/// | `SMB_TEST_NT_HASH`      | `LM:NT` hex pair for pass-the-hash tests   |
/// | `SMB_TEST_NONEXISTENT_HOST` | IP that should time out (default: 10.255.255.1) |
/// | `SMB_TEST_KERBEROS_REALM`   | Realm for Kerberos tests                   |

#[cfg(all(test, feature = "integration-tests"))]
pub mod scanner_tests;
