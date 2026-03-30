use crate::{
    credentials::Credentials,
    error::Result,
    share::Share,
};

/// All SMB network I/O is routed through this trait.
/// The `automock` attribute generates `MockSmbBackend` in test builds so that
/// every scanner unit test runs without a real network connection.
#[cfg_attr(test, mockall::automock)]
pub trait SmbBackend: Send + Sync {
    /// Enumerate all shares visible to the given credentials on `host`.
    fn list_shares(&self, host: &str, creds: &Credentials) -> Result<Vec<Share>>;

    /// Return `true` if the user can list the share's contents.
    fn check_read(&self, host: &str, share: &str, creds: &Credentials) -> Result<bool>;

    /// Return `true` if the user can create (and delete) files in the share.
    /// Implementations must clean up any probe file they create.
    fn check_write(&self, host: &str, share: &str, creds: &Credentials) -> Result<bool>;
}

// Platform-specific backend implementations.
#[cfg(not(target_os = "windows"))]
pub mod libsmb;

#[cfg(target_os = "windows")]
pub mod windows;

pub mod platform;

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    /// Verify that MockSmbBackend is generated and usable.
    #[test]
    fn mock_backend_compiles_and_returns_configured_values() {
        let mut mock = MockSmbBackend::new();
        mock.expect_list_shares()
            .with(eq("host"), always())
            .returning(|_, _| Ok(vec![]));

        let creds = Credentials::new(crate::credentials::AuthMethod::Null);
        let result = mock.list_shares("host", &creds);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
