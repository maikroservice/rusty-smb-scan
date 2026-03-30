use thiserror::Error;

#[derive(Debug, Error)]
pub enum SmbError {
    #[error("authentication failed for '{user}' on '{host}': {reason}")]
    AuthFailed {
        user: String,
        host: String,
        reason: String,
    },

    #[error("access denied to \\\\{host}\\{share}")]
    AccessDenied { host: String, share: String },

    #[error("host unreachable: {host}")]
    HostUnreachable { host: String },

    #[error("share not found: \\\\{host}\\{share}")]
    ShareNotFound { host: String, share: String },

    #[error("invalid credentials: {0}")]
    InvalidCredentials(String),

    #[error("backend unavailable on this platform")]
    BackendUnavailable,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("backend error: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, SmbError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failed_display_includes_user_and_host() {
        let e = SmbError::AuthFailed {
            user: "alice".into(),
            host: "192.168.1.1".into(),
            reason: "wrong password".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("alice"), "expected user in: {msg}");
        assert!(msg.contains("192.168.1.1"), "expected host in: {msg}");
        assert!(msg.contains("wrong password"), "expected reason in: {msg}");
    }

    #[test]
    fn access_denied_display_includes_host_and_share() {
        let e = SmbError::AccessDenied {
            host: "fileserver".into(),
            share: "docs".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("fileserver"), "{msg}");
        assert!(msg.contains("docs"), "{msg}");
    }

    #[test]
    fn host_unreachable_display_includes_host() {
        let e = SmbError::HostUnreachable {
            host: "10.0.0.99".into(),
        };
        assert!(e.to_string().contains("10.0.0.99"));
    }

    #[test]
    fn io_error_wraps_via_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let smb_err: SmbError = io_err.into();
        assert!(matches!(smb_err, SmbError::Io(_)));
        assert!(smb_err.to_string().contains("timed out"));
    }

    #[test]
    fn invalid_credentials_carries_message() {
        let e = SmbError::InvalidCredentials("NT hash must be 32 hex chars".into());
        assert!(e.to_string().contains("32 hex chars"));
    }
}
