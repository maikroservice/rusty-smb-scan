use crate::error::{Result, SmbError};

/// All supported authentication methods.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    /// Standard username + password.
    Password {
        username: String,
        password: String,
        domain: Option<String>,
    },
    /// Pass-the-hash: provide the LM and NT hash in hex (32 chars each).
    /// Use an empty string for the LM hash if only the NT hash is available.
    NtlmHash {
        username: String,
        /// 32-char hex string or empty string.
        lm_hash: String,
        /// 32-char hex string.
        nt_hash: String,
        domain: Option<String>,
    },
    /// Use a Kerberos ticket from the credential cache pointed to by `KRB5CCNAME`.
    Kerberos { username: String, realm: String },
    /// Anonymous / unauthenticated session.
    Null,
    /// Explicit guest login.
    Guest,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub method: AuthMethod,
    /// Workgroup or AD domain hint passed to the SMB context.
    pub workgroup: Option<String>,
}

impl Credentials {
    pub fn new(method: AuthMethod) -> Self {
        Self {
            method,
            workgroup: None,
        }
    }

    pub fn with_workgroup(mut self, wg: impl Into<String>) -> Self {
        self.workgroup = Some(wg.into());
        self
    }

    /// Validate the credentials without making any network calls.
    pub fn validate(&self) -> Result<()> {
        match &self.method {
            AuthMethod::NtlmHash {
                nt_hash, lm_hash, ..
            } => {
                validate_hash("NT hash", nt_hash, 32)?;
                // LM hash is optional — empty means "not provided"
                if !lm_hash.is_empty() {
                    validate_hash("LM hash", lm_hash, 32)?;
                }
                Ok(())
            }
            AuthMethod::Kerberos { realm, .. } => {
                if realm.is_empty() {
                    Err(SmbError::InvalidCredentials(
                        "Kerberos realm must not be empty".into(),
                    ))
                } else {
                    Ok(())
                }
            }
            AuthMethod::Password { username, .. } => {
                if username.is_empty() {
                    Err(SmbError::InvalidCredentials(
                        "username must not be empty for password auth".into(),
                    ))
                } else {
                    Ok(())
                }
            }
            AuthMethod::Null | AuthMethod::Guest => Ok(()),
        }
    }

    /// Convenience: the display username (for logging / error messages).
    pub fn display_username(&self) -> &str {
        match &self.method {
            AuthMethod::Password { username, .. } => username,
            AuthMethod::NtlmHash { username, .. } => username,
            AuthMethod::Kerberos { username, .. } => username,
            AuthMethod::Null => "<null>",
            AuthMethod::Guest => "guest",
        }
    }
}

fn validate_hash(label: &str, hash: &str, expected_len: usize) -> Result<()> {
    if hash.len() != expected_len {
        return Err(SmbError::InvalidCredentials(format!(
            "{label} must be exactly {expected_len} hex characters, got {}",
            hash.len()
        )));
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SmbError::InvalidCredentials(format!(
            "{label} must contain only hex characters (0-9, a-f, A-F)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // ── AuthMethod::Password ──────────────────────────────────────────────────

    #[test]
    fn password_with_username_is_valid() {
        let creds = Credentials::new(AuthMethod::Password {
            username: "alice".into(),
            password: "s3cr3t".into(),
            domain: None,
        });
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn password_with_empty_username_is_invalid() {
        let creds = Credentials::new(AuthMethod::Password {
            username: "".into(),
            password: "pass".into(),
            domain: None,
        });
        assert!(matches!(
            creds.validate(),
            Err(SmbError::InvalidCredentials(_))
        ));
    }

    #[test]
    fn password_with_optional_domain() {
        let creds = Credentials::new(AuthMethod::Password {
            username: "bob".into(),
            password: "pass".into(),
            domain: Some("CORP".into()),
        });
        assert!(creds.validate().is_ok());
    }

    // ── AuthMethod::NtlmHash ──────────────────────────────────────────────────

    #[test]
    fn ntlm_hash_valid_32_char_hex() {
        let creds = Credentials::new(AuthMethod::NtlmHash {
            username: "alice".into(),
            lm_hash: "aad3b435b51404eeaad3b435b51404ee".into(),
            nt_hash: "8846f7eaee8fb117ad06bdd830b7586c".into(),
            domain: None,
        });
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn ntlm_hash_nt_only_empty_lm_is_valid() {
        let creds = Credentials::new(AuthMethod::NtlmHash {
            username: "alice".into(),
            lm_hash: "".into(), // empty = not provided
            nt_hash: "8846f7eaee8fb117ad06bdd830b7586c".into(),
            domain: None,
        });
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn ntlm_hash_nt_too_short_is_invalid() {
        let creds = Credentials::new(AuthMethod::NtlmHash {
            username: "alice".into(),
            lm_hash: "".into(),
            nt_hash: "8846f7ea".into(), // only 8 chars
            domain: None,
        });
        let err = creds.validate().unwrap_err();
        assert!(
            err.to_string().contains("32"),
            "expected '32' in error: {err}"
        );
    }

    #[test]
    fn ntlm_hash_nt_non_hex_is_invalid() {
        let creds = Credentials::new(AuthMethod::NtlmHash {
            username: "alice".into(),
            lm_hash: "".into(),
            nt_hash: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".into(), // 32 chars but not hex
            domain: None,
        });
        assert!(matches!(
            creds.validate(),
            Err(SmbError::InvalidCredentials(_))
        ));
    }

    #[test]
    fn ntlm_hash_lm_wrong_length_is_invalid() {
        let creds = Credentials::new(AuthMethod::NtlmHash {
            username: "alice".into(),
            lm_hash: "aad3b435".into(), // too short
            nt_hash: "8846f7eaee8fb117ad06bdd830b7586c".into(),
            domain: None,
        });
        assert!(creds.validate().is_err());
    }

    #[test]
    fn ntlm_hash_uppercase_hex_is_valid() {
        let creds = Credentials::new(AuthMethod::NtlmHash {
            username: "alice".into(),
            lm_hash: "AAD3B435B51404EEAAD3B435B51404EE".into(),
            nt_hash: "8846F7EAEE8FB117AD06BDD830B7586C".into(),
            domain: None,
        });
        assert!(creds.validate().is_ok());
    }

    // ── AuthMethod::Kerberos ──────────────────────────────────────────────────

    #[test]
    fn kerberos_with_realm_is_valid() {
        let creds = Credentials::new(AuthMethod::Kerberos {
            username: "alice".into(),
            realm: "CORP.LOCAL".into(),
        });
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn kerberos_with_empty_realm_is_invalid() {
        let creds = Credentials::new(AuthMethod::Kerberos {
            username: "alice".into(),
            realm: "".into(),
        });
        assert!(matches!(
            creds.validate(),
            Err(SmbError::InvalidCredentials(_))
        ));
    }

    // ── AuthMethod::Null / Guest ──────────────────────────────────────────────

    #[test]
    fn null_always_valid() {
        assert!(Credentials::new(AuthMethod::Null).validate().is_ok());
    }

    #[test]
    fn guest_always_valid() {
        assert!(Credentials::new(AuthMethod::Guest).validate().is_ok());
    }

    // ── display_username ──────────────────────────────────────────────────────

    #[test]
    fn display_username_password() {
        let c = Credentials::new(AuthMethod::Password {
            username: "bob".into(),
            password: "x".into(),
            domain: None,
        });
        assert_eq!(c.display_username(), "bob");
    }

    #[test]
    fn display_username_null() {
        assert_eq!(Credentials::new(AuthMethod::Null).display_username(), "<null>");
    }

    #[test]
    fn display_username_guest() {
        assert_eq!(Credentials::new(AuthMethod::Guest).display_username(), "guest");
    }

    // ── workgroup builder ────────────────────────────────────────────────────

    #[test]
    fn with_workgroup_sets_field() {
        let c = Credentials::new(AuthMethod::Null).with_workgroup("WORKGROUP");
        assert_eq!(c.workgroup.as_deref(), Some("WORKGROUP"));
    }
}
