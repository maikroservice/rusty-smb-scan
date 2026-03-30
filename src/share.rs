use bitflags::bitflags;
use serde::{Deserialize, Serialize};

/// The type of an SMB share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareType {
    /// Standard disk share.
    Disk,
    /// Printer share.
    Printer,
    /// Communications device share.
    Device,
    /// Inter-Process Communication share (IPC$).
    Ipc,
    /// Unknown / unrecognised type.
    Unknown,
}

impl ShareType {
    /// Whether this share type is IPC (special internal pipe share).
    pub fn is_ipc(&self) -> bool {
        matches!(self, ShareType::Ipc)
    }
}

bitflags! {
    /// Which access levels the authenticated user has on a share.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct AccessLevel: u8 {
        const READ  = 0b01;
        const WRITE = 0b10;
    }
}

impl AccessLevel {
    pub fn can_read(self) -> bool {
        self.contains(AccessLevel::READ)
    }

    pub fn can_write(self) -> bool {
        self.contains(AccessLevel::WRITE)
    }

    /// Human-readable summary, e.g. `"read,write"`, `"read"`, `"none"`.
    pub fn display(self) -> &'static str {
        match (self.can_read(), self.can_write()) {
            (true, true) => "read,write",
            (true, false) => "read",
            (false, true) => "write",
            (false, false) => "none",
        }
    }
}

impl Serialize for AccessLevel {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.display())
    }
}

impl<'de> Deserialize<'de> for AccessLevel {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "read,write" => Ok(AccessLevel::READ | AccessLevel::WRITE),
            "read" => Ok(AccessLevel::READ),
            "write" => Ok(AccessLevel::WRITE),
            "none" | "" => Ok(AccessLevel::empty()),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["read,write", "read", "write", "none"],
            )),
        }
    }
}

/// A single SMB share discovered on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub host: String,
    pub name: String,
    pub share_type: ShareType,
    /// Comment / description reported by the server.
    pub comment: String,
    pub access: AccessLevel,
}

impl Share {
    pub fn new(host: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            name: name.into(),
            share_type: ShareType::Disk,
            comment: String::new(),
            access: AccessLevel::empty(),
        }
    }

    /// Share name ends with `$`, making it hidden from casual browsing.
    pub fn is_hidden(&self) -> bool {
        self.name.ends_with('$')
    }

    /// Well-known administrative shares: `ADMIN$`, `C$`…`Z$`, `IPC$`, `PRINT$`, `FAX$`.
    pub fn is_admin(&self) -> bool {
        let upper = self.name.to_uppercase();
        matches!(
            upper.as_str(),
            "ADMIN$" | "IPC$" | "PRINT$" | "FAX$"
        ) || (upper.len() == 2
            && upper.ends_with('$')
            && upper.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
    }

    /// UNC path: `\\host\share`
    pub fn unc_path(&self) -> String {
        format!("\\\\{}\\{}", self.host, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // ── AccessLevel ───────────────────────────────────────────────────────────

    #[test]
    fn access_level_none_has_no_flags() {
        let a = AccessLevel::empty();
        assert!(!a.can_read());
        assert!(!a.can_write());
        assert_eq!(a.display(), "none");
    }

    #[test]
    fn access_level_read_only() {
        let a = AccessLevel::READ;
        assert!(a.can_read());
        assert!(!a.can_write());
        assert_eq!(a.display(), "read");
    }

    #[test]
    fn access_level_write_only() {
        let a = AccessLevel::WRITE;
        assert!(!a.can_read());
        assert!(a.can_write());
        assert_eq!(a.display(), "write");
    }

    #[test]
    fn access_level_read_write() {
        let a = AccessLevel::READ | AccessLevel::WRITE;
        assert!(a.can_read());
        assert!(a.can_write());
        assert_eq!(a.display(), "read,write");
    }

    #[test]
    fn access_level_serde_round_trip() {
        for level in [
            AccessLevel::empty(),
            AccessLevel::READ,
            AccessLevel::WRITE,
            AccessLevel::READ | AccessLevel::WRITE,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: AccessLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back, "round-trip failed for {level:?}");
        }
    }

    #[test]
    fn access_level_deserialize_invalid_string_errors() {
        let result: Result<AccessLevel, _> = serde_json::from_str(r#""execute""#);
        assert!(result.is_err());
    }

    // ── ShareType ─────────────────────────────────────────────────────────────

    #[test]
    fn share_type_ipc_is_ipc() {
        assert!(ShareType::Ipc.is_ipc());
    }

    #[test]
    fn share_type_disk_is_not_ipc() {
        assert!(!ShareType::Disk.is_ipc());
    }

    #[test]
    fn share_type_serde_round_trip() {
        for t in [
            ShareType::Disk,
            ShareType::Printer,
            ShareType::Device,
            ShareType::Ipc,
            ShareType::Unknown,
        ] {
            let json = serde_json::to_string(&t).unwrap();
            let back: ShareType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    // ── Share::is_hidden ──────────────────────────────────────────────────────

    #[test]
    fn hidden_share_ends_with_dollar() {
        let s = Share::new("host", "C$");
        assert!(s.is_hidden());
    }

    #[test]
    fn normal_share_is_not_hidden() {
        let s = Share::new("host", "public");
        assert!(!s.is_hidden());
    }

    #[test]
    fn share_ending_in_dollar_is_hidden() {
        let s = Share::new("host", "NETLOGON$");
        assert!(s.is_hidden());
    }

    // ── Share::is_admin ───────────────────────────────────────────────────────

    #[test]
    fn admin_dollar_is_admin() {
        assert!(Share::new("host", "ADMIN$").is_admin());
    }

    #[test]
    fn ipc_dollar_is_admin() {
        assert!(Share::new("host", "IPC$").is_admin());
    }

    #[test]
    fn print_dollar_is_admin() {
        assert!(Share::new("host", "PRINT$").is_admin());
    }

    #[test]
    fn fax_dollar_is_admin() {
        assert!(Share::new("host", "FAX$").is_admin());
    }

    #[test]
    fn drive_letter_share_is_admin() {
        // C$, D$, E$ etc.
        assert!(Share::new("host", "C$").is_admin());
        assert!(Share::new("host", "Z$").is_admin());
    }

    #[test]
    fn regular_hidden_share_is_not_admin() {
        // A custom hidden share like "backup$" is hidden but not an admin share
        assert!(!Share::new("host", "backup$").is_admin());
    }

    #[test]
    fn normal_share_is_not_admin() {
        assert!(!Share::new("host", "public").is_admin());
    }

    #[test]
    fn admin_check_is_case_insensitive() {
        assert!(Share::new("host", "admin$").is_admin());
        assert!(Share::new("host", "ipc$").is_admin());
    }

    // ── Share::unc_path ───────────────────────────────────────────────────────

    #[test]
    fn unc_path_format() {
        let s = Share::new("fileserver", "docs");
        assert_eq!(s.unc_path(), r"\\fileserver\docs");
    }

    // ── Share serde round-trip ────────────────────────────────────────────────

    #[test]
    fn share_json_round_trip() {
        let original = Share {
            host: "srv01".into(),
            name: "public".into(),
            share_type: ShareType::Disk,
            comment: "Public share".into(),
            access: AccessLevel::READ | AccessLevel::WRITE,
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: Share = serde_json::from_str(&json).unwrap();
        assert_eq!(original.name, back.name);
        assert_eq!(original.access, back.access);
        assert_eq!(original.share_type, back.share_type);
    }
}
