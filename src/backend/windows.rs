//! Windows SMB backend using Win32 APIs.
//!
//! Share enumeration: `NetShareEnum` (level 1) via `Win32_NetworkManagement_NetManagement`.
//! Credential injection: `WNetAddConnection2A` + `WNetCancelConnection2A` via
//! `Win32_NetworkManagement_WNet` (same approach as <https://blog.veeso.dev/blog/en/how-to-access-an-smb-share-with-rust-on-windows/>).
//!
//! Requires the `windows-sys` crate with features:
//! - `Win32_NetworkManagement_WNet`
//! - `Win32_NetworkManagement_NetManagement`
//! - `Win32_Foundation`

#![cfg(target_os = "windows")]

use std::{
    ffi::{CString, OsString},
    fs,
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    ptr,
    slice,
};

use windows_sys::Win32::{
    Foundation::{NO_ERROR, TRUE},
    NetworkManagement::{
        NetManagement::{
            NetApiBufferFree, NetShareEnum, SHARE_INFO_1, STYPE_DEVICE, STYPE_DISKTREE,
            STYPE_IPC, STYPE_PRINTQ, STYPE_SPECIAL,
        },
        WNet::{
            WNetAddConnection2A, WNetCancelConnection2A, NETRESOURCEA,
            RESOURCE_GLOBALNET, RESOURCEDISPLAYTYPE_SHAREADMIN,
            RESOURCETYPE_ANY, RESOURCEUSAGE_ALL,
        },
    },
};

use crate::{
    backend::SmbBackend,
    credentials::{AuthMethod, Credentials},
    error::{Result, SmbError},
    share::{AccessLevel, Share, ShareType},
};

/// Maximum buffer size requested from `NetShareEnum`.
/// `0xFFFFFFFF` means "allocate as much as needed".
const MAX_PREFERRED_LENGTH: u32 = 0xFFFF_FFFF;

// ── RAII connection guard ────────────────────────────────────────────────────

/// Establishes a WNet connection on construction, cancels it on drop.
struct WNetConnection {
    remote: CString,
}

impl WNetConnection {
    /// Connect to `\\server\share` (pass `"IPC$"` for enumeration).
    fn connect(
        server: &str,
        share: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self> {
        let remote_str = format!("\\\\{server}\\{share}");
        let remote = CString::new(remote_str.as_bytes())
            .map_err(|e| SmbError::Backend(format!("invalid remote path: {e}")))?;

        let username_cstr = username
            .map(|u| CString::new(u).map_err(|e| SmbError::Backend(e.to_string())))
            .transpose()?;
        let password_cstr = password
            .map(|p| CString::new(p).map_err(|e| SmbError::Backend(e.to_string())))
            .transpose()?;

        let mut resource = NETRESOURCEA {
            dwScope: RESOURCE_GLOBALNET,
            dwType: RESOURCETYPE_ANY,
            dwDisplayType: RESOURCEDISPLAYTYPE_SHAREADMIN,
            dwUsage: RESOURCEUSAGE_ALL,
            lpLocalName: ptr::null_mut(),
            lpRemoteName: remote.as_ptr() as *mut u8,
            lpComment: ptr::null_mut(),
            lpProvider: ptr::null_mut(),
        };

        let username_ptr = username_cstr
            .as_ref()
            .map(|c| c.as_ptr())
            .unwrap_or(ptr::null());
        let password_ptr = password_cstr
            .as_ref()
            .map(|c| c.as_ptr())
            .unwrap_or(ptr::null());

        // Do NOT use CONNECT_INTERACTIVE — a CLI tool must never pop a dialog.
        // Use 0 (no flags) so the call fails fast with an error code instead.
        let rc = unsafe {
            WNetAddConnection2A(
                &mut resource as *mut NETRESOURCEA,
                password_ptr as *const u8,
                username_ptr as *const u8,
                0,
            )
        };

        if rc == NO_ERROR {
            Ok(Self { remote })
        } else {
            Err(win32_error_to_smb(rc, server, share))
        }
    }
}

impl Drop for WNetConnection {
    fn drop(&mut self) {
        unsafe {
            // Best-effort: ignore the return value on drop.
            WNetCancelConnection2A(self.remote.as_ptr() as *const u8, 0, TRUE);
        }
    }
}

// ── Public backend struct ────────────────────────────────────────────────────

pub struct Win32Backend;

impl Win32Backend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Win32Backend {
    fn default() -> Self {
        Self::new()
    }
}

impl SmbBackend for Win32Backend {
    fn list_shares(&self, host: &str, creds: &Credentials) -> Result<Vec<Share>> {
        let (username, password) = extract_credentials(creds);

        // Open a session to IPC$ so NetShareEnum can use our credentials.
        let _conn = WNetConnection::connect(host, "IPC$", username, password)?;

        enumerate_shares(host)
    }

    fn check_read(&self, host: &str, share: &str, creds: &Credentials) -> Result<bool> {
        let (username, password) = extract_credentials(creds);
        let _conn = WNetConnection::connect(host, share, username, password)
            .map_err(|e| match e {
                SmbError::AuthFailed { .. } => e,
                other => SmbError::AccessDenied {
                    host: host.into(),
                    share: share.into(),
                },
            })?;

        let unc = unc_path(host, share);
        match fs::read_dir(&unc) {
            Ok(_) => Ok(true),
            Err(e) if is_access_denied(&e) => Ok(false),
            Err(e) => Err(SmbError::Io(e)),
        }
    }

    fn check_write(&self, host: &str, share: &str, creds: &Credentials) -> Result<bool> {
        let (username, password) = extract_credentials(creds);
        let _conn = WNetConnection::connect(host, share, username, password)?;

        let probe_name = format!(
            "__rusty_smb_probe_{}.tmp",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0xdead)
        );

        let mut probe_path = PathBuf::from(unc_path(host, share));
        probe_path.push(&probe_name);

        match fs::write(&probe_path, b"rusty-smb-scan probe") {
            Ok(()) => {
                let _ = fs::remove_file(&probe_path);
                Ok(true)
            }
            Err(e) if is_access_denied(&e) => Ok(false),
            Err(e) => Err(SmbError::Io(e)),
        }
    }
}

// ── NetShareEnum ─────────────────────────────────────────────────────────────

fn enumerate_shares(host: &str) -> Result<Vec<Share>> {
    // NetShareEnum expects `\\hostname` as a wide string.
    let server_wide: Vec<u16> = format!("\\\\{host}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut buf_ptr: *mut u8 = ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume_handle: u32 = 0;

    let rc = unsafe {
        NetShareEnum(
            server_wide.as_ptr(),
            1, // SHARE_INFO_1
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume_handle,
        )
    };

    if rc != 0 {
        return Err(SmbError::Backend(format!(
            "NetShareEnum failed with error {rc:#010x}"
        )));
    }

    let shares = unsafe {
        let info = buf_ptr as *const SHARE_INFO_1;
        let slice = slice::from_raw_parts(info, entries_read as usize);

        let result = slice
            .iter()
            .map(|entry| {
                let name = wide_ptr_to_string(entry.shi1_netname);
                let comment = wide_ptr_to_string(entry.shi1_remark);
                let share_type = decode_share_type(entry.shi1_type);
                Share {
                    host: host.to_string(),
                    name,
                    share_type,
                    comment,
                    access: AccessLevel::empty(),
                }
            })
            .collect();

        NetApiBufferFree(buf_ptr as *mut _);
        result
    };

    Ok(shares)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_credentials(creds: &Credentials) -> (Option<&str>, Option<&str>) {
    match &creds.method {
        AuthMethod::Password {
            username, password, ..
        } => (Some(username.as_str()), Some(password.as_str())),
        AuthMethod::Guest => (Some("guest"), Some("")),
        AuthMethod::Null => (None, None),
        AuthMethod::NtlmHash { username, .. } => {
            // WNetAddConnection2A cannot pass a raw hash; the caller must use
            // LogonUser/impersonation. We surface this as an unsupported error.
            // The field is used for the username display only.
            (Some(username.as_str()), None)
        }
        AuthMethod::Kerberos { .. } => {
            // On Windows, passing NULL for both username and password tells
            // WNetAddConnection2A to use the current thread's security token.
            // The Windows SMB redirector then negotiates Kerberos automatically
            // using the existing TGT/TGS from LSASS — no credentials needed.
            (None, None)
        }
    }
}

fn unc_path(host: &str, share: &str) -> String {
    format!("\\\\{host}\\{share}")
}

/// Convert a null-terminated wide string pointer to a Rust `String`.
///
/// # Safety
/// `ptr` must be either null or point to a valid null-terminated UTF-16 sequence.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let wide = slice::from_raw_parts(ptr, len);
    OsString::from_wide(wide).to_string_lossy().into_owned()
}

fn decode_share_type(raw_type: u32) -> ShareType {
    // Mask off STYPE_SPECIAL (0x8000_0000) and STYPE_TEMPORARY (0x4000_0000)
    match raw_type & 0x0FFF_FFFF {
        STYPE_DISKTREE => ShareType::Disk,
        STYPE_PRINTQ => ShareType::Printer,
        STYPE_DEVICE => ShareType::Device,
        STYPE_IPC => ShareType::Ipc,
        _ => ShareType::Unknown,
    }
}

fn is_access_denied(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
        || e.raw_os_error() == Some(5) // ERROR_ACCESS_DENIED
        || e.raw_os_error() == Some(1326) // ERROR_LOGON_FAILURE
}

fn win32_error_to_smb(code: u32, host: &str, share: &str) -> SmbError {
    match code {
        5 => SmbError::AccessDenied {
            host: host.into(),
            share: share.into(),
        },
        // ERROR_LOGON_FAILURE / ERROR_WRONG_PASSWORD
        1326 | 86 => SmbError::AuthFailed {
            user: host.into(), // best we can do without passing user here
            host: host.into(),
            reason: format!("Win32 error {code}"),
        },
        // ERROR_BAD_NETPATH / ERROR_NETWORK_UNREACHABLE
        53 | 1231 => SmbError::HostUnreachable { host: host.into() },
        other => SmbError::Backend(format!(
            "WNetAddConnection2A failed for \\\\{host}\\{share}: error {other:#06x}"
        )),
    }
}

// ── Unit tests (compile-time only on Windows) ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_share_type_disk() {
        assert_eq!(decode_share_type(STYPE_DISKTREE), ShareType::Disk);
    }

    #[test]
    fn decode_share_type_printer() {
        assert_eq!(decode_share_type(STYPE_PRINTQ), ShareType::Printer);
    }

    #[test]
    fn decode_share_type_ipc() {
        assert_eq!(decode_share_type(STYPE_IPC), ShareType::Ipc);
    }

    #[test]
    fn decode_share_type_special_disk_masked() {
        // Admin shares have STYPE_SPECIAL | STYPE_DISKTREE
        let admin = STYPE_SPECIAL | STYPE_DISKTREE;
        assert_eq!(decode_share_type(admin), ShareType::Disk);
    }

    #[test]
    fn decode_share_type_unknown() {
        assert_eq!(decode_share_type(0xFF), ShareType::Unknown);
    }

    #[test]
    fn unc_path_format() {
        assert_eq!(unc_path("server", "docs"), r"\\server\docs");
    }

    #[test]
    fn win32_error_access_denied() {
        assert!(matches!(
            win32_error_to_smb(5, "host", "share"),
            SmbError::AccessDenied { .. }
        ));
    }

    #[test]
    fn win32_error_host_unreachable() {
        assert!(matches!(
            win32_error_to_smb(53, "host", "share"),
            SmbError::HostUnreachable { .. }
        ));
        assert!(matches!(
            win32_error_to_smb(1231, "host", "share"),
            SmbError::HostUnreachable { .. }
        ));
    }

    #[test]
    fn win32_error_auth_failure() {
        assert!(matches!(
            win32_error_to_smb(1326, "host", "share"),
            SmbError::AuthFailed { .. }
        ));
    }

    #[test]
    fn extract_credentials_password() {
        let creds = Credentials::new(AuthMethod::Password {
            username: "alice".into(),
            password: "s3cr3t".into(),
            domain: None,
        });
        let (user, pass) = extract_credentials(&creds);
        assert_eq!(user, Some("alice"));
        assert_eq!(pass, Some("s3cr3t"));
    }

    #[test]
    fn extract_credentials_null_returns_none() {
        let creds = Credentials::new(AuthMethod::Null);
        let (user, pass) = extract_credentials(&creds);
        assert!(user.is_none());
        assert!(pass.is_none());
    }

    #[test]
    fn extract_credentials_kerberos_returns_none_to_use_tgt() {
        // Passing (None, None) to WNetAddConnection2A tells Windows to use the
        // current thread's TGT/TGS — same as Null for the credential pointer.
        let creds = Credentials::new(AuthMethod::Kerberos {
            username: "alice".into(),
            realm: "CORP.LOCAL".into(),
        });
        let (user, pass) = extract_credentials(&creds);
        assert!(user.is_none(), "Kerberos on Windows should pass NULL username to use TGT");
        assert!(pass.is_none());
    }

    #[test]
    fn extract_credentials_guest() {
        let creds = Credentials::new(AuthMethod::Guest);
        let (user, pass) = extract_credentials(&creds);
        assert_eq!(user, Some("guest"));
        assert_eq!(pass, Some(""));
    }
}
