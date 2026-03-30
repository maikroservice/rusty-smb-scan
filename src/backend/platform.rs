//! Re-exports the platform-appropriate concrete backend as `PlatformBackend`
//! so integration tests and `main.rs` can refer to a single type.

#[cfg(not(target_os = "windows"))]
pub use super::libsmb::LibSmbBackend as PlatformBackend;

#[cfg(target_os = "windows")]
pub use super::windows::Win32Backend as PlatformBackend;
