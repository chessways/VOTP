
//! util.rs – Windows ACL helper + no‑op stub for non‑Windows.
//!
//! Goal: restrict a file’s DACL to
//!   • the current user (file owner)
//!   • BUILTIN\Administrators
//! both with full control (FILE_ALL_ACCESS).

// ---------------- Windows implementation ---------------------------------
#[cfg(windows)]
mod win_acl {
    use std::{io, path::Path};

    use windows_acl::{
        acl::ACL,                       // v0.3 API
        helper::{current_user, name_to_sid},
    };
    use winapi::um::winnt::FILE_ALL_ACCESS;

    pub(crate) fn tighten(path: &Path) -> io::Result<()> {
        // Convert the path to &str for the crate API.
        let path_str = path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non‑Unicode path"))?;

        // Load the file’s current ACL.
        let mut acl =
            ACL::from_file_path(path_str, /*get_sacl=*/ false).map_err(os_err)?;

        /* --- resolve the SIDs we want to keep ------------------------- */

        // Current user (file owner)
        let owner_name = current_user()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "cannot determine current user"))?;
        let owner_sid = name_to_sid(&owner_name, None).map_err(os_err)?;

        // BUILTIN\Administrators
        let admin_sid = name_to_sid("BUILTIN\\Administrators", None).map_err(os_err)?;

        /* --- grant full control -------------------------------------- */
        //
        // ACL::allow() *immediately* writes the ACE back to the file,
        // so no extra apply/commit call is needed.

        acl.allow(owner_sid.as_ptr() as *mut _, false, FILE_ALL_ACCESS)
            .map_err(os_err)?;
        acl.allow(admin_sid.as_ptr() as *mut _, false, FILE_ALL_ACCESS)
            .map_err(os_err)?;

        Ok(())
    }

    // Helper: convert DWORD error codes returned by windows‑acl into io::Error.
    fn os_err(code: u32) -> io::Error {
        io::Error::from_raw_os_error(code as i32)
    }
}

// Re‑export for callers in the rest of the code‑base.
#[cfg(windows)]
pub(crate) use win_acl::tighten as tighten_dacl;

// ---------------- Non‑Windows stub --------------------------------------
#[cfg(not(windows))]
#[allow(dead_code)]
pub(crate) fn tighten_dacl(_path: &std::path::Path) -> std::io::Result<()> {
    // POSIX platforms already use chmod(0o600) elsewhere.
    Ok(())
}
