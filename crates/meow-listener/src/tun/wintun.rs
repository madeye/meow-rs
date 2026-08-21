//! Locate the official WireGuard [`wintun.dll`](https://www.wintun.net/) used
//! as the Windows TUN backend.
//!
//! Windows has no `/dev/net/tun`. The transparent-proxy inbound creates a
//! Wintun adapter and feeds its packets into the same userspace stack as
//! Linux/macOS. `tun-rs` loads the DLL at runtime; we resolve the path
//! ourselves so a missing or hijacked DLL fails with a clear error instead
//! of a generic device-create failure.
//!
//! Search order:
//! 1. Next to the running executable (official Windows zips ship it here).
//! 2. The process working directory (handy for `cargo run` from the repo).
//! 3. Extract the official signed DLL embedded in this binary (next to the
//!    exe if writable, otherwise `%LOCALAPPDATA%\meow\`, then the temp dir).
//!
//! The DLL search path / `PATH` is **not** consulted — a random `wintun.dll`
//! elsewhere is both a version-skew source and a LoadLibrary hijack risk.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// File name of the official Wintun userspace library.
pub const WINTUN_DLL: &str = "wintun.dll";

/// Official signed DLL for this target, fetched by `build.rs`.
///
/// Static linking is impossible (Wintun is a signed PE + kernel driver).
/// Embedding the official DLL and writing it to disk is the supported
/// single-file distribution form.
#[cfg(target_os = "windows")]
const EMBEDDED_WINTUN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wintun/wintun.dll"));

/// Locate `wintun.dll`: sidecar first, then the copy embedded in this binary.
#[cfg(target_os = "windows")]
pub fn resolve_wintun_dll() -> io::Result<PathBuf> {
    match resolve_from(
        std::env::current_exe().ok().as_deref(),
        std::env::current_dir().ok().as_deref(),
        Path::is_file,
    ) {
        Ok(path) => Ok(path),
        Err(sidecar) => extract_embedded().map_err(|extract| {
            io::Error::new(
                extract.kind(),
                format!("{sidecar}; bundled extract also failed: {extract}"),
            )
        }),
    }
}

#[cfg(target_os = "windows")]
fn extract_embedded() -> io::Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let dests = extract_destinations(
        std::env::current_exe()
            .ok()
            .as_deref()
            .and_then(Path::parent),
        local.as_deref(),
        &std::env::temp_dir(),
    );
    extract_to_first_writable(&dests, EMBEDDED_WINTUN)
}

/// Testable search: first existing candidate wins.
pub(super) fn resolve_from(
    exe: Option<&Path>,
    cwd: Option<&Path>,
    exists: impl Fn(&Path) -> bool,
) -> io::Result<PathBuf> {
    let mut looked = Vec::new();
    if let Some(dir) = exe.and_then(Path::parent) {
        let candidate = dir.join(WINTUN_DLL);
        if exists(&candidate) {
            return Ok(candidate);
        }
        looked.push(candidate);
    }
    if let Some(cwd) = cwd {
        let candidate = cwd.join(WINTUN_DLL);
        if exists(&candidate) {
            return Ok(candidate);
        }
        looked.push(candidate);
    }

    let looked_at = if looked.is_empty() {
        "the executable directory and the working directory".to_string()
    } else {
        looked
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{WINTUN_DLL} sidecar not found (looked in {looked_at}). \
             Official Windows builds ship {WINTUN_DLL} beside meow.exe. \
             Download the matching architecture from https://www.wintun.net/ \
             or rely on the copy embedded in this binary."
        ),
    ))
}

/// Where a bundled DLL may be written, in preference order.
pub(super) fn extract_destinations(
    exe_dir: Option<&Path>,
    local_app_data: Option<&Path>,
    temp_dir: &Path,
) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(3);
    if let Some(dir) = exe_dir {
        out.push(dir.join(WINTUN_DLL));
    }
    if let Some(base) = local_app_data {
        out.push(base.join("meow").join(WINTUN_DLL));
    }
    out.push(temp_dir.join("meow").join(WINTUN_DLL));
    out
}

/// Reuse a same-length file, otherwise write `bytes` to the first dest that
/// accepts the write. Empty blobs are rejected so a failed `include_bytes`
/// cannot install a dummy DLL.
pub(super) fn extract_to_first_writable(dests: &[PathBuf], bytes: &[u8]) -> io::Result<PathBuf> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "embedded wintun.dll is empty",
        ));
    }
    for dest in dests {
        if dest
            .metadata()
            .ok()
            .is_some_and(|meta| meta.is_file() && meta.len() == bytes.len() as u64)
        {
            return Ok(dest.clone());
        }
    }
    let mut errors = Vec::new();
    for dest in dests {
        match write_dll(dest, bytes) {
            Ok(()) => return Ok(dest.clone()),
            Err(e) => errors.push(format!("{}: {e}", dest.display())),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "could not write bundled {WINTUN_DLL} to any of: {}",
            errors.join("; ")
        ),
    ))
}

fn write_dll(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::other(format!("{} has no parent directory", dest.display())))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        dest.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, bytes)?;
    if dest.exists() {
        let _ = fs::remove_file(dest);
    }
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{extract_destinations, extract_to_first_writable, resolve_from, WINTUN_DLL};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn testdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "meow-wintun-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&p).expect("testdir");
        p
    }

    #[test]
    fn resolve_from_search_order() {
        // Forward slashes so Path::parent works on Unix CI hosts too.
        struct Case {
            name: &'static str,
            exe: &'static str,
            cwd: &'static str,
            /// The only directory whose `wintun.dll` the predicate accepts.
            present_dir: &'static str,
        }

        let cases = [
            Case {
                name: "prefers the dll next to the executable",
                exe: "/opt/meow/meow.exe",
                cwd: "/home/me",
                present_dir: "/opt/meow",
            },
            Case {
                name: "falls back to the working directory",
                exe: "/missing/meow.exe",
                cwd: "/work/meow-rs",
                present_dir: "/work/meow-rs",
            },
        ];

        let mut failures = Vec::new();
        for case in &cases {
            let expected = Path::new(case.present_dir).join(WINTUN_DLL);
            let exe = PathBuf::from(case.exe);
            let cwd = PathBuf::from(case.cwd);
            match resolve_from(Some(&exe), Some(&cwd), |p| p == expected) {
                Ok(found) if found == expected => {}
                Ok(found) => failures.push(format!(
                    "{}: expected {}, got {}",
                    case.name,
                    expected.display(),
                    found.display()
                )),
                Err(e) => failures.push(format!("{}: resolve_from failed: {e}", case.name)),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    }

    #[test]
    fn missing_dll_is_a_not_found_error_with_download_hint() {
        let exe = PathBuf::from("/meow/meow.exe");
        let cwd = PathBuf::from("/meow");
        let err = resolve_from(Some(&exe), Some(&cwd), |_| false).expect_err("no candidate exists");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let msg = err.to_string();
        assert!(msg.contains(WINTUN_DLL), "{msg}");
        assert!(msg.contains("wintun.net"), "{msg}");
        assert!(
            msg.contains(
                Path::new("/meow")
                    .join(WINTUN_DLL)
                    .to_string_lossy()
                    .as_ref()
            ),
            "{msg}"
        );
    }

    #[test]
    fn missing_exe_and_cwd_still_mentions_wintun() {
        let err = resolve_from(None, None, |_| false).expect_err("no search roots");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains(WINTUN_DLL));
    }

    #[test]
    fn extract_destinations_prefer_exe_then_appdata_then_temp() {
        let dests = extract_destinations(
            Some(Path::new("/opt/meow")),
            Some(Path::new("/Users/me/AppData/Local")),
            Path::new("/tmp"),
        );
        assert_eq!(
            dests,
            vec![
                PathBuf::from("/opt/meow").join(WINTUN_DLL),
                PathBuf::from("/Users/me/AppData/Local/meow").join(WINTUN_DLL),
                PathBuf::from("/tmp/meow").join(WINTUN_DLL),
            ]
        );
    }

    #[test]
    fn extract_reuses_same_length_file() {
        let dir = testdir();
        let dest = dir.join(WINTUN_DLL);
        fs::write(&dest, b"hello").unwrap();
        let dests = [dest.clone()];
        let got = extract_to_first_writable(&dests, b"hello").unwrap();
        assert_eq!(got, dest);
        assert_eq!(fs::read(&dest).unwrap(), b"hello");
    }

    #[test]
    fn extract_overwrites_different_length() {
        let dir = testdir();
        let dest = dir.join(WINTUN_DLL);
        fs::write(&dest, b"old").unwrap();
        let dests = [dest.clone()];
        extract_to_first_writable(&dests, b"newdata").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"newdata");
    }

    #[test]
    fn extract_skips_failed_dest_and_uses_next() {
        let dir = testdir();
        let blocker = dir.join("not-a-dir");
        fs::write(&blocker, b"x").unwrap();
        let bad = blocker.join(WINTUN_DLL);
        let good = dir.join("ok").join(WINTUN_DLL);
        let got = extract_to_first_writable(&[bad, good.clone()], b"dll").unwrap();
        assert_eq!(got, good);
        assert_eq!(fs::read(&good).unwrap(), b"dll");
    }

    #[test]
    fn extract_rejects_empty_blob() {
        let err = extract_to_first_writable(&[PathBuf::from("/x/wintun.dll")], b"").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("empty"));
    }
}
