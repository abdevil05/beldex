//! Share-custody interface (**Phase D / D.1**).
//!
//! Holds each member's *own* shares of `Pevm` and `Pgw` (plus the Paillier
//! private key for `Pevm`). This blob interface provides versioning and erasure
//! semantics for tests and local persistence; it does **not** itself provide
//! hardware-backed non-exportability:
//!
//!   1. **Versioning** — every proactive refresh writes a new version; the store
//!      keeps enough to support the restore path (Phase J.2) without a reshare.
//!   2. **Epoch-consistent erasure** — superseded share versions are removed from
//!      the active store ([`ShareStore::erase_versions_below`]); a restorable pre-refresh share
//!      silently voids proactive security (Assumption 2).
//!
//! This scaffold ships the in-memory backend ([`MemoryShareStore`]) for tests and
//! devnet. Production requires a separately reviewed Vault/enclave/HSM adapter whose
//! API performs threshold operations without exporting the raw share. **No full key is
//! assembled here (S1): this store holds individual shares only.**

use std::collections::BTreeMap;
use std::collections::HashMap;

/// Atomically replace one private share file. This does not make a multi-file
/// ceremony transactional and is not non-exportable custody.
#[cfg(unix)]
pub fn atomic_private_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_private_write_before_commit(path, bytes, || Ok(()))
}

#[cfg(unix)]
fn atomic_private_write_before_commit(
    path: &std::path::Path,
    bytes: &[u8],
    before_commit: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::{
        fs,
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let meta = fs::symlink_metadata(parent)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::other(
            "share parent must be a private directory (0700), not a symlink",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() => {
            return Err(std::io::Error::other(
                "share destination must be a regular file",
            ))
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("missing share filename"))?
        .to_string_lossy();
    let mut created = None;
    for _ in 0..128 {
        let temp = parent.join(format!(
            ".{name}.tmp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(file) => {
                created = Some((temp, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let (temp, mut file) =
        created.ok_or_else(|| std::io::Error::other("no unique share temporary path"))?;
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(temp.clone());
    file.write_all(bytes)?;
    file.sync_all()?;
    before_commit()?;
    fs::rename(&temp, path)?;
    fs::File::open(parent)?.sync_all()
}

#[cfg(all(test, unix))]
mod atomic_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn interrupted_share_replacement_preserves_old_file_and_permissions() {
        let dir = std::env::temp_dir().join(format!("bridge-share-atomic-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("share");
        atomic_private_write(&path, b"old fixture").unwrap();
        assert!(
            atomic_private_write_before_commit(&path, b"new fixture", || Err(
                std::io::Error::other("injected pre-rename failure")
            ))
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"old fixture");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        atomic_private_write(&path, b"new fixture").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new fixture");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(atomic_private_write(&link, b"overwrite").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"new fixture");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Custody backend for versioned key material. Keys are logical names such as
/// `"pevm.share"`, `"pgw.share"`, `"pevm.paillier"`.
pub trait ShareStore {
    /// Store `blob` for `key` at `version` (overwrites that version if present).
    fn put(&mut self, key: &str, version: u32, blob: Vec<u8>);
    /// The highest-versioned blob for `key`, if any.
    fn get_latest(&self, key: &str) -> Option<(u32, Vec<u8>)>;
    /// A specific version's blob for `key`, if present.
    fn get_version(&self, key: &str, version: u32) -> Option<Vec<u8>>;
    /// All stored versions for `key`, ascending.
    fn versions(&self, key: &str) -> Vec<u32>;
    /// Remove every version of `key` (e.g. share destroyed on ejection).
    fn erase_key(&mut self, key: &str);
    /// Epoch-consistent erasure: destroy every version of `key` **below**
    /// `min_version`, so no pre-refresh share survives (including in backups).
    fn erase_versions_below(&mut self, key: &str, min_version: u32);
}

/// In-memory [`ShareStore`] for tests / devnet. **Not** for production custody
/// (a full-node compromise reads it) — production uses Vault or an enclave.
#[derive(Debug, Default)]
pub struct MemoryShareStore {
    map: HashMap<String, BTreeMap<u32, Vec<u8>>>,
}

impl MemoryShareStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ShareStore for MemoryShareStore {
    fn put(&mut self, key: &str, version: u32, blob: Vec<u8>) {
        self.map
            .entry(key.to_string())
            .or_default()
            .insert(version, blob);
    }

    fn get_latest(&self, key: &str) -> Option<(u32, Vec<u8>)> {
        self.map
            .get(key)
            .and_then(|versions| versions.iter().next_back())
            .map(|(v, blob)| (*v, blob.clone()))
    }

    fn get_version(&self, key: &str, version: u32) -> Option<Vec<u8>> {
        self.map
            .get(key)
            .and_then(|versions| versions.get(&version))
            .cloned()
    }

    fn versions(&self, key: &str) -> Vec<u32> {
        self.map
            .get(key)
            .map(|v| v.keys().copied().collect())
            .unwrap_or_default()
    }

    fn erase_key(&mut self, key: &str) {
        self.map.remove(key);
    }

    fn erase_versions_below(&mut self, key: &str, min_version: u32) {
        if let Some(versions) = self.map.get_mut(key) {
            versions.retain(|&v, _| v >= min_version);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get_latest() {
        let mut s = MemoryShareStore::new();
        s.put("pgw.share", 1, vec![1, 1, 1]);
        s.put("pgw.share", 2, vec![2, 2, 2]);
        assert_eq!(s.get_latest("pgw.share"), Some((2, vec![2, 2, 2])));
        assert_eq!(s.get_version("pgw.share", 1), Some(vec![1, 1, 1]));
        assert_eq!(s.get_latest("absent"), None);
    }

    #[test]
    fn versions_are_sorted() {
        let mut s = MemoryShareStore::new();
        s.put("k", 3, vec![]);
        s.put("k", 1, vec![]);
        s.put("k", 2, vec![]);
        assert_eq!(s.versions("k"), vec![1, 2, 3]);
    }

    #[test]
    fn epoch_consistent_erasure_leaves_no_old_share() {
        // Simulate three refresh epochs, then erase everything below the current.
        let mut s = MemoryShareStore::new();
        s.put("pevm.share", 1, vec![10]);
        s.put("pevm.share", 2, vec![20]);
        s.put("pevm.share", 3, vec![30]);
        s.erase_versions_below("pevm.share", 3);
        // A pre-refresh share must NOT be restorable (Assumption 2).
        assert_eq!(s.get_version("pevm.share", 1), None);
        assert_eq!(s.get_version("pevm.share", 2), None);
        assert_eq!(s.versions("pevm.share"), vec![3]);
        assert_eq!(s.get_latest("pevm.share"), Some((3, vec![30])));
    }

    #[test]
    fn erase_key_destroys_the_share() {
        let mut s = MemoryShareStore::new();
        s.put("pgw.share", 5, vec![9]);
        s.erase_key("pgw.share");
        assert_eq!(s.get_latest("pgw.share"), None);
        assert!(s.versions("pgw.share").is_empty());
    }
}
