use crate::{PlatformError, PlatformResult};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct PrivateAppPaths {
    pub root: PathBuf,
    pub store_lock: PathBuf,
    pub database: PathBuf,
    pub backups: PathBuf,
    pub backup_staging: PathBuf,
    pub backup_trash: PathBuf,
    pub blobs: PathBuf,
    pub staging: PathBuf,
    pub restore: PathBuf,
    pub restore_intent: PathBuf,
    pub restore_intent_sha256: PathBuf,
    pub upgrade_recovery_intent: PathBuf,
    pub upgrade_recovery_intent_sha256: PathBuf,
    pub diagnostics: PathBuf,
    pub deletion_trash: PathBuf,
    pub network_mode_dir: PathBuf,
    pub network_mode_intent: PathBuf,
    pub network_mode: PathBuf,
    pub network_mode_acknowledgment: PathBuf,
    pub updates: PathBuf,
    pub update_lock: PathBuf,
    pub update_staging: PathBuf,
    pub update_verified: PathBuf,
}

impl PrivateAppPaths {
    pub fn create(root: impl AsRef<Path>) -> PlatformResult<Self> {
        let requested_root = root.as_ref();
        if let Ok(metadata) = fs::symlink_metadata(requested_root) {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(PlatformError::Corrupt("private_path_not_directory"));
            }
        }
        fs::create_dir_all(requested_root)?;
        fs::set_permissions(requested_root, fs::Permissions::from_mode(0o700))?;
        let root = fs::canonicalize(requested_root)?;
        let backups = root.join("backups");
        let restore = root.join(".restore");
        let network_mode = root.join(".network-mode");
        let updates = root.join(".updates");
        let paths = Self {
            database: root.join("wardrobe.sqlite3"),
            store_lock: root.join(".wardrobe.lock"),
            backup_staging: backups.join(".staging"),
            backup_trash: backups.join(".trash"),
            backups,
            blobs: root.join("blobs").join("sha256"),
            staging: root.join("blobs").join(".staging"),
            restore_intent: root.join("restore-request.json"),
            restore_intent_sha256: root.join("restore-request.sha256"),
            upgrade_recovery_intent: restore.join("upgrade-recovery-v1.json"),
            upgrade_recovery_intent_sha256: restore.join("upgrade-recovery-v1.sha256"),
            restore,
            diagnostics: root.join("diagnostics.jsonl"),
            deletion_trash: root.join(".deletion-trash"),
            network_mode_intent: network_mode.join("transition-intent-v1.json"),
            network_mode: network_mode.join("network-mode-v1.json"),
            network_mode_acknowledgment: network_mode.join("transition-acknowledgment-v1.json"),
            network_mode_dir: network_mode,
            update_staging: updates.join(".staging"),
            update_lock: updates.join(".stage.lock"),
            update_verified: updates.join("verified"),
            updates,
            root,
        };

        for directory in [
            &paths.backups,
            &paths.backup_staging,
            &paths.backup_trash,
            &paths.blobs,
            &paths.staging,
            &paths.restore,
            &paths.deletion_trash,
            &paths.network_mode_dir,
            &paths.updates,
            &paths.update_staging,
            &paths.update_verified,
        ] {
            if let Ok(metadata) = fs::symlink_metadata(directory) {
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(PlatformError::Corrupt("private_path_not_directory"));
                }
            }
            fs::create_dir_all(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(PlatformError::Corrupt("private_path_not_directory"));
            }
            if metadata.mode() & 0o077 != 0
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.gid() != unsafe { libc::getegid() }
            {
                return Err(PlatformError::Corrupt("private_path_permissions"));
            }
        }
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_private_layout() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();

        for directory in [
            paths.root,
            paths.backups,
            paths.backup_staging,
            paths.backup_trash,
            paths.blobs,
            paths.staging,
            paths.restore,
            paths.deletion_trash,
            paths.network_mode_dir,
            paths.updates,
            paths.update_staging,
            paths.update_verified,
        ] {
            assert!(directory.is_dir());
            assert_eq!(
                fs::symlink_metadata(directory).unwrap().mode() & 0o777,
                0o700
            );
        }
    }
}
