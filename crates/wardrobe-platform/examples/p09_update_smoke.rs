use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use uuid::Uuid;
use wardrobe_core::{
    Sha256Digest, UpdateArtifactKindV1, UpdateChannelV1, UpdateManifestV1, UpdateOperatingSystemV1,
    UPDATE_APPLICATION_ID_V1, UPDATE_MANIFEST_SCHEMA_VERSION_V1,
};
use wardrobe_platform::{
    canonical_manifest_bytes, encode_update_package, update_signature_message, Database,
    PrivateAppPaths, StoreLock, TrustedUpdateRuntimeContext, UpdatePackageError,
    UpdatePackageStager, UpdateTrustKey, BACKUP_FORMAT_VERSION,
};

#[derive(Serialize)]
struct SmokeReport {
    schema_version: u8,
    status: &'static str,
    real_ed25519: bool,
    canonical_manifest_verified: bool,
    valid_package_staged: bool,
    exact_signed_package_retained: bool,
    staged_package_reverified: bool,
    artifact_tamper_rejected: bool,
    manifest_tamper_rejected: bool,
    noncanonical_manifest_rejected: bool,
    database_unchanged: bool,
    database_lineage_unchanged: bool,
    live_data_tree_unchanged: bool,
    production_keyring_empty: bool,
    network_sandbox_enforced: bool,
    install_feature_enabled: bool,
    acceptance_claim: &'static str,
    deferred_limitation: &'static str,
}

fn main() -> Result<(), Box<dyn Error>> {
    let temporary = tempdir()?;
    let paths = PrivateAppPaths::create(temporary.path().join("private"))?;
    let store_lock = Arc::new(StoreLock::acquire(&paths)?);
    let database = Database::open(&paths, 1_000)?;
    let database_before = sha256_file(&paths.database)?;
    let live_tree_before = live_tree_sha256(&paths.root)?;
    let lineage_before = database.compatibility_snapshot()?;

    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "ephemeral key generation failed")?;
    let key = Ed25519KeyPair::from_pkcs8(key_document.as_ref())
        .map_err(|_| "ephemeral key parse failed")?;
    let key_id = "ephemeral-smoke-key".to_owned();
    let trust_key = UpdateTrustKey {
        key_id: key_id.clone(),
        public_key: key.public_key().as_ref().try_into()?,
        minimum_release_sequence: 2,
        maximum_release_sequence: 2,
    };
    let stager =
        UpdatePackageStager::new(database.clone(), Arc::clone(&store_lock), vec![trust_key])?;
    let context = stager.current_compatibility()?;
    let artifact = b"wardrobe-personal-update-smoke-artifact-v1";
    let manifest = manifest(&context, &key_id, artifact)?;
    let canonical = canonical_manifest_bytes(&manifest)?;
    let signature = key.sign(&update_signature_message(&canonical)?);
    let package_bytes = encode_update_package(&manifest, signature.as_ref(), artifact)?;
    let package_path = temporary.path().join("valid.wdupdate");
    fs::write(&package_path, &package_bytes)?;

    let staged = stager.stage(&Uuid::new_v4().to_string(), &package_path, 2_000)?;
    let retained = fs::read(staged.stage_path.join("package.wdupdate"))?;
    let recovered = stager.recover()?;
    let staged_package_reverified =
        recovered.len() == 1 && recovered[0].package_sha256 == staged.package_sha256;

    let mut artifact_tampered = package_bytes.clone();
    *artifact_tampered.last_mut().ok_or("empty update package")? ^= 0x01;
    let artifact_tampered_path = temporary.path().join("artifact-tampered.wdupdate");
    fs::write(&artifact_tampered_path, artifact_tampered)?;
    let artifact_tamper_rejected = matches!(
        stager.verify_only(&artifact_tampered_path),
        Err(UpdatePackageError::Invalid("artifact_sha256"))
    );

    let mut manifest_tampered = package_bytes.clone();
    replace_once(&mut manifest_tampered, b"0.2.0", b"0.3.0")?;
    let manifest_tampered_path = temporary.path().join("manifest-tampered.wdupdate");
    fs::write(&manifest_tampered_path, manifest_tampered)?;
    let manifest_tamper_rejected = matches!(
        stager.verify_only(&manifest_tampered_path),
        Err(UpdatePackageError::SignatureInvalid)
    );

    let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
    noncanonical.push(b'{');
    noncanonical.push(b' ');
    noncanonical.extend_from_slice(&canonical[1..]);
    let noncanonical_signature = key.sign(&update_signature_message(&noncanonical)?);
    let noncanonical_package =
        encode_raw_package(&noncanonical, noncanonical_signature.as_ref(), artifact);
    let noncanonical_path = temporary.path().join("noncanonical.wdupdate");
    fs::write(&noncanonical_path, noncanonical_package)?;
    let noncanonical_manifest_rejected = matches!(
        stager.verify_only(&noncanonical_path),
        Err(UpdatePackageError::Invalid("manifest_canonical"))
    );

    let database_after = sha256_file(&paths.database)?;
    let lineage_after = database.compatibility_snapshot()?;
    let live_tree_after = live_tree_sha256(&paths.root)?;
    let production_disabled = UpdatePackageStager::production_disabled(database, store_lock)?;
    let real_ed25519 = !staged.replayed && manifest_tamper_rejected;
    let report = SmokeReport {
        schema_version: 1,
        status: "pass",
        real_ed25519,
        canonical_manifest_verified: noncanonical_manifest_rejected,
        valid_package_staged: !staged.replayed,
        exact_signed_package_retained: retained == package_bytes,
        staged_package_reverified,
        artifact_tamper_rejected,
        manifest_tamper_rejected,
        noncanonical_manifest_rejected,
        database_unchanged: database_before == database_after,
        database_lineage_unchanged: lineage_before == lineage_after,
        live_data_tree_unchanged: live_tree_before == live_tree_after,
        production_keyring_empty: !production_disabled.has_trusted_release_key(),
        network_sandbox_enforced: env::var("P09_UPDATE_NETWORK_SANDBOX").as_deref() == Ok("1"),
        install_feature_enabled: false,
        acceptance_claim: "deferred_not_passed",
        deferred_limitation: "genuine two-version installation is not implemented",
    };
    if !report.valid_package_staged
        || !report.exact_signed_package_retained
        || !report.staged_package_reverified
        || !report.artifact_tamper_rejected
        || !report.manifest_tamper_rejected
        || !report.noncanonical_manifest_rejected
        || !report.database_unchanged
        || !report.database_lineage_unchanged
        || !report.live_data_tree_unchanged
        || !report.production_keyring_empty
        || !report.network_sandbox_enforced
    {
        return Err("P09 update smoke invariant failed".into());
    }
    let encoded = serde_json::to_vec(&report)?;
    if let Some(destination) = env::var_os("P09_UPDATE_SMOKE_REPORT") {
        fs::write(destination, &encoded)?;
    }
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}

fn manifest(
    context: &TrustedUpdateRuntimeContext,
    key_id: &str,
    artifact: &[u8],
) -> Result<UpdateManifestV1, Box<dyn Error>> {
    Ok(UpdateManifestV1 {
        schema_version: UPDATE_MANIFEST_SCHEMA_VERSION_V1,
        application_id: UPDATE_APPLICATION_ID_V1.to_owned(),
        channel: UpdateChannelV1::Personal,
        key_id: key_id.to_owned(),
        release_id: "p09-update-smoke-release".to_owned(),
        release_sequence: 2,
        target_version: "0.2.0".to_owned(),
        target_os: UpdateOperatingSystemV1::Macos,
        target_architecture: context.architecture(),
        minimum_macos_version: "15.0.0".to_owned(),
        artifact_kind: UpdateArtifactKindV1::MacosApplicationArchive,
        artifact_length: artifact.len() as u64,
        artifact_sha256: Sha256Digest::parse(hex_digest(Sha256::digest(artifact)))?,
        accepted_source_version_min: context.application_version().to_owned(),
        accepted_source_version_max: context.application_version().to_owned(),
        accepted_databases: vec![context.database().clone()],
        target_database_schema_version: context.database().schema_version,
        target_migration_prefix_sha256: context.database().migration_prefix_sha256.clone(),
        required_backup_format_version: BACKUP_FORMAT_VERSION,
        required_asset_manifest_version: 1,
    })
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) -> Result<(), Box<dyn Error>> {
    if from.len() != to.len() {
        return Err("replacement length changed".into());
    }
    let index = bytes
        .windows(from.len())
        .position(|window| window == from)
        .ok_or("manifest marker absent")?;
    bytes[index..index + to.len()].copy_from_slice(to);
    Ok(())
}

fn encode_raw_package(manifest: &[u8], signature: &[u8], artifact: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"WDU1");
    bytes.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&(artifact.len() as u64).to_be_bytes());
    bytes.extend_from_slice(manifest);
    bytes.extend_from_slice(signature);
    bytes.extend_from_slice(artifact);
    bytes
}

fn live_tree_sha256(root: &Path) -> Result<String, Box<dyn Error>> {
    let mut files = Vec::new();
    collect_live_files(root, root, &mut files)?;
    files.sort();
    let mut digest = Sha256::new();
    for path in files {
        let relative = path.strip_prefix(root)?.to_string_lossy();
        let file_digest = sha256_file(&path)?;
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative.as_bytes());
        digest.update(file_digest.as_bytes());
    }
    Ok(hex_digest(digest.finalize()))
}

fn collect_live_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<std::path::PathBuf>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root)?;
        if relative.components().next().is_some_and(|component| {
            component.as_os_str() == ".updates" || component.as_os_str() == ".wardrobe.lock"
        }) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err("unexpected symlink in live private tree".into());
        }
        if metadata.is_dir() {
            collect_live_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut DigestWriter(&mut digest))?;
    Ok(hex_digest(digest.finalize()))
}

struct DigestWriter<'a>(&'a mut Sha256);

impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
