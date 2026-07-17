use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use wardrobe_core::Sha256Digest;

const MANIFEST_RESOURCE_PATH: &str = "release/supply-chain-manifest-v1.json";
const MODEL_ROOT: &str = "assets/model-artifacts";
const EXPECTED_APPLICATION_ID: &str = "com.devrai.wardrobe";
const EXPECTED_RELEASE_SEQUENCE: u64 = 1;
const CARGO_REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const NPM_REGISTRY_SOURCE_PREFIX: &str = "https://registry.npmjs.org/";
const EXPECTED_TARGETS: [&str; 2] = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
const EXPECTED_PROHIBITIONS: [&str; 4] = [
    concat!("dynamic_model_", "plugins"),
    "executable_model_artifacts",
    "remote_model_code",
    "runtime_model_downloads",
];
const MODEL_SUFFIXES: [&str; 13] = [
    "bin",
    "ckpt",
    "dylib",
    "gguf",
    "mlmodel",
    "mlpackage",
    "onnx",
    "pt",
    "pth",
    "safetensors",
    "so",
    "tflite",
    "wasm",
];
const EXECUTABLE_SUFFIXES: [&str; 5] = ["dll", "dylib", "exe", "so", "wasm"];
const EXPECTED_RECEIPT_INTELLIGENCE_EVALUATOR_SHA256: &str =
    "3fd9db5e09176d6dd83616b40ece3d39a1f706612998a037e3c1293c5459b70e";

pub(crate) const COMPILED_MANIFEST_BYTES: &[u8] =
    include_bytes!("../../release/generated/supply-chain-manifest-v1.json");

#[derive(Debug)]
pub(crate) struct ReleaseManifestError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupplyChainManifest {
    counts: Counts,
    dependencies: Vec<Dependency>,
    input_hashes: BTreeMap<String, String>,
    licenses: Vec<License>,
    models: Models,
    release: ReleaseIdentity,
    schema_version: u64,
    targets: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    dependencies: u64,
    licenses: u64,
    model_artifacts: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dependency {
    ecosystem: String,
    install_script: bool,
    integrity: Option<String>,
    license: String,
    name: String,
    roles: Vec<String>,
    source: String,
    targets: Vec<String>,
    version: String,
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct License {
    ecosystem: String,
    license: String,
    name: String,
    source: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Models {
    artifacts: Vec<ModelArtifact>,
    local_providers: LocalProviders,
    prohibitions: Vec<String>,
    remote_model_code_allowed: bool,
    remote_services: RemoteServices,
    root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelArtifact {
    execution_class: String,
    length: u64,
    path: String,
    provider: String,
    revision: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalProviders {
    segmentation: LocalProvider,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalProvider {
    availability: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteServices {
    outfit_recommendation: RemoteService,
    try_on_visualization: RemoteService,
    #[serde(default)]
    openai_receipt_intelligence: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteService {
    downloads_code: bool,
    model: String,
    provider: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptIntelligenceRemoteService {
    downloads_code: bool,
    provider: String,
    model: String,
    prompt_revision: String,
    schema_revision: String,
    projection_revision: String,
    retention_revision: String,
    evaluator_sha256: String,
    phase_spec_sha256: String,
    requirements_sha256: String,
    proposal_sha256: String,
    review_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIdentity {
    application_id: String,
    application_version: String,
    release_sequence: u64,
    schema_version: u64,
}

pub(crate) fn verify_bundled_release_manifest(
    resource_root: &Path,
) -> Result<(), ReleaseManifestError> {
    verify_with_expected(resource_root, COMPILED_MANIFEST_BYTES)
}

pub(crate) fn receipt_intelligence_service_available() -> bool {
    receipt_intelligence_service_available_from(COMPILED_MANIFEST_BYTES)
}

fn receipt_intelligence_service_available_from(bytes: &[u8]) -> bool {
    let Ok(manifest) = parse_and_validate_manifest(bytes) else {
        return false;
    };
    let Some(value) = manifest.models.remote_services.openai_receipt_intelligence else {
        return false;
    };
    let Ok(service) = serde_json::from_value::<ReceiptIntelligenceRemoteService>(value) else {
        return false;
    };
    !service.downloads_code
        && service.provider == "openai"
        && service.model == "gpt-5.6-sol"
        && service.prompt_revision == "receipt-intelligence-prompt-v1"
        && service.schema_revision == "receipt-intelligence-v1"
        && service.projection_revision == "receipt-intelligence-projection-v1"
        && service.retention_revision == "p11-openai-responses-retention-v1"
        && service.evaluator_sha256 == EXPECTED_RECEIPT_INTELLIGENCE_EVALUATOR_SHA256
        && service.phase_spec_sha256
            == "e559ff6bcddf2d6546a50fbce22315b210c617c1454a3340ebcbd4619cb73c66"
        && service.requirements_sha256
            == "42c1c1a182b82571b49b926f679e56f1eb3b8fe6f7bdbb987013ada71ed98bb3"
        && service.proposal_sha256
            == "ab85491e61c17dbd465655e6e21dc087f079de4b7e58784a0637215847904d04"
        && service.review_sha256
            == "f35b29c4ac6b72cd76612b0aff2c1341de4db6e6bdf5846d050fa9cadb3161a6"
}

fn verify_with_expected(
    resource_root: &Path,
    expected_bytes: &[u8],
) -> Result<(), ReleaseManifestError> {
    let root_metadata = fs::symlink_metadata(resource_root).map_err(|_| ReleaseManifestError)?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err(ReleaseManifestError);
    }

    let manifest_path = resource_root.join(MANIFEST_RESOURCE_PATH);
    let manifest_metadata =
        fs::symlink_metadata(&manifest_path).map_err(|_| ReleaseManifestError)?;
    if !manifest_metadata.file_type().is_file() || manifest_metadata.file_type().is_symlink() {
        return Err(ReleaseManifestError);
    }
    let bundled_bytes = fs::read(&manifest_path).map_err(|_| ReleaseManifestError)?;
    if bundled_bytes != expected_bytes {
        return Err(ReleaseManifestError);
    }

    let manifest = parse_and_validate_manifest(expected_bytes)?;
    verify_resource_tree(resource_root, &manifest.models)
}

fn parse_and_validate_manifest(bytes: &[u8]) -> Result<SupplyChainManifest, ReleaseManifestError> {
    let manifest: SupplyChainManifest =
        serde_json::from_slice(bytes).map_err(|_| ReleaseManifestError)?;
    let mut value: Value = serde_json::from_slice(bytes).map_err(|_| ReleaseManifestError)?;
    value.sort_all_objects();
    let mut canonical = serde_json::to_vec(&value).map_err(|_| ReleaseManifestError)?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(ReleaseManifestError);
    }

    validate_release_identity(&manifest)?;
    validate_dependency_inventory(&manifest)?;
    validate_model_policy(&manifest.models, manifest.counts.model_artifacts)?;
    Ok(manifest)
}

fn validate_release_identity(manifest: &SupplyChainManifest) -> Result<(), ReleaseManifestError> {
    if manifest.schema_version != 1
        || manifest.release.schema_version != 1
        || manifest.release.application_id != EXPECTED_APPLICATION_ID
        || manifest.release.application_version != env!("CARGO_PKG_VERSION")
        || manifest.release.release_sequence != EXPECTED_RELEASE_SEQUENCE
    {
        return Err(ReleaseManifestError);
    }
    Ok(())
}

fn validate_dependency_inventory(
    manifest: &SupplyChainManifest,
) -> Result<(), ReleaseManifestError> {
    if manifest.counts.dependencies != manifest.dependencies.len() as u64
        || manifest.counts.licenses != manifest.licenses.len() as u64
        || manifest.targets
            != EXPECTED_TARGETS
                .iter()
                .map(|target| (*target).to_owned())
                .collect::<Vec<_>>()
    {
        return Err(ReleaseManifestError);
    }

    if manifest.input_hashes.is_empty()
        || manifest
            .input_hashes
            .iter()
            .any(|(path, hash)| !is_safe_relative(path) || !is_sha256(hash))
    {
        return Err(ReleaseManifestError);
    }

    let mut previous_dependency: Option<(&str, &str, &str, &str)> = None;
    let mut projected_licenses = Vec::with_capacity(manifest.dependencies.len());
    for dependency in &manifest.dependencies {
        let identity = (
            dependency.ecosystem.as_str(),
            dependency.name.as_str(),
            dependency.version.as_str(),
            dependency.source.as_str(),
        );
        if previous_dependency.is_some_and(|previous| previous >= identity)
            || !matches!(dependency.ecosystem.as_str(), "cargo" | "npm")
            || dependency.name.is_empty()
            || dependency.version.is_empty()
            || dependency.source.is_empty()
            || dependency.license.is_empty()
            || dependency.roles.is_empty()
            || !is_sorted_unique(&dependency.roles)
            || dependency
                .roles
                .iter()
                .any(|role| !matches!(role.as_str(), "build" | "runtime"))
            || !is_sorted_unique(&dependency.targets)
            || dependency
                .targets
                .iter()
                .any(|target| !EXPECTED_TARGETS.contains(&target.as_str()))
        {
            return Err(ReleaseManifestError);
        }
        if dependency.install_script && dependency.ecosystem != "npm" {
            return Err(ReleaseManifestError);
        }
        let source_and_integrity_valid = match dependency.ecosystem.as_str() {
            "cargo" if dependency.source == CARGO_REGISTRY_SOURCE => {
                dependency.integrity.as_deref().is_some_and(is_sha256)
            }
            "npm" if is_npm_registry_source(&dependency.source) => {
                dependency.integrity.as_deref().is_some_and(is_sha512_sri)
            }
            "cargo" | "npm" if is_contained_path_source(&dependency.source) => {
                dependency.integrity.is_none()
            }
            _ => false,
        };
        if !source_and_integrity_valid {
            return Err(ReleaseManifestError);
        }
        previous_dependency = Some(identity);
        projected_licenses.push(License {
            ecosystem: dependency.ecosystem.clone(),
            license: dependency.license.clone(),
            name: dependency.name.clone(),
            source: dependency.source.clone(),
            version: dependency.version.clone(),
        });
    }

    if manifest.licenses != projected_licenses {
        return Err(ReleaseManifestError);
    }
    Ok(())
}

fn validate_model_policy(models: &Models, artifact_count: u64) -> Result<(), ReleaseManifestError> {
    if models.root != MODEL_ROOT
        || models.remote_model_code_allowed
        || models.prohibitions
            != EXPECTED_PROHIBITIONS
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>()
        || models.local_providers.segmentation.availability != "unavailable"
        || !remote_service_matches(
            &models.remote_services.outfit_recommendation,
            "openai",
            "gpt-5.6-sol",
        )
        || !remote_service_matches(
            &models.remote_services.try_on_visualization,
            "openai",
            "gpt-image-2",
        )
        || artifact_count != models.artifacts.len() as u64
    {
        return Err(ReleaseManifestError);
    }

    let mut previous_path: Option<&str> = None;
    for artifact in &models.artifacts {
        if previous_path.is_some_and(|previous| previous >= artifact.path.as_str())
            || !is_safe_relative(&artifact.path)
            || !is_sha256(&artifact.sha256)
            || artifact.provider.is_empty()
            || artifact.revision.is_empty()
            || artifact.execution_class != "data"
        {
            return Err(ReleaseManifestError);
        }
        previous_path = Some(&artifact.path);
    }
    Ok(())
}

fn remote_service_matches(service: &RemoteService, provider: &str, model: &str) -> bool {
    !service.downloads_code && service.provider == provider && service.model == model
}

fn verify_resource_tree(resource_root: &Path, models: &Models) -> Result<(), ReleaseManifestError> {
    let declared = models
        .artifacts
        .iter()
        .map(|artifact| (Path::new(&models.root).join(&artifact.path), artifact))
        .collect::<BTreeMap<_, _>>();
    let model_root = Path::new(&models.root);
    let mut observed = BTreeSet::new();
    let mut pending = vec![resource_root.to_path_buf()];

    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|_| ReleaseManifestError)?;
        for entry in entries {
            let entry = entry.map_err(|_| ReleaseManifestError)?;
            let path = entry.path();
            let relative = path
                .strip_prefix(resource_root)
                .map_err(|_| ReleaseManifestError)?;
            let metadata = fs::symlink_metadata(&path).map_err(|_| ReleaseManifestError)?;
            if metadata.file_type().is_symlink() {
                return Err(ReleaseManifestError);
            }
            if metadata.file_type().is_dir() {
                if is_model_shaped(relative) {
                    return Err(ReleaseManifestError);
                }
                pending.push(path);
                continue;
            }
            if !metadata.file_type().is_file()
                || metadata.permissions().mode() & 0o111 != 0
                || is_executable_resource(&path, relative)?
            {
                return Err(ReleaseManifestError);
            }

            let reviewed = declared.get(relative);
            if relative.starts_with(model_root) || is_model_shaped(relative) {
                let artifact = reviewed.ok_or(ReleaseManifestError)?;
                verify_artifact(&path, &metadata, artifact)?;
                observed.insert(relative.to_path_buf());
            } else if reviewed.is_some() {
                return Err(ReleaseManifestError);
            }
        }
    }

    if observed.len() != declared.len() || declared.keys().any(|path| !observed.contains(path)) {
        return Err(ReleaseManifestError);
    }
    Ok(())
}

fn verify_artifact(
    path: &Path,
    metadata: &fs::Metadata,
    artifact: &ModelArtifact,
) -> Result<(), ReleaseManifestError> {
    if metadata.len() != artifact.length {
        return Err(ReleaseManifestError);
    }
    let bytes = fs::read(path).map_err(|_| ReleaseManifestError)?;
    if Sha256Digest::from_bytes(&bytes).as_str() != artifact.sha256 {
        return Err(ReleaseManifestError);
    }
    Ok(())
}

fn is_executable_resource(path: &Path, relative: &Path) -> Result<bool, ReleaseManifestError> {
    if extension_is(relative, &EXECUTABLE_SUFFIXES) {
        return Ok(true);
    }
    let mut file = fs::File::open(path).map_err(|_| ReleaseManifestError)?;
    let mut magic = [0_u8; 4];
    let count = file.read(&mut magic).map_err(|_| ReleaseManifestError)?;
    let magic = &magic[..count];
    Ok(magic.starts_with(b"\x7fELF")
        || magic.starts_with(b"\0asm")
        || magic.starts_with(b"MZ")
        || matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        ))
}

fn is_model_shaped(path: &Path) -> bool {
    extension_is(path, &MODEL_SUFFIXES)
}

fn extension_is(path: &Path, choices: &[&str]) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| choices.contains(&extension.to_ascii_lowercase().as_str()))
}

fn is_safe_relative(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha512_sri(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("sha512-") else {
        return false;
    };
    encoded.len() == 88
        && encoded.ends_with("==")
        && encoded[..encoded.len() - 2]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

fn is_npm_registry_source(value: &str) -> bool {
    value.starts_with(NPM_REGISTRY_SOURCE_PREFIX)
        && value.ends_with(".tgz")
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'\\' | b'?' | b'#'))
        && !value.split('/').any(|component| component == "..")
}

fn is_contained_path_source(value: &str) -> bool {
    value
        .strip_prefix("path:")
        .is_some_and(|path| path == "." || is_safe_relative(path))
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn write_manifest(root: &Path, bytes: &[u8]) {
        let path = root.join(MANIFEST_RESOURCE_PATH);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn canonical(mut value: Value) -> Vec<u8> {
        value.sort_all_objects();
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn changed_manifest(change: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(COMPILED_MANIFEST_BYTES).unwrap();
        change(&mut value);
        canonical(value)
    }

    #[test]
    fn accepts_exact_compiled_and_bundled_manifest() {
        let resources = TempDir::new().unwrap();
        write_manifest(resources.path(), COMPILED_MANIFEST_BYTES);

        let manifest: SupplyChainManifest =
            serde_json::from_slice(COMPILED_MANIFEST_BYTES).unwrap();
        validate_release_identity(&manifest).unwrap();
        validate_dependency_inventory(&manifest).unwrap();
        validate_model_policy(&manifest.models, manifest.counts.model_artifacts).unwrap();
        verify_bundled_release_manifest(resources.path()).unwrap();
    }

    #[test]
    fn receipt_intelligence_release_requires_exact_evaluator_revision() {
        let manifest = |evaluator_sha256: &str| {
            changed_manifest(|value| {
                value["models"]["remote_services"]["openai_receipt_intelligence"] = json!({
                    "downloads_code": false,
                    "provider": "openai",
                    "model": "gpt-5.6-sol",
                    "prompt_revision": "receipt-intelligence-prompt-v1",
                    "schema_revision": "receipt-intelligence-v1",
                    "projection_revision": "receipt-intelligence-projection-v1",
                    "retention_revision": "p11-openai-responses-retention-v1",
                    "evaluator_sha256": evaluator_sha256,
                    "phase_spec_sha256": "e559ff6bcddf2d6546a50fbce22315b210c617c1454a3340ebcbd4619cb73c66",
                    "requirements_sha256": "42c1c1a182b82571b49b926f679e56f1eb3b8fe6f7bdbb987013ada71ed98bb3",
                    "proposal_sha256": "ab85491e61c17dbd465655e6e21dc087f079de4b7e58784a0637215847904d04",
                    "review_sha256": "f35b29c4ac6b72cd76612b0aff2c1341de4db6e6bdf5846d050fa9cadb3161a6"
                });
            })
        };

        assert!(receipt_intelligence_service_available_from(&manifest(
            EXPECTED_RECEIPT_INTELLIGENCE_EVALUATOR_SHA256
        )));
        assert!(!receipt_intelligence_service_available_from(&manifest(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )));
    }

    #[test]
    fn rejects_missing_and_tampered_manifest() {
        let missing = TempDir::new().unwrap();
        assert!(verify_bundled_release_manifest(missing.path()).is_err());

        let tampered = TempDir::new().unwrap();
        let mut bytes = COMPILED_MANIFEST_BYTES.to_vec();
        bytes[0] ^= 1;
        write_manifest(tampered.path(), &bytes);
        assert!(verify_bundled_release_manifest(tampered.path()).is_err());
    }

    #[test]
    fn rejects_noncanonical_or_open_json_even_when_expected_bytes_match() {
        let noncanonical = TempDir::new().unwrap();
        let value: Value = serde_json::from_slice(COMPILED_MANIFEST_BYTES).unwrap();
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        write_manifest(noncanonical.path(), &bytes);
        assert!(verify_with_expected(noncanonical.path(), &bytes).is_err());

        let open = TempDir::new().unwrap();
        let bytes = changed_manifest(|value| {
            value
                .as_object_mut()
                .unwrap()
                .insert("unexpected".to_owned(), json!(true));
        });
        write_manifest(open.path(), &bytes);
        assert!(verify_with_expected(open.path(), &bytes).is_err());
    }

    #[test]
    fn rejects_wrong_release_identity_even_when_expected_bytes_match() {
        let resources = TempDir::new().unwrap();
        let bytes = changed_manifest(|value| {
            value["release"]["application_id"] = json!("com.example.replaced");
        });
        write_manifest(resources.path(), &bytes);

        assert!(verify_with_expected(resources.path(), &bytes).is_err());
    }

    #[test]
    fn rejects_escaped_path_sources_and_invalid_registry_integrity() {
        let escaped = TempDir::new().unwrap();
        let bytes = changed_manifest(|value| {
            let dependency = value["dependencies"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|dependency| dependency["source"] == "path:src-tauri")
                .unwrap();
            dependency["source"] = json!("path:../src-tauri");
        });
        write_manifest(escaped.path(), &bytes);
        assert!(verify_with_expected(escaped.path(), &bytes).is_err());

        let invalid_sri = TempDir::new().unwrap();
        let bytes = changed_manifest(|value| {
            let dependency = value["dependencies"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|dependency| {
                    dependency["ecosystem"] == "npm"
                        && dependency["source"]
                            .as_str()
                            .is_some_and(|source| source.starts_with(NPM_REGISTRY_SOURCE_PREFIX))
                })
                .unwrap();
            dependency["integrity"] = json!("sha512-invalid");
        });
        write_manifest(invalid_sri.path(), &bytes);
        assert!(verify_with_expected(invalid_sri.path(), &bytes).is_err());
    }

    #[test]
    fn rejects_undeclared_model_and_executable_resources() {
        let model_resources = TempDir::new().unwrap();
        write_manifest(model_resources.path(), COMPILED_MANIFEST_BYTES);
        let model = model_resources.path().join("other/segmenter.onnx");
        fs::create_dir_all(model.parent().unwrap()).unwrap();
        fs::write(model, b"model").unwrap();
        assert!(verify_bundled_release_manifest(model_resources.path()).is_err());

        let executable_resources = TempDir::new().unwrap();
        write_manifest(executable_resources.path(), COMPILED_MANIFEST_BYTES);
        let executable = executable_resources.path().join("tools/helper");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_bundled_release_manifest(executable_resources.path()).is_err());
    }

    #[test]
    fn verifies_declared_model_hash_and_length() {
        let resources = TempDir::new().unwrap();
        let model_bytes = b"synthetic-model-data";
        let digest = Sha256Digest::from_bytes(model_bytes);
        let bytes = changed_manifest(|value| {
            value["counts"]["model_artifacts"] = json!(1);
            value["models"]["artifacts"] = json!([{
                "execution_class": "data",
                "length": model_bytes.len(),
                "path": "segmenter.onnx",
                "provider": "synthetic",
                "revision": "test-v1",
                "sha256": digest.as_str()
            }]);
        });
        write_manifest(resources.path(), &bytes);
        let model = resources.path().join(MODEL_ROOT).join("segmenter.onnx");
        fs::create_dir_all(model.parent().unwrap()).unwrap();
        fs::write(&model, model_bytes).unwrap();
        verify_with_expected(resources.path(), &bytes).unwrap();

        fs::write(model, b"synthetic-model-DATA").unwrap();
        assert!(verify_with_expected(resources.path(), &bytes).is_err());
    }
}
