use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema_version: u64,
    release_metadata_path: String,
    cargo: CargoPolicy,
    npm: NpmPolicy,
    swift: SwiftPolicy,
    models: ModelsPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoPolicy {
    allowed_dependency_kinds: Vec<String>,
    first_party_license: String,
    lockfile_path: String,
    manifest_path: String,
    registry_source: String,
    root_package: String,
    targets: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NpmPolicy {
    install_script_allowlist: Vec<NpmInstallScript>,
    lockfile_path: String,
    registry_base_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NpmInstallScript {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SwiftPolicy {
    allow_external_dependencies: bool,
    manifest_sha256: String,
    package_path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelsPolicy {
    artifacts: Vec<ModelArtifact>,
    local_providers: LocalProviders,
    prohibitions: Vec<String>,
    remote_model_code_allowed: bool,
    remote_services: BTreeMap<String, RemoteService>,
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
struct RemoteService {
    downloads_code: bool,
    model: String,
    provider: String,
    #[serde(default)]
    evaluator_sha256: Option<String>,
    #[serde(default)]
    phase_spec_sha256: Option<String>,
    #[serde(default)]
    projection_revision: Option<String>,
    #[serde(default)]
    prompt_revision: Option<String>,
    #[serde(default)]
    proposal_sha256: Option<String>,
    #[serde(default)]
    requirements_sha256: Option<String>,
    #[serde(default)]
    retention_revision: Option<String>,
    #[serde(default)]
    review_sha256: Option<String>,
    #[serde(default)]
    schema_revision: Option<String>,
}

fn nonempty(value: &str, label: &str) {
    assert!(!value.is_empty(), "{label} must not be empty");
}

fn validate_closed_policy(policy: &Policy) {
    assert_eq!(policy.schema_version, 1, "policy schema must be version 1");
    nonempty(&policy.release_metadata_path, "release metadata path");

    assert_eq!(
        policy.cargo.allowed_dependency_kinds,
        ["build", "normal"],
        "Cargo dependency kinds are not reviewed"
    );
    nonempty(&policy.cargo.first_party_license, "first-party license");
    nonempty(&policy.cargo.lockfile_path, "Cargo lock path");
    nonempty(&policy.cargo.manifest_path, "Cargo manifest path");
    nonempty(&policy.cargo.registry_source, "Cargo registry");
    nonempty(&policy.cargo.root_package, "Cargo root package");
    assert!(
        !policy.cargo.targets.is_empty(),
        "Cargo targets must not be empty"
    );

    nonempty(&policy.npm.lockfile_path, "npm lock path");
    nonempty(&policy.npm.registry_base_url, "npm registry");
    for entry in &policy.npm.install_script_allowlist {
        nonempty(&entry.name, "npm install-script package");
        nonempty(&entry.version, "npm install-script version");
    }

    assert!(
        !policy.swift.allow_external_dependencies,
        "external Swift dependencies are prohibited"
    );
    assert_eq!(
        policy.swift.manifest_sha256.len(),
        64,
        "Swift package manifest hash must be SHA-256"
    );
    assert!(
        policy
            .swift
            .manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Swift package manifest hash must be lowercase hexadecimal"
    );
    nonempty(&policy.swift.package_path, "Swift package path");

    assert!(
        !policy.models.remote_model_code_allowed,
        "remote model code must remain prohibited"
    );
    assert_eq!(
        policy.models.prohibitions.len(),
        4,
        "the reviewed model prohibition set must remain complete"
    );
    nonempty(&policy.models.root, "model artifact root");
    assert_eq!(
        policy.models.local_providers.segmentation.availability, "unavailable",
        "local segmentation must remain truthfully unavailable"
    );
    for artifact in &policy.models.artifacts {
        assert_eq!(
            artifact.execution_class, "data",
            "model artifacts must not be executable"
        );
        nonempty(&artifact.path, "model artifact path");
        nonempty(&artifact.provider, "model artifact provider");
        nonempty(&artifact.revision, "model artifact revision");
        assert_eq!(
            artifact.sha256.len(),
            64,
            "model artifact hash must be SHA-256"
        );
        let _ = artifact.length;
    }

    assert_eq!(
        policy.models.remote_services.len(),
        3,
        "remote service policy must contain exactly three reviewed bindings"
    );
    for (purpose, service) in &policy.models.remote_services {
        assert!(
            !service.downloads_code,
            "{purpose} must not download executable code"
        );
        nonempty(&service.provider, "remote service provider");
        nonempty(&service.model, "remote service model");
    }
    let receipt = service(policy, "openai_receipt_intelligence");
    assert_eq!(receipt.provider, "openai");
    assert_eq!(receipt.model, "gpt-5.6-sol");
    assert_eq!(
        receipt.evaluator_sha256.as_deref(),
        Some("3fd9db5e09176d6dd83616b40ece3d39a1f706612998a037e3c1293c5459b70e")
    );
    assert_eq!(
        receipt.phase_spec_sha256.as_deref(),
        Some("e559ff6bcddf2d6546a50fbce22315b210c617c1454a3340ebcbd4619cb73c66")
    );
    assert_eq!(
        receipt.prompt_revision.as_deref(),
        Some("receipt-intelligence-prompt-v1")
    );
    assert_eq!(
        receipt.schema_revision.as_deref(),
        Some("receipt-intelligence-v1")
    );
    assert_eq!(
        receipt.projection_revision.as_deref(),
        Some("receipt-intelligence-projection-v1")
    );
    assert_eq!(
        receipt.retention_revision.as_deref(),
        Some("p11-openai-responses-retention-v1")
    );
    assert_eq!(
        receipt.requirements_sha256.as_deref(),
        Some("42c1c1a182b82571b49b926f679e56f1eb3b8fe6f7bdbb987013ada71ed98bb3")
    );
    assert_eq!(
        receipt.proposal_sha256.as_deref(),
        Some("ab85491e61c17dbd465655e6e21dc087f079de4b7e58784a0637215847904d04")
    );
    assert_eq!(
        receipt.review_sha256.as_deref(),
        Some("f35b29c4ac6b72cd76612b0aff2c1341de4db6e6bdf5846d050fa9cadb3161a6")
    );
}

fn rust_string(value: &str) -> String {
    serde_json::to_string(value).expect("policy strings must serialize")
}

fn service<'a>(policy: &'a Policy, purpose: &str) -> &'a RemoteService {
    policy
        .models
        .remote_services
        .get(purpose)
        .unwrap_or_else(|| panic!("missing reviewed remote service binding: {purpose}"))
}

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"));
    let policy_path = manifest_dir.join("../../release/supply-chain-policy-v1.json");
    println!("cargo:rerun-if-changed={}", policy_path.display());

    let bytes = fs::read(&policy_path).unwrap_or_else(|error| {
        panic!(
            "failed to read release supply-chain policy {}: {error}",
            policy_path.display()
        )
    });
    let policy: Policy = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("invalid closed supply-chain policy: {error}"));
    validate_closed_policy(&policy);

    let recommendation = service(&policy, "outfit_recommendation");
    let try_on = service(&policy, "try_on_visualization");
    let generated = format!(
        "pub const OUTFIT_RECOMMENDATION_PROVIDER_V1: &str = {};\n\
         pub const OUTFIT_RECOMMENDATION_MODEL_V1: &str = {};\n\
         pub const TRY_ON_PROVIDER_V1: &str = {};\n\
         pub const TRY_ON_MODEL_V1: &str = {};\n",
        rust_string(&recommendation.provider),
        rust_string(&recommendation.model),
        rust_string(&try_on.provider),
        rust_string(&try_on.model),
    );

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("release_model_policy.rs");
    write_if_changed(&output, generated.as_bytes());
}

fn write_if_changed(path: &Path, bytes: &[u8]) {
    if fs::read(path).ok().as_deref() == Some(bytes) {
        return;
    }
    fs::write(path, bytes)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}
