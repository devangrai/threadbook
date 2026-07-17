use serde_json::json;
use wardrobe_core::{
    evaluate_update_compatibility, AcceptedDatabaseLineageV1, Sha256Digest, UpdateArchitectureV1,
    UpdateArtifactKindV1, UpdateChannelV1, UpdateCompatibilityContext,
    UpdateCompatibilityDecisionV1, UpdateCompatibilityFailureV1, UpdateManifestV1,
    UpdateOperatingSystemV1, UpdateSigningKeyRangeV1, MAX_SAFE_INTEGER_V1,
    MAX_UPDATE_ARTIFACT_BYTES_V1, UPDATE_APPLICATION_ID_V1, UPDATE_MANIFEST_SCHEMA_VERSION_V1,
};

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(character.to_string().repeat(64)).unwrap()
}

fn source_database() -> AcceptedDatabaseLineageV1 {
    AcceptedDatabaseLineageV1 {
        schema_version: 13,
        migration_prefix_sha256: digest('a'),
    }
}

fn manifest() -> UpdateManifestV1 {
    UpdateManifestV1 {
        schema_version: UPDATE_MANIFEST_SCHEMA_VERSION_V1,
        application_id: UPDATE_APPLICATION_ID_V1.to_owned(),
        channel: UpdateChannelV1::Personal,
        key_id: "wardrobe-release-2026".to_owned(),
        release_id: "wardrobe-0.2.0-2".to_owned(),
        release_sequence: 2,
        target_version: "0.2.0".to_owned(),
        target_os: UpdateOperatingSystemV1::Macos,
        target_architecture: UpdateArchitectureV1::Aarch64,
        minimum_macos_version: "15.0.0".to_owned(),
        artifact_kind: UpdateArtifactKindV1::MacosApplicationArchive,
        artifact_length: 4096,
        artifact_sha256: digest('b'),
        accepted_source_version_min: "0.1.0".to_owned(),
        accepted_source_version_max: "0.1.9".to_owned(),
        accepted_databases: vec![source_database()],
        target_database_schema_version: 15,
        target_migration_prefix_sha256: digest('c'),
        required_backup_format_version: 1,
        required_asset_manifest_version: 1,
    }
}

fn context() -> UpdateCompatibilityContext {
    UpdateCompatibilityContext {
        application_id: UPDATE_APPLICATION_ID_V1.to_owned(),
        channel: UpdateChannelV1::Personal,
        application_version: "0.1.0".to_owned(),
        installed_release_sequence: 1,
        operating_system: UpdateOperatingSystemV1::Macos,
        architecture: UpdateArchitectureV1::Aarch64,
        macos_version: "15.5.0".to_owned(),
        database: source_database(),
        supported_backup_format_version: 1,
        supported_asset_manifest_version: 1,
        signing_key: UpdateSigningKeyRangeV1 {
            key_id: "wardrobe-release-2026".to_owned(),
            minimum_release_sequence: 2,
            maximum_release_sequence: 100,
        },
    }
}

fn assert_rejected(
    manifest: &UpdateManifestV1,
    context: &UpdateCompatibilityContext,
    expected: UpdateCompatibilityFailureV1,
) {
    assert_eq!(
        evaluate_update_compatibility(manifest, context),
        UpdateCompatibilityDecisionV1::Rejected { reason: expected }
    );
}

#[test]
fn valid_contracts_roundtrip_and_are_compatible() {
    let manifest = manifest();
    let context = context();

    manifest.validate().unwrap();
    context.validate().unwrap();
    assert_eq!(
        evaluate_update_compatibility(&manifest, &context),
        UpdateCompatibilityDecisionV1::Compatible {}
    );

    let encoded = serde_json::to_vec(&manifest).unwrap();
    let decoded: UpdateManifestV1 = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
    assert!(encoded.starts_with(br#"{"schema_version":1,"application_id":"#));

    assert_eq!(
        serde_json::to_value(UpdateCompatibilityDecisionV1::Compatible {}).unwrap(),
        json!({"status": "compatible"})
    );
}

#[test]
fn every_contract_rejects_unknown_fields_and_closed_wire_values() {
    let mut manifest_value = serde_json::to_value(manifest()).unwrap();
    manifest_value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<UpdateManifestV1>(manifest_value).is_err());

    let mut context_value = serde_json::to_value(context()).unwrap();
    context_value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<UpdateCompatibilityContext>(context_value).is_err());

    let mut lineage_value = serde_json::to_value(source_database()).unwrap();
    lineage_value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<AcceptedDatabaseLineageV1>(lineage_value).is_err());

    let mut key_value = serde_json::to_value(context().signing_key).unwrap();
    key_value["public_key"] = json!("must-not-be-part-of-core-policy");
    assert!(serde_json::from_value::<UpdateSigningKeyRangeV1>(key_value).is_err());

    for (field, value) in [
        ("channel", json!("production")),
        ("target_os", json!("ios")),
        ("target_architecture", json!("universal")),
        ("artifact_kind", json!("shell_script")),
    ] {
        let mut value_with_unknown = serde_json::to_value(manifest()).unwrap();
        value_with_unknown[field] = value;
        assert!(
            serde_json::from_value::<UpdateManifestV1>(value_with_unknown).is_err(),
            "accepted unknown {field}"
        );
    }

    assert!(serde_json::from_value::<UpdateCompatibilityDecisionV1>(
        json!({"status": "compatible", "reason": "invalid_version"})
    )
    .is_err());
}

#[test]
fn manifest_rejects_invalid_versions_ranges_and_numeric_bounds() {
    for version in [
        "",
        "1",
        "1.2",
        "1.2.3.4",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2.3-beta",
        "4294967296.0.0",
    ] {
        let mut invalid = manifest();
        invalid.target_version = version.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(UpdateCompatibilityFailureV1::InvalidVersion),
            "accepted version {version:?}"
        );
    }

    let mut invalid = manifest();
    invalid.accepted_source_version_min = "0.2.0".to_owned();
    invalid.accepted_source_version_max = "0.1.0".to_owned();
    assert_eq!(
        invalid.validate(),
        Err(UpdateCompatibilityFailureV1::InvalidSourceVersionRange)
    );

    let mut invalid = manifest();
    invalid.release_sequence = MAX_SAFE_INTEGER_V1 + 1;
    assert_eq!(
        invalid.validate(),
        Err(UpdateCompatibilityFailureV1::InvalidReleaseSequence)
    );

    let mut invalid = manifest();
    invalid.artifact_length = MAX_UPDATE_ARTIFACT_BYTES_V1 + 1;
    assert_eq!(
        invalid.validate(),
        Err(UpdateCompatibilityFailureV1::InvalidArtifactLength)
    );
}

#[test]
fn compatibility_rejects_application_channel_and_platform_mismatches() {
    let context = context();

    let mut wrong_application = manifest();
    wrong_application.application_id = "com.example.wardrobe".to_owned();
    assert_rejected(
        &wrong_application,
        &context,
        UpdateCompatibilityFailureV1::ApplicationMismatch,
    );

    let mut wrong_channel = manifest();
    wrong_channel.channel = UpdateChannelV1::Development;
    assert_rejected(
        &wrong_channel,
        &context,
        UpdateCompatibilityFailureV1::ChannelMismatch,
    );

    let mut wrong_os = manifest();
    wrong_os.target_os = UpdateOperatingSystemV1::Linux;
    assert_rejected(
        &wrong_os,
        &context,
        UpdateCompatibilityFailureV1::PlatformMismatch,
    );

    let mut wrong_architecture = manifest();
    wrong_architecture.target_architecture = UpdateArchitectureV1::X86_64;
    assert_rejected(
        &wrong_architecture,
        &context,
        UpdateCompatibilityFailureV1::ArchitectureMismatch,
    );

    let mut unsupported_macos = manifest();
    unsupported_macos.minimum_macos_version = "16.0.0".to_owned();
    assert_rejected(
        &unsupported_macos,
        &context,
        UpdateCompatibilityFailureV1::MacosVersionUnsupported,
    );
}

#[test]
fn compatibility_rejects_source_version_and_downgrades() {
    let mut invalid_context = context();
    invalid_context.installed_release_sequence = 0;
    assert_eq!(
        invalid_context.validate(),
        Err(UpdateCompatibilityFailureV1::InvalidReleaseSequence)
    );

    let mut old_context = context();
    old_context.application_version = "0.0.9".to_owned();
    assert_rejected(
        &manifest(),
        &old_context,
        UpdateCompatibilityFailureV1::SourceVersionUnsupported,
    );

    let mut version_downgrade = manifest();
    version_downgrade.target_version = "0.1.0".to_owned();
    assert_rejected(
        &version_downgrade,
        &context(),
        UpdateCompatibilityFailureV1::TargetVersionNotNewer,
    );

    let mut sequence_downgrade = manifest();
    sequence_downgrade.release_sequence = 1;
    assert_rejected(
        &sequence_downgrade,
        &context(),
        UpdateCompatibilityFailureV1::ReleaseSequenceDowngrade,
    );
}

#[test]
fn compatibility_rejects_unknown_and_out_of_range_signing_keys() {
    let mut unknown_key = manifest();
    unknown_key.key_id = "different-reviewed-key".to_owned();
    assert_rejected(
        &unknown_key,
        &context(),
        UpdateCompatibilityFailureV1::SigningKeyMismatch,
    );

    let mut expired_key_context = context();
    expired_key_context.signing_key.minimum_release_sequence = 3;
    assert_rejected(
        &manifest(),
        &expired_key_context,
        UpdateCompatibilityFailureV1::SigningKeyOutOfRange,
    );

    let mut malformed_range = context();
    malformed_range.signing_key.minimum_release_sequence = 101;
    assert_eq!(
        malformed_range.validate(),
        Err(UpdateCompatibilityFailureV1::InvalidSigningKeyRange)
    );
}

#[test]
fn compatibility_requires_exact_source_database_lineage() {
    let mut wrong_schema = context();
    wrong_schema.database.schema_version = 12;
    assert_rejected(
        &manifest(),
        &wrong_schema,
        UpdateCompatibilityFailureV1::DatabaseLineageUnsupported,
    );

    let mut wrong_prefix = context();
    wrong_prefix.database.migration_prefix_sha256 = digest('d');
    assert_rejected(
        &manifest(),
        &wrong_prefix,
        UpdateCompatibilityFailureV1::DatabaseLineageUnsupported,
    );

    let mut database_downgrade = manifest();
    database_downgrade.target_database_schema_version = 12;
    assert_rejected(
        &database_downgrade,
        &context(),
        UpdateCompatibilityFailureV1::TargetDatabaseDowngrade,
    );

    let mut duplicate = manifest();
    duplicate.accepted_databases.push(source_database());
    assert_eq!(
        duplicate.validate(),
        Err(UpdateCompatibilityFailureV1::InvalidDatabaseLineage)
    );
}

#[test]
fn compatibility_requires_exact_supported_data_formats() {
    let mut backup_mismatch = manifest();
    backup_mismatch.required_backup_format_version = 2;
    assert_rejected(
        &backup_mismatch,
        &context(),
        UpdateCompatibilityFailureV1::BackupFormatUnsupported,
    );

    let mut asset_mismatch = manifest();
    asset_mismatch.required_asset_manifest_version = 2;
    assert_rejected(
        &asset_mismatch,
        &context(),
        UpdateCompatibilityFailureV1::AssetManifestFormatUnsupported,
    );
}
