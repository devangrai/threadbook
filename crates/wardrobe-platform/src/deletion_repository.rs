use crate::backup_repository::{
    format_timestamp, hash_private_file, lock_maintenance, MaintenanceGuard,
};
use crate::blob::sync_directory;
use crate::{
    BackupRepository, Database, MacOsPhotoKitKeychain, MaintenanceCoordinator, PhotoKitKeyError,
    PhotoKitKeyPort, PlatformError, PlatformResult, PrivateAppPaths,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use uuid::Uuid;
use wardrobe_core::{
    BackupId, BackupReasonV1, CatalogPortError, CatalogPortErrorKind, CatalogPortResult,
    CredentialProviderV1, DeletionBackupRetentionV1, DeletionHealthCountsV1,
    DeletionHealthStatusV1, DeletionHealthV1, DeletionPort, DeletionRemotePurposeV1,
    DeletionRemoteRetentionStatusV1, DeletionRemoteRetentionV1, DeletionRevisionSnapshotV1,
    DeletionRunId, DeletionTargetKindV1, ExecuteDeletionV1Request, ExecuteDeletionV1Response,
    OpenAiRetentionModeV1, ReplayStatusV1, Sha256Digest, Validate, SCHEMA_VERSION_V1,
};

const PLAN_TTL_MS: i64 = 15 * 60 * 1_000;
const EXECUTION_DEADLINE_MS: i64 = 60 * 60 * 1_000;
const TRANSIENT_DRAIN_RETRY_LIMIT: u8 = 3;
const TRANSIENT_DRAIN_RETRY_DELAY: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeletionDrainMode {
    Online,
    Recovery,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct TestDrainFault {
    transient_failures: u8,
    interrupt_after_blob: bool,
}

#[cfg(test)]
static TEST_DRAIN_FAULTS: OnceLock<Mutex<BTreeMap<String, TestDrainFault>>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct PreparedDeletionPlan {
    pub plan_sha256: Sha256Digest,
    pub prepared_at_ms: i64,
    pub expires_at_ms: i64,
    pub revisions: DeletionRevisionSnapshotV1,
    pub unique_blob_count: u64,
    pub unique_blob_bytes: u64,
    pub backup_retention: Vec<DeletionBackupRetentionV1>,
    pub remote_retention: Vec<DeletionRemoteRetentionV1>,
}

macro_rules! deletion_entity_kinds {
    ($($variant:ident => $table:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        enum DeletionEntityKind {
            $($variant),+
        }

        impl DeletionEntityKind {
            const ALL: &'static [Self] = &[$(Self::$variant),+];

            const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $table),+
                }
            }

            fn parse(value: &str) -> PlatformResult<Self> {
                match value {
                    $($table => Ok(Self::$variant),)+
                    _ => Err(PlatformError::Corrupt("deletion_entity_kind")),
                }
            }
        }

        impl Serialize for DeletionEntityKind {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }
    };
}

deletion_entity_kinds! {
    ImportRoots => "import_roots",
    ImportScans => "import_scans",
    LocalSources => "local_sources",
    SourceProvenance => "source_provenance",
    QuarantineRecords => "quarantine_records",
    MimeParts => "mime_parts",
    Evidence => "evidence",
    CatalogItems => "catalog_items",
    ItemEvidence => "item_evidence",
    CatalogDecisions => "catalog_decisions",
    DecisionEntities => "decision_entities",
    Derivatives => "derivatives",
    RemoteReferences => "remote_references",
    StorageChecks => "storage_checks",
    Jobs => "jobs",
    JobDependencies => "job_dependencies",
    JobResults => "job_results",
    JobFailures => "job_failures",
    Provenance => "provenance",
    CommandReceipts => "command_receipts",
    ReceiptParses => "receipt_parses",
    ReceiptFragments => "receipt_fragments",
    ReceiptExtractionRuns => "receipt_extraction_runs",
    ReceiptOrders => "receipt_orders",
    ReceiptOrderLines => "receipt_order_lines",
    ReceiptVariantEvidence => "receipt_variant_evidence",
    ReceiptFields => "receipt_fields",
    ReceiptFieldCitations => "receipt_field_citations",
    ReceiptReviewDecisions => "receipt_review_decisions",
    ReceiptReviewHeads => "receipt_review_heads",
    ReceiptCommandEntities => "receipt_command_entities",
    ReceiptImageCandidates => "receipt_image_candidates",
    ReceiptImageCandidateOverflow => "receipt_image_candidate_overflow",
    ReceiptImageApprovals => "receipt_image_approvals",
    ReceiptImageAttempts => "receipt_image_attempts",
    ReceiptImageAttemptOutcomes => "receipt_image_attempt_outcomes",
    ReceiptImageHops => "receipt_image_hops",
    ReceiptImageMaterializationIntents => "receipt_image_materialization_intents",
    ReceiptRemoteImages => "receipt_remote_images",
    PhotoScopes => "photo_scopes",
    PhotoScopeMembers => "photo_scope_members",
    PhotoSourceRevisions => "photo_source_revisions",
    PhotoAnalysisRuns => "photo_analysis_runs",
    PhotoAnalysisMemberClaims => "photo_analysis_member_claims",
    PhotoSegmentationAttempts => "photo_segmentation_attempts",
    PhotoSegmentationOutcomes => "photo_segmentation_outcomes",
    PhotoArtifacts => "photo_artifacts",
    PhotoArtifactParents => "photo_artifact_parents",
    PhotoObservations => "photo_observations",
    PhotoReviewDecisions => "photo_review_decisions",
    PhotoReviewHeads => "photo_review_heads",
    PhotoCommandEntities => "photo_command_entities",
    PhotoPersonDetectionRuns => "photo_person_detection_runs",
    PhotoPersonDetectionAttempts => "photo_person_detection_attempts",
    PhotoOwnerPreviewReferences => "photo_owner_preview_references",
    PhotoOwnerReviews => "photo_owner_reviews",
    PhotoDetectionCorrections => "photo_detection_corrections",
    PhotoPersonInstances => "photo_person_instances",
    PhotoOwnerDecisions => "photo_owner_decisions",
    PhotoOwnerHeads => "photo_owner_heads",
    PhotoOwnerWorkClaims => "photo_owner_work_claims",
    PhotoObservationOwnerLinks => "photo_observation_owner_links",
    PhotoOwnerCommandEntities => "photo_owner_command_entities",
    ReconciliationCases => "reconciliation_cases",
    ReconciliationCandidates => "reconciliation_candidates",
    ReconciliationCandidateEvidence => "reconciliation_candidate_evidence",
    ReconciliationEvidenceInputHashes => "reconciliation_evidence_input_hashes",
    ReconciliationDecisions => "reconciliation_decisions",
    ReconciliationDecisionHeads => "reconciliation_decision_heads",
    ReconciliationCommandEntities => "reconciliation_command_entities",
    GmailProviderSources => "gmail_provider_sources",
    GmailSourceRevisions => "gmail_source_revisions",
    GmailSourceHeads => "gmail_source_heads",
    GmailRevisionMaterializations => "gmail_revision_materializations",
    GmailScopeSources => "gmail_scope_sources",
    GmailOperations => "gmail_operations",
    GmailOperationRevisions => "gmail_operation_revisions",
    PhotoKitEnrollments => "photokit_enrollments",
    PhotoKitLocatorRecords => "photokit_locator_records",
    PhotoKitAssets => "photokit_assets",
    PhotoKitOperations => "photokit_operations",
    PhotoKitOperationObservations => "photokit_operation_observations",
    PhotoKitMaterializationAttempts => "photokit_materialization_attempts",
    PhotoKitMembershipGenerations => "photokit_membership_generations",
    PhotoKitMaterializations => "photokit_materializations",
    PhotoKitAvailabilityRevisions => "photokit_availability_revisions",
    PhotoKitAvailabilityHeads => "photokit_availability_heads",
    PhotoKitGenerationMembers => "photokit_generation_members",
    PhotoKitCommandReceipts => "photokit_command_receipts",
    Outfits => "outfits",
    OutfitMembers => "outfit_members",
    OutfitRecommendationApprovals => "outfit_recommendation_approvals",
    OutfitRecommendationAttempts => "outfit_recommendation_attempts",
    OutfitRecommendationProposals => "outfit_recommendation_proposals",
    OutfitRecommendationMembers => "outfit_recommendation_members",
    TryOnApprovals => "try_on_approvals",
    TryOnAssets => "try_on_assets",
    TryOnJobs => "try_on_jobs",
    TryOnAttempts => "try_on_attempts",
    TryOnOutputs => "try_on_outputs",
    Blobs => "blobs",
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PlanEntry {
    delete_rank: i64,
    entity_kind: DeletionEntityKind,
    key_json: String,
}

#[derive(Serialize)]
struct CanonicalPlan<'a> {
    target_kind: &'a str,
    target_id: &'a str,
    revisions: &'a DeletionRevisionSnapshotV1,
    entries: &'a BTreeSet<PlanEntry>,
    key_cleanup_actions: &'a [KeyCleanupAction],
    backup_retention: &'a [DeletionBackupRetentionV1],
    remote_retention: &'a [DeletionRemoteRetentionV1],
}

#[derive(Clone, Debug)]
struct CompiledPlan {
    entries: BTreeSet<PlanEntry>,
    key_cleanup_actions: Vec<KeyCleanupAction>,
    retained_shared_blob_count: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct KeyCleanupAction {
    enrollment_epoch: String,
    key_reference: String,
}

#[derive(Clone, Copy)]
struct DeleteSpec {
    table: &'static str,
    rank: i64,
    sql: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct BlobOwnerSpec {
    kind: DeletionEntityKind,
    blob_column: &'static str,
    key_expression: &'static str,
}

const BLOB_OWNER_SPECS: &[BlobOwnerSpec] = &[
    BlobOwnerSpec {
        kind: DeletionEntityKind::LocalSources,
        blob_column: "blob_sha256",
        key_expression: "json_array(source_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::SourceProvenance,
        blob_column: "blob_sha256",
        key_expression: "json_array(provenance_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::Provenance,
        blob_column: "blob_sha256",
        key_expression: "json_array(provenance_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::StorageChecks,
        blob_column: "blob_sha256",
        key_expression: "json_array(check_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::Derivatives,
        blob_column: "blob_sha256",
        key_expression: "json_array(derivative_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::ReceiptRemoteImages,
        blob_column: "source_blob_sha256",
        key_expression: "json_array(image_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::ReceiptRemoteImages,
        blob_column: "display_blob_sha256",
        key_expression: "json_array(image_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::ReceiptImageMaterializationIntents,
        blob_column: "source_blob_sha256",
        key_expression: "json_array(intent_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::ReceiptImageMaterializationIntents,
        blob_column: "display_blob_sha256",
        key_expression: "json_array(intent_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::PhotoSourceRevisions,
        blob_column: "blob_sha256",
        key_expression: "json_array(source_revision_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::PhotoSegmentationAttempts,
        blob_column: "input_blob_sha256",
        key_expression: "json_array(attempt_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::PhotoArtifacts,
        blob_column: "input_blob_sha256",
        key_expression: "json_array(artifact_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::PhotoPersonDetectionAttempts,
        blob_column: "input_blob_sha256",
        key_expression: "json_array(detection_attempt_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::PhotoOwnerPreviewReferences,
        blob_column: "blob_sha256",
        key_expression: "json_array(preview_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::GmailRevisionMaterializations,
        blob_column: "blob_sha256",
        key_expression: "json_array(revision_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::PhotoKitMaterializations,
        blob_column: "blob_sha256",
        key_expression: "json_array(materialization_id)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::OutfitMembers,
        blob_column: "blob_sha256",
        key_expression: "json_array(outfit_id,ordinal)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::TryOnAssets,
        blob_column: "parent_blob_sha256",
        key_expression: "json_array(approval_id,asset_ordinal)",
    },
    BlobOwnerSpec {
        kind: DeletionEntityKind::TryOnOutputs,
        blob_column: "blob_sha256",
        key_expression: "json_array(output_id)",
    },
];

const RETAINED_INFRASTRUCTURE_TABLES: &[&str] = &[
    "credential_references",
    "gmail_accounts",
    "gmail_checkpoints",
    "gmail_connector_settings",
    "gmail_connector_state",
    "gmail_disconnect_stages",
    "gmail_oauth_attempts",
    "gmail_scopes",
    "photokit_connector_state",
    "photokit_key_cleanup_intents",
    "revision_state",
    "schema_migrations",
    "settings",
    "store_authority_epoch",
];

const DELETION_BOOKKEEPING_TABLES: &[&str] = &[
    "domain_mutation_authority",
    "deletion_execution_authority",
    "deletion_execution_receipts",
    "deletion_plan_backup_retention",
    "deletion_plan_entries",
    "deletion_plan_photokit_key_cleanup",
    "deletion_plan_remote_retention",
    "deletion_plans",
    "deletion_preview_items",
    "deletion_previews",
    "deletion_run_backup_retention",
    "deletion_run_blobs",
    "deletion_run_remote_retention",
    "deletion_runs",
];

macro_rules! delete_spec {
    ($table:literal, $rank:literal, $where:literal) => {
        DeleteSpec {
            table: $table,
            rank: $rank,
            sql: concat!("DELETE FROM ", $table, " WHERE ", $where),
        }
    };
}

const DELETE_SPECS: &[DeleteSpec] = &[
    delete_spec!("job_dependencies", 10, "job_id=json_extract(?1,'$[0]') AND depends_on_job_id=json_extract(?1,'$[1]')"),
    delete_spec!("receipt_field_citations", 10, "citation_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_review_heads", 10, "order_evidence_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_command_entities", 10, "request_id=json_extract(?1,'$[0]') AND entity_kind=json_extract(?1,'$[1]') AND entity_id=json_extract(?1,'$[2]')"),
    delete_spec!("receipt_image_attempt_outcomes", 10, "attempt_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_image_hops", 10, "attempt_id=json_extract(?1,'$[0]') AND hop_ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("receipt_remote_images", 10, "image_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_review_heads", 10, "observation_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_command_entities", 10, "request_id=json_extract(?1,'$[0]') AND entity_kind=json_extract(?1,'$[1]') AND entity_id=json_extract(?1,'$[2]')"),
    delete_spec!("photo_owner_command_entities", 10, "request_id=json_extract(?1,'$[0]') AND entity_kind=json_extract(?1,'$[1]') AND entity_id=json_extract(?1,'$[2]')"),
    delete_spec!("photo_artifact_parents", 10, "artifact_id=json_extract(?1,'$[0]') AND parent_ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("photo_analysis_member_claims", 100, "run_id=json_extract(?1,'$[0]') AND member_ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("photo_owner_heads", 10, "source_revision_id=json_extract(?1,'$[0]')"),
    delete_spec!("reconciliation_decision_heads", 10, "case_id=json_extract(?1,'$[0]')"),
    delete_spec!("reconciliation_command_entities", 10, "request_id=json_extract(?1,'$[0]') AND entity_kind=json_extract(?1,'$[1]') AND entity_id=json_extract(?1,'$[2]')"),
    delete_spec!("reconciliation_evidence_input_hashes", 10, "evidence_id=json_extract(?1,'$[0]') AND input_ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("gmail_source_heads", 10, "provider_source_id=json_extract(?1,'$[0]')"),
    delete_spec!("gmail_scope_sources", 10, "scope_id=json_extract(?1,'$[0]') AND provider_source_id=json_extract(?1,'$[1]')"),
    delete_spec!("gmail_operation_revisions", 10, "request_id=json_extract(?1,'$[0]') AND revision_id=json_extract(?1,'$[1]')"),
    delete_spec!("photokit_command_receipts", 10, "request_id=json_extract(?1,'$[0]')"),
    delete_spec!("photokit_availability_heads", 10, "asset_id=json_extract(?1,'$[0]')"),
    delete_spec!("photokit_generation_members", 15, "enrollment_epoch=json_extract(?1,'$[0]') AND membership_generation=json_extract(?1,'$[1]') AND ordinal=json_extract(?1,'$[2]')"),
    delete_spec!("photokit_materialization_attempts", 20, "attempt_id=json_extract(?1,'$[0]')"),
    delete_spec!("photokit_availability_revisions", 25, "revision_id=json_extract(?1,'$[0]')"),
    delete_spec!("photokit_materializations", 30, "materialization_id=json_extract(?1,'$[0]')"),
    delete_spec!("photokit_operation_observations", 35, "operation_id=json_extract(?1,'$[0]') AND ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("photokit_membership_generations", 40, "enrollment_epoch=json_extract(?1,'$[0]') AND membership_generation=json_extract(?1,'$[1]')"),
    delete_spec!("photokit_assets", 45, "asset_id=json_extract(?1,'$[0]')"),
    delete_spec!("photokit_locator_records", 50, "locator_id=json_extract(?1,'$[0]')"),
    delete_spec!("photokit_operations", 55, "operation_id=json_extract(?1,'$[0]')"),
    delete_spec!("photokit_enrollments", 60, "enrollment_epoch=json_extract(?1,'$[0]')"),
    delete_spec!("outfit_recommendation_members", 10, "attempt_id=json_extract(?1,'$[0]') AND proposal_ordinal=json_extract(?1,'$[1]') AND member_ordinal=json_extract(?1,'$[2]')"),
    delete_spec!("try_on_outputs", 10, "output_id=json_extract(?1,'$[0]')"),
    delete_spec!("try_on_attempts", 15, "attempt_id=json_extract(?1,'$[0]')"),
    delete_spec!("outfit_members", 15, "outfit_id=json_extract(?1,'$[0]') AND ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("item_evidence", 15, "item_id=json_extract(?1,'$[0]') AND evidence_id=json_extract(?1,'$[1]')"),
    delete_spec!("decision_entities", 15, "decision_id=json_extract(?1,'$[0]') AND entity_kind=json_extract(?1,'$[1]') AND entity_id=json_extract(?1,'$[2]')"),
    delete_spec!("job_results", 15, "job_id=json_extract(?1,'$[0]')"),
    delete_spec!("job_failures", 15, "job_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_image_materialization_intents", 15, "intent_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_image_attempts", 20, "attempt_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_image_approvals", 20, "approval_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_segmentation_outcomes", 85, "attempt_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_observation_owner_links", 50, "observation_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_owner_work_claims", 50, "owner_decision_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_segmentation_attempts", 90, "attempt_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_observations", 70, "observation_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_review_decisions", 60, "decision_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_artifacts", 80, "artifact_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_owner_decisions", 500, "owner_decision_id=json_extract(?1,'$[0]')"),
    delete_spec!("reconciliation_decisions", 25, "decision_id=json_extract(?1,'$[0]')"),
    delete_spec!("reconciliation_candidate_evidence", 25, "evidence_id=json_extract(?1,'$[0]')"),
    delete_spec!("outfit_recommendation_proposals", 25, "attempt_id=json_extract(?1,'$[0]') AND ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("try_on_jobs", 25, "job_id=json_extract(?1,'$[0]')"),
    delete_spec!("derivatives", 30, "derivative_id=json_extract(?1,'$[0]')"),
    delete_spec!("remote_references", 30, "remote_reference_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_fields", 30, "field_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_variant_evidence", 30, "variant_evidence_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_order_lines", 35, "order_line_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_image_candidates", 35, "candidate_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_image_candidate_overflow", 35, "parse_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_analysis_runs", 640, "run_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_person_detection_runs", 640, "run_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_person_instances", 600, "person_instance_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_detection_corrections", 610, "correction_id=json_extract(?1,'$[0]')"),
    delete_spec!("reconciliation_candidates", 35, "candidate_id=json_extract(?1,'$[0]')"),
    delete_spec!("gmail_revision_materializations", 35, "revision_id=json_extract(?1,'$[0]')"),
    delete_spec!("outfit_recommendation_attempts", 35, "attempt_id=json_extract(?1,'$[0]')"),
    delete_spec!("try_on_assets", 35, "approval_id=json_extract(?1,'$[0]') AND asset_ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("outfits", 40, "outfit_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_review_decisions", 40, "review_decision_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_orders", 40, "order_evidence_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_scope_members", 650, "scope_id=json_extract(?1,'$[0]') AND member_ordinal=json_extract(?1,'$[1]')"),
    delete_spec!("photo_owner_reviews", 620, "owner_review_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_owner_preview_references", 630, "preview_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_person_detection_attempts", 630, "detection_attempt_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_source_revisions", 660, "source_revision_id=json_extract(?1,'$[0]')"),
    delete_spec!("reconciliation_cases", 40, "case_id=json_extract(?1,'$[0]')"),
    delete_spec!("gmail_source_revisions", 40, "revision_id=json_extract(?1,'$[0]')"),
    delete_spec!("gmail_operations", 40, "request_id=json_extract(?1,'$[0]')"),
    delete_spec!("outfit_recommendation_approvals", 40, "approval_id=json_extract(?1,'$[0]')"),
    delete_spec!("try_on_approvals", 40, "approval_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_extraction_runs", 45, "run_id=json_extract(?1,'$[0]')"),
    delete_spec!("photo_scopes", 680, "scope_id=json_extract(?1,'$[0]')"),
    delete_spec!("gmail_provider_sources", 45, "provider_source_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_fragments", 50, "fragment_id=json_extract(?1,'$[0]')"),
    delete_spec!("receipt_parses", 55, "parse_id=json_extract(?1,'$[0]')"),
    delete_spec!("catalog_decisions", 55, "decision_id=json_extract(?1,'$[0]')"),
    delete_spec!("storage_checks", 55, "check_id=json_extract(?1,'$[0]')"),
    delete_spec!("jobs", 55, "job_id=json_extract(?1,'$[0]')"),
    delete_spec!("provenance", 55, "provenance_id=json_extract(?1,'$[0]')"),
    delete_spec!("quarantine_records", 55, "quarantine_id=json_extract(?1,'$[0]')"),
    delete_spec!("evidence", 60, "evidence_id=json_extract(?1,'$[0]')"),
    delete_spec!("mime_parts", 500, "part_id=json_extract(?1,'$[0]')"),
    delete_spec!("source_provenance", 690, "provenance_id=json_extract(?1,'$[0]')"),
    delete_spec!("catalog_items", 65, "item_id=json_extract(?1,'$[0]')"),
    delete_spec!("local_sources", 700, "source_id=json_extract(?1,'$[0]')"),
    delete_spec!("import_scans", 800, "scan_id=json_extract(?1,'$[0]')"),
    delete_spec!("import_roots", 900, "root_id=json_extract(?1,'$[0]')"),
    delete_spec!("command_receipts", 950, "request_id=json_extract(?1,'$[0]')"),
    delete_spec!("blobs", 1000, "sha256=json_extract(?1,'$[0]')"),
];

pub(crate) fn prepare_plan(
    transaction: &Transaction<'_>,
    paths: &PrivateAppPaths,
    maintenance: &MaintenanceGuard,
    snapshot_token: &str,
    target_kind: DeletionTargetKindV1,
    target_id: &str,
    now_ms: i64,
) -> PlatformResult<PreparedDeletionPlan> {
    validate_schema_classification(transaction)?;
    let epoch: String = transaction.query_row(
        "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let revisions = current_revisions(transaction)?;
    let compiled = compile_entries(transaction, snapshot_token)?;
    let unique_blobs = compiled
        .entries
        .iter()
        .filter(|entry| entry.entity_kind == DeletionEntityKind::Blobs)
        .map(|entry| {
            serde_json::from_str::<Vec<String>>(&entry.key_json)
                .map_err(PlatformError::from)?
                .into_iter()
                .next()
                .ok_or(PlatformError::Corrupt("deletion_blob_key"))
        })
        .collect::<PlatformResult<BTreeSet<_>>>()?;
    let unique_blob_bytes = unique_blobs.iter().try_fold(0_u64, |total, hash| {
        let bytes: i64 = transaction.query_row(
            "SELECT byte_length FROM blobs WHERE sha256=?1",
            [hash],
            |row| row.get(0),
        )?;
        total
            .checked_add(
                u64::try_from(bytes).map_err(|_| PlatformError::Corrupt("deletion_blob_bytes"))?,
            )
            .ok_or(PlatformError::InvalidInput("deletion_blob_bytes"))
    })?;
    let backup_retention = BackupRepository::new(paths).deletion_retention_locked(
        target_kind,
        target_id,
        &unique_blobs,
        maintenance,
    )?;
    let remote_retention = remote_retention(transaction, snapshot_token)?;
    let target_kind_text = target_kind_db(target_kind);
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&CanonicalPlan {
            target_kind: target_kind_text,
            target_id,
            revisions: &revisions,
            entries: &compiled.entries,
            key_cleanup_actions: &compiled.key_cleanup_actions,
            backup_retention: &backup_retention,
            remote_retention: &remote_retention,
        })?)
    );
    let expires_at_ms = now_ms
        .checked_add(PLAN_TTL_MS)
        .ok_or(PlatformError::InvalidInput("deletion_expiry"))?;
    transaction.execute(
        "INSERT INTO deletion_plans(
            snapshot_token,epoch,target_kind,target_id,plan_sha256,catalog_revision,
            evidence_generation,receipt_revision,photo_revision,reconciliation_revision,
            outfit_revision,try_on_revision,photokit_revision,prepared_at_ms,expires_at_ms,
            unique_blob_count,unique_blob_bytes,retained_shared_blob_count
         ) VALUES(
            ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18
         )",
        params![
            snapshot_token,
            epoch,
            target_kind_text,
            target_id,
            digest,
            revisions.catalog_revision as i64,
            revisions.evidence_generation as i64,
            revisions.receipt_revision as i64,
            revisions.photo_revision as i64,
            revisions.reconciliation_revision as i64,
            revisions.outfit_revision as i64,
            revisions.try_on_revision as i64,
            revisions.photokit_revision as i64,
            now_ms,
            expires_at_ms,
            unique_blobs.len() as i64,
            unique_blob_bytes as i64,
            compiled.retained_shared_blob_count as i64,
        ],
    )?;
    for entry in &compiled.entries {
        transaction.execute(
            "INSERT INTO deletion_plan_entries(snapshot_token,epoch,entity_kind,key_json,delete_rank)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                snapshot_token,
                epoch,
                entry.entity_kind.as_str(),
                entry.key_json,
                entry.delete_rank
            ],
        )?;
    }
    for action in &compiled.key_cleanup_actions {
        transaction.execute(
            "INSERT INTO deletion_plan_photokit_key_cleanup(
                snapshot_token,epoch,enrollment_epoch,key_reference
             ) VALUES(?1,?2,?3,?4)",
            params![
                snapshot_token,
                epoch,
                action.enrollment_epoch,
                action.key_reference
            ],
        )?;
    }
    store_plan_reports(
        transaction,
        snapshot_token,
        &backup_retention,
        &remote_retention,
    )?;
    Ok(PreparedDeletionPlan {
        plan_sha256: Sha256Digest::parse(digest)
            .map_err(|_| PlatformError::Corrupt("deletion_plan_digest"))?,
        prepared_at_ms: now_ms,
        expires_at_ms,
        revisions,
        unique_blob_count: unique_blobs.len() as u64,
        unique_blob_bytes,
        backup_retention,
        remote_retention,
    })
}

fn validate_schema_classification(connection: &Connection) -> PlatformResult<()> {
    let deletable = DeletionEntityKind::ALL
        .iter()
        .map(|kind| kind.as_str())
        .collect::<BTreeSet<_>>();
    let delete_specs = DELETE_SPECS
        .iter()
        .map(|spec| spec.table)
        .collect::<BTreeSet<_>>();
    if deletable.len() != DeletionEntityKind::ALL.len()
        || delete_specs.len() != DELETE_SPECS.len()
        || deletable != delete_specs
    {
        return Err(PlatformError::Corrupt("deletion_table_inventory"));
    }
    let retained = RETAINED_INFRASTRUCTURE_TABLES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let bookkeeping = DELETION_BOOKKEEPING_TABLES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if retained.len() != RETAINED_INFRASTRUCTURE_TABLES.len()
        || bookkeeping.len() != DELETION_BOOKKEEPING_TABLES.len()
        || !deletable.is_disjoint(&retained)
        || !deletable.is_disjoint(&bookkeeping)
        || !retained.is_disjoint(&bookkeeping)
    {
        return Err(PlatformError::Corrupt("deletion_schema_classification"));
    }
    let expected = deletable
        .union(&retained)
        .copied()
        .collect::<BTreeSet<_>>()
        .union(&bookkeeping)
        .copied()
        .collect::<BTreeSet<_>>();
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type='table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let actual = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected.into_iter().map(str::to_owned).collect() {
        return Err(PlatformError::Corrupt("deletion_schema_classification"));
    }
    for table in &deletable {
        let guarded: i64 = connection.query_row(
            "SELECT COUNT(*)
             FROM sqlite_schema
             WHERE type = 'trigger'
               AND tbl_name = ?1
               AND instr(lower(sql), 'before delete') > 0
               AND instr(sql, 'deletion_execution_authority') > 0
               AND instr(sql, 'deletion_plan_entries') > 0
               AND instr(sql, ?1) > 0",
            [table],
            |row| row.get(0),
        )?;
        if guarded == 0 {
            return Err(PlatformError::Corrupt("deletion_authority_trigger"));
        }
    }
    let expected_blob_owners = BLOB_OWNER_SPECS
        .iter()
        .map(|owner| (owner.kind.as_str().to_owned(), owner.blob_column.to_owned()))
        .collect::<BTreeSet<_>>();
    if expected_blob_owners.len() != BLOB_OWNER_SPECS.len() {
        return Err(PlatformError::Corrupt("deletion_blob_owner_inventory"));
    }
    let mut actual_blob_owners = BTreeSet::new();
    for table in &actual {
        let columns_sql = format!("SELECT name FROM pragma_table_info('{table}')");
        let columns = connection
            .prepare(&columns_sql)?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for column in columns {
            if column == "blob_sha256"
                || column == "source_blob_sha256"
                || column == "display_blob_sha256"
                || column == "input_blob_sha256"
                || column == "parent_blob_sha256"
            {
                actual_blob_owners.insert((table.clone(), column));
            }
        }
        let foreign_keys_sql =
            format!("SELECT \"table\",\"from\" FROM pragma_foreign_key_list('{table}')");
        for (target, column) in connection
            .prepare(&foreign_keys_sql)?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            if target == "blobs" {
                actual_blob_owners.insert((table.clone(), column));
            }
        }
    }
    if actual_blob_owners != expected_blob_owners {
        return Err(PlatformError::Corrupt("deletion_blob_owner_inventory"));
    }
    Ok(())
}

fn compile_entries(connection: &Connection, snapshot_token: &str) -> PlatformResult<CompiledPlan> {
    let mut entries = BTreeSet::new();
    augment_photokit_entries(connection, snapshot_token, &mut entries)?;
    let key_cleanup_actions = compile_key_cleanup_actions(connection, snapshot_token)?;
    let mut statement = connection.prepare(
        "SELECT dependency_class, entity_id FROM deletion_preview_items
         WHERE snapshot_token=?1 ORDER BY dependency_class,entity_id",
    )?;
    let rows = statement
        .query_map([snapshot_token], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (class, id) in rows {
        if class == "retained_shared_blobs" {
            continue;
        }
        if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        if Uuid::parse_str(&id).is_ok() {
            for (table, column) in [
                ("import_roots", "root_id"),
                ("local_sources", "source_id"),
                ("catalog_items", "item_id"),
                ("evidence", "evidence_id"),
                ("catalog_decisions", "decision_id"),
            ] {
                add_existing_simple(connection, &mut entries, table, column, &id)?;
            }
            continue;
        }
        if id.starts_with("deletion_preview:")
            || id.starts_with("deletion_preview_item:")
            || id.starts_with("photokit_key_cleanup:")
            || id.starts_with("try_on_remote_reference:")
            || id.starts_with("try_on_provenance:")
            || id.starts_with("try_on_materialization_intent:")
        {
            continue;
        }
        if add_prefixed_entry(connection, &mut entries, &id)? {
            continue;
        }
        return Err(PlatformError::Corrupt("unclassified_deletion_plan_row"));
    }
    expand_parent_rows(connection, &mut entries)?;
    let retained_shared_blob_count = reconcile_blob_entries(connection, &mut entries)?;
    Ok(CompiledPlan {
        entries,
        key_cleanup_actions,
        retained_shared_blob_count,
    })
}

fn compile_key_cleanup_actions(
    connection: &Connection,
    snapshot_token: &str,
) -> PlatformResult<Vec<KeyCleanupAction>> {
    let target = connection
        .query_row(
            "SELECT target_kind,target_id FROM deletion_previews
             WHERE snapshot_token=?1",
            [snapshot_token],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((target_kind, target_id)) = target else {
        return Ok(Vec::new());
    };
    if target_kind != "photokit_enrollment" {
        return Ok(Vec::new());
    }
    let key_reference = connection
        .query_row(
            "SELECT key_reference FROM photokit_enrollments
             WHERE enrollment_epoch=?1",
            [&target_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(PlatformError::Conflict("snapshot_expired"))?;
    Ok(vec![KeyCleanupAction {
        enrollment_epoch: target_id,
        key_reference,
    }])
}

fn augment_photokit_entries(
    connection: &Connection,
    snapshot_token: &str,
    entries: &mut BTreeSet<PlanEntry>,
) -> PlatformResult<()> {
    let target = connection
        .query_row(
            "SELECT target_kind,target_id FROM deletion_previews
             WHERE snapshot_token=?1",
            [snapshot_token],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((target_kind, target_id)) = target else {
        return Ok(());
    };
    if target_kind != "photokit_enrollment" && target_kind != "photokit_asset" {
        return Ok(());
    }

    let (enrollment_epoch, asset_ids) = if target_kind == "photokit_enrollment" {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM photokit_enrollments WHERE enrollment_epoch=?1
             )",
            [&target_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(PlatformError::Conflict("snapshot_expired"));
        }
        let mut statement = connection.prepare(
            "SELECT asset_id FROM photokit_assets
             WHERE enrollment_epoch=?1 ORDER BY asset_id",
        )?;
        let assets = statement
            .query_map([&target_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        (target_id, assets)
    } else {
        let row = connection
            .query_row(
                "SELECT enrollment_epoch,asset_id FROM photokit_assets
                 WHERE asset_id=?1",
                [&target_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or(PlatformError::Conflict("snapshot_expired"))?;
        (row.0, vec![row.1])
    };

    for asset_id in &asset_ids {
        add_existing_simple(
            connection,
            entries,
            "photokit_availability_heads",
            "asset_id",
            asset_id,
        )?;
        add_existing_simple(connection, entries, "photokit_assets", "asset_id", asset_id)?;

        let mut statement = connection.prepare(
            "SELECT materialization_id FROM photokit_materializations
             WHERE asset_id=?1 ORDER BY materialization_id",
        )?;
        for id in statement
            .query_map([asset_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_existing_simple(
                connection,
                entries,
                "photokit_materializations",
                "materialization_id",
                &id,
            )?;
        }

        let mut statement = connection.prepare(
            "SELECT revision_id FROM photokit_availability_revisions
             WHERE asset_id=?1 ORDER BY revision_id",
        )?;
        for id in statement
            .query_map([asset_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_existing_simple(
                connection,
                entries,
                "photokit_availability_revisions",
                "revision_id",
                &id,
            )?;
        }

        let mut statement = connection.prepare(
            "SELECT enrollment_epoch,membership_generation,ordinal
             FROM photokit_generation_members
             WHERE asset_id=?1
             ORDER BY enrollment_epoch,membership_generation,ordinal",
        )?;
        for (epoch, generation, ordinal) in statement
            .query_map([asset_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_entry(
                entries,
                "photokit_generation_members",
                serde_json::json!([epoch, generation, ordinal]),
            )?;
        }

        let mut statement = connection.prepare(
            "SELECT operation_id,ordinal
             FROM photokit_operation_observations
             WHERE asset_id=?1 ORDER BY operation_id,ordinal",
        )?;
        let observations = statement
            .query_map([asset_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (operation_id, ordinal) in observations {
            let mut attempts = connection.prepare(
                "SELECT attempt_id FROM photokit_materialization_attempts
                 WHERE operation_id=?1 AND observation_ordinal=?2
                 ORDER BY attempt_id",
            )?;
            for attempt_id in attempts
                .query_map(params![operation_id, ordinal], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
            {
                add_existing_simple(
                    connection,
                    entries,
                    "photokit_materialization_attempts",
                    "attempt_id",
                    &attempt_id,
                )?;
            }
            add_entry(
                entries,
                "photokit_operation_observations",
                serde_json::json!([operation_id, ordinal]),
            )?;
        }

        let locator_id: String = connection.query_row(
            "SELECT locator_id FROM photokit_assets WHERE asset_id=?1",
            [asset_id],
            |row| row.get(0),
        )?;
        add_existing_simple(
            connection,
            entries,
            "photokit_locator_records",
            "locator_id",
            &locator_id,
        )?;
    }

    if target_kind == "photokit_enrollment" {
        let mut statement = connection.prepare(
            "SELECT attempt.attempt_id
             FROM photokit_materialization_attempts attempt
             JOIN photokit_operations operation
               ON operation.operation_id=attempt.operation_id
             WHERE operation.enrollment_epoch=?1
             ORDER BY attempt.attempt_id",
        )?;
        for attempt_id in statement
            .query_map([&enrollment_epoch], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_existing_simple(
                connection,
                entries,
                "photokit_materialization_attempts",
                "attempt_id",
                &attempt_id,
            )?;
        }
        let mut statement = connection.prepare(
            "SELECT observation.operation_id,observation.ordinal
             FROM photokit_operation_observations observation
             JOIN photokit_operations operation
               ON operation.operation_id=observation.operation_id
             WHERE operation.enrollment_epoch=?1
             ORDER BY observation.operation_id,observation.ordinal",
        )?;
        for (operation_id, ordinal) in statement
            .query_map([&enrollment_epoch], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_entry(
                entries,
                "photokit_operation_observations",
                serde_json::json!([operation_id, ordinal]),
            )?;
        }
        let mut statement = connection.prepare(
            "SELECT enrollment_epoch,membership_generation,ordinal
             FROM photokit_generation_members
             WHERE enrollment_epoch=?1
             ORDER BY membership_generation,ordinal",
        )?;
        for (epoch, generation, ordinal) in statement
            .query_map([&enrollment_epoch], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_entry(
                entries,
                "photokit_generation_members",
                serde_json::json!([epoch, generation, ordinal]),
            )?;
        }
        for (table, column) in [
            ("photokit_command_receipts", "request_id"),
            ("photokit_operations", "operation_id"),
            ("photokit_locator_records", "locator_id"),
        ] {
            let sql = format!(
                "SELECT {column} FROM {table}
                 WHERE enrollment_epoch=?1 ORDER BY {column}"
            );
            let mut statement = connection.prepare(&sql)?;
            for id in statement
                .query_map([&enrollment_epoch], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
            {
                add_existing_simple(connection, entries, table, column, &id)?;
            }
        }
        let mut statement = connection.prepare(
            "SELECT enrollment_epoch,membership_generation
             FROM photokit_membership_generations
             WHERE enrollment_epoch=?1 ORDER BY membership_generation",
        )?;
        for (epoch, generation) in statement
            .query_map([&enrollment_epoch], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_entry(
                entries,
                "photokit_membership_generations",
                serde_json::json!([epoch, generation]),
            )?;
        }
        add_existing_simple(
            connection,
            entries,
            "photokit_enrollments",
            "enrollment_epoch",
            &enrollment_epoch,
        )?;
    }
    Ok(())
}

fn reconcile_blob_entries(
    connection: &Connection,
    entries: &mut BTreeSet<PlanEntry>,
) -> PlatformResult<u64> {
    let mut owner_counts = BTreeMap::<String, (u64, u64)>::new();
    for owner in BLOB_OWNER_SPECS {
        let sql = format!(
            "SELECT {0},{1} FROM {2} WHERE {0} IS NOT NULL ORDER BY {1}",
            owner.blob_column,
            owner.key_expression,
            owner.kind.as_str()
        );
        let mut statement = connection.prepare(&sql)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (hash, key_json) in rows {
            validate_blob_hash(&hash)?;
            let counts = owner_counts.entry(hash).or_default();
            counts.0 = counts
                .0
                .checked_add(1)
                .ok_or(PlatformError::Corrupt("blob_owner_count"))?;
            let owner_entry = PlanEntry {
                entity_kind: owner.kind,
                key_json,
                delete_rank: delete_spec_for(owner.kind.as_str())?.rank,
            };
            if entries.contains(&owner_entry) {
                counts.1 = counts
                    .1
                    .checked_add(1)
                    .ok_or(PlatformError::Corrupt("blob_owner_count"))?;
            }
        }
    }

    let mut retained_shared = 0_u64;
    for (hash, (total, planned)) in owner_counts {
        if planned == 0 {
            continue;
        }
        if planned == total {
            add_entry(entries, "blobs", serde_json::json!([hash]))?;
        } else {
            retained_shared = retained_shared
                .checked_add(1)
                .ok_or(PlatformError::Corrupt("retained_shared_blob_count"))?;
        }
    }
    Ok(retained_shared)
}

fn validate_blob_hash(value: &str) -> PlatformResult<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(PlatformError::Corrupt("blob_sha256"))
    }
}

fn add_prefixed_entry(
    connection: &Connection,
    entries: &mut BTreeSet<PlanEntry>,
    value: &str,
) -> PlatformResult<bool> {
    let simple = [
        ("import_scans:", "import_scans", "scan_id"),
        ("source_provenance:", "source_provenance", "provenance_id"),
        ("quarantine_records:", "quarantine_records", "quarantine_id"),
        ("mime_parts:", "mime_parts", "part_id"),
        ("derivatives:", "derivatives", "derivative_id"),
        (
            "remote_references:",
            "remote_references",
            "remote_reference_id",
        ),
        ("receipt_parse:", "receipt_parses", "parse_id"),
        ("receipt_fragment:", "receipt_fragments", "fragment_id"),
        ("receipt_run:", "receipt_extraction_runs", "run_id"),
        ("receipt_order:", "receipt_orders", "order_evidence_id"),
        ("receipt_line:", "receipt_order_lines", "order_line_id"),
        (
            "receipt_variant:",
            "receipt_variant_evidence",
            "variant_evidence_id",
        ),
        ("receipt_field:", "receipt_fields", "field_id"),
        (
            "receipt_citation:",
            "receipt_field_citations",
            "citation_id",
        ),
        (
            "receipt_review_decision:",
            "receipt_review_decisions",
            "review_decision_id",
        ),
        (
            "receipt_review_head:",
            "receipt_review_heads",
            "order_evidence_id",
        ),
        (
            "receipt_image_candidate:",
            "receipt_image_candidates",
            "candidate_id",
        ),
        (
            "receipt_image_candidate_overflow:",
            "receipt_image_candidate_overflow",
            "parse_id",
        ),
        (
            "receipt_image_approval:",
            "receipt_image_approvals",
            "approval_id",
        ),
        (
            "receipt_image_attempt:",
            "receipt_image_attempts",
            "attempt_id",
        ),
        (
            "receipt_image_attempt_outcome:",
            "receipt_image_attempt_outcomes",
            "attempt_id",
        ),
        (
            "receipt_image_materialization_intent:",
            "receipt_image_materialization_intents",
            "intent_id",
        ),
        ("receipt_remote_image:", "receipt_remote_images", "image_id"),
        ("photo_scope:", "photo_scopes", "scope_id"),
        (
            "photo_source_revision:",
            "photo_source_revisions",
            "source_revision_id",
        ),
        ("photo_analysis_run:", "photo_analysis_runs", "run_id"),
        (
            "photo_segmentation_attempt:",
            "photo_segmentation_attempts",
            "attempt_id",
        ),
        (
            "photo_segmentation_outcome:",
            "photo_segmentation_outcomes",
            "attempt_id",
        ),
        ("photo_artifact:", "photo_artifacts", "artifact_id"),
        ("photo_observation:", "photo_observations", "observation_id"),
        (
            "photo_person_detection_run:",
            "photo_person_detection_runs",
            "run_id",
        ),
        (
            "photo_person_detection_attempt:",
            "photo_person_detection_attempts",
            "detection_attempt_id",
        ),
        (
            "photo_owner_preview:",
            "photo_owner_preview_references",
            "preview_id",
        ),
        (
            "photo_owner_review:",
            "photo_owner_reviews",
            "owner_review_id",
        ),
        (
            "photo_detection_correction:",
            "photo_detection_corrections",
            "correction_id",
        ),
        (
            "photo_person_instance:",
            "photo_person_instances",
            "person_instance_id",
        ),
        (
            "photo_owner_decision:",
            "photo_owner_decisions",
            "owner_decision_id",
        ),
        (
            "photo_owner_head:",
            "photo_owner_heads",
            "source_revision_id",
        ),
        (
            "photo_owner_work:",
            "photo_owner_work_claims",
            "owner_decision_id",
        ),
        (
            "photo_observation_owner_link:",
            "photo_observation_owner_links",
            "observation_id",
        ),
        (
            "photo_review_decision:",
            "photo_review_decisions",
            "decision_id",
        ),
        ("photo_review_head:", "photo_review_heads", "observation_id"),
        ("reconciliation_case:", "reconciliation_cases", "case_id"),
        (
            "reconciliation_candidate:",
            "reconciliation_candidates",
            "candidate_id",
        ),
        (
            "reconciliation_evidence:",
            "reconciliation_candidate_evidence",
            "evidence_id",
        ),
        (
            "reconciliation_decision:",
            "reconciliation_decisions",
            "decision_id",
        ),
        (
            "reconciliation_decision_head:",
            "reconciliation_decision_heads",
            "case_id",
        ),
        (
            "gmail_provider_source:",
            "gmail_provider_sources",
            "provider_source_id",
        ),
        (
            "gmail_source_head:",
            "gmail_source_heads",
            "provider_source_id",
        ),
        ("gmail_revision:", "gmail_source_revisions", "revision_id"),
        (
            "gmail_materialization:",
            "gmail_revision_materializations",
            "revision_id",
        ),
        ("outfit:", "outfits", "outfit_id"),
        (
            "outfit_recommendation_attempt:",
            "outfit_recommendation_attempts",
            "attempt_id",
        ),
        (
            "outfit_recommendation_approval:",
            "outfit_recommendation_approvals",
            "approval_id",
        ),
        ("try_on_approval:", "try_on_approvals", "approval_id"),
        ("try_on_job:", "try_on_jobs", "job_id"),
        ("try_on_attempt:", "try_on_attempts", "attempt_id"),
        ("try_on_output:", "try_on_outputs", "output_id"),
    ];
    for (prefix, table, column) in simple {
        if let Some(id) = value.strip_prefix(prefix) {
            add_existing_simple(connection, entries, table, column, id)?;
            return Ok(true);
        }
    }
    for prefix in [
        "receipt_command_receipt:",
        "photo_command_receipt:",
        "reconciliation_command_receipt:",
        "outfit_command_receipt:",
        "outfit_recommendation_command_receipt:",
        "try_on_command_receipt:",
    ] {
        if let Some(id) = value.strip_prefix(prefix) {
            add_existing_simple(connection, entries, "command_receipts", "request_id", id)?;
            add_related_work(connection, entries, id)?;
            return Ok(true);
        }
    }
    let composite: &[(&str, &str, &[&str])] = &[
        (
            "item_evidence:",
            "item_evidence",
            &["item_id", "evidence_id"],
        ),
        (
            "receipt_image_hop:",
            "receipt_image_hops",
            &["attempt_id", "hop_ordinal"],
        ),
        (
            "photo_scope_member:",
            "photo_scope_members",
            &["scope_id", "member_ordinal"],
        ),
        (
            "photo_analysis_member_claim:",
            "photo_analysis_member_claims",
            &["run_id", "member_ordinal"],
        ),
        (
            "photo_artifact_parent:",
            "photo_artifact_parents",
            &["artifact_id", "parent_ordinal"],
        ),
        (
            "reconciliation_evidence_hash:",
            "reconciliation_evidence_input_hashes",
            &["evidence_id", "input_ordinal"],
        ),
        (
            "gmail_scope_source:",
            "gmail_scope_sources",
            &["scope_id", "provider_source_id"],
        ),
        (
            "gmail_operation_revision:",
            "gmail_operation_revisions",
            &["request_id", "revision_id"],
        ),
        (
            "outfit_member:",
            "outfit_members",
            &["outfit_id", "ordinal"],
        ),
        (
            "outfit_recommendation_proposal:",
            "outfit_recommendation_proposals",
            &["attempt_id", "ordinal"],
        ),
        (
            "outfit_recommendation_member:",
            "outfit_recommendation_members",
            &["attempt_id", "proposal_ordinal", "member_ordinal"],
        ),
        (
            "try_on_asset:",
            "try_on_assets",
            &["approval_id", "asset_ordinal"],
        ),
    ];
    for (prefix, table, columns) in composite {
        if let Some(key) = value.strip_prefix(prefix) {
            add_existing_composite(connection, entries, table, columns, key)?;
            return Ok(true);
        }
    }
    for (prefix, table) in [
        ("receipt_command_entity:", "receipt_command_entities"),
        ("photo_command_entity:", "photo_command_entities"),
        (
            "photo_owner_command_entity:",
            "photo_owner_command_entities",
        ),
        (
            "reconciliation_command_entity:",
            "reconciliation_command_entities",
        ),
    ] {
        if let Some(key) = value.strip_prefix(prefix) {
            add_existing_composite(
                connection,
                entries,
                table,
                &["request_id", "entity_kind", "entity_id"],
                key,
            )?;
            return Ok(true);
        }
    }
    if let Some(key) = value.strip_prefix("decision_entity:") {
        let mut parts = key.splitn(2, ':');
        let decision_id = parts.next().unwrap_or_default();
        let entity_id = parts.next().unwrap_or_default();
        let mut statement = connection.prepare(
            "SELECT entity_kind FROM decision_entities WHERE decision_id=?1 AND entity_id=?2",
        )?;
        for kind in statement
            .query_map(params![decision_id, entity_id], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_entry(
                entries,
                "decision_entities",
                serde_json::json!([decision_id, kind, entity_id]),
            )?;
        }
        return Ok(true);
    }
    Ok(false)
}

fn add_existing_simple(
    connection: &Connection,
    entries: &mut BTreeSet<PlanEntry>,
    table: &'static str,
    column: &str,
    value: &str,
) -> PlatformResult<()> {
    let spec = delete_spec_for(table)?;
    let sql = format!("SELECT json_array({column}) FROM {table} WHERE {column}=?1");
    if let Some(key) = connection
        .query_row(&sql, [value], |row| row.get::<_, String>(0))
        .optional()?
    {
        let delete_rank = delete_rank_for_simple_key(connection, table, value, spec.rank)?;
        entries.insert(PlanEntry {
            entity_kind: DeletionEntityKind::parse(table)?,
            key_json: key,
            delete_rank,
        });
    }
    Ok(())
}

fn delete_rank_for_simple_key(
    connection: &Connection,
    table: &str,
    value: &str,
    base_rank: i64,
) -> PlatformResult<i64> {
    let depth: i64 = match table {
        "mime_parts" => connection.query_row(
            "WITH RECURSIVE ancestors(part_id,parent_part_id,depth) AS (
               SELECT part_id,parent_part_id,0 FROM mime_parts WHERE part_id=?1
               UNION ALL
               SELECT parent.part_id,parent.parent_part_id,ancestors.depth+1
               FROM mime_parts parent
               JOIN ancestors ON parent.part_id=ancestors.parent_part_id
             )
             SELECT MAX(depth) FROM ancestors",
            [value],
            |row| row.get(0),
        )?,
        "local_sources" => connection.query_row(
            "WITH RECURSIVE ancestors(source_id,parent_source_id,depth) AS (
               SELECT source_id,parent_source_id,0 FROM local_sources WHERE source_id=?1
               UNION ALL
               SELECT parent.source_id,parent.parent_source_id,ancestors.depth+1
               FROM local_sources parent
               JOIN ancestors ON parent.source_id=ancestors.parent_source_id
             )
             SELECT MAX(depth) FROM ancestors",
            [value],
            |row| row.get(0),
        )?,
        "photo_owner_decisions" => connection.query_row(
            "WITH RECURSIVE ancestors(
                owner_decision_id,superseded_owner_decision_id,depth
             ) AS (
               SELECT owner_decision_id,superseded_owner_decision_id,0
               FROM photo_owner_decisions WHERE owner_decision_id=?1
               UNION ALL
               SELECT parent.owner_decision_id,
                      parent.superseded_owner_decision_id,
                      ancestors.depth+1
               FROM photo_owner_decisions parent
               JOIN ancestors
                 ON parent.owner_decision_id =
                    ancestors.superseded_owner_decision_id
             )
             SELECT MAX(depth) FROM ancestors",
            [value],
            |row| row.get(0),
        )?,
        _ => return Ok(base_rank),
    };
    let rank = base_rank
        .checked_sub(depth)
        .ok_or(PlatformError::Corrupt("deletion_parent_depth"))?;
    let minimum_rank = if table == "photo_owner_decisions" {
        400
    } else {
        1
    };
    if rank < minimum_rank {
        return Err(PlatformError::Corrupt("deletion_parent_depth"));
    }
    Ok(rank)
}

fn add_existing_composite(
    connection: &Connection,
    entries: &mut BTreeSet<PlanEntry>,
    table: &'static str,
    columns: &[&str],
    encoded: &str,
) -> PlatformResult<()> {
    let values = encoded.split(':').collect::<Vec<_>>();
    if values.len() != columns.len() {
        return Err(PlatformError::Corrupt("deletion_composite_key"));
    }
    let predicates = columns
        .iter()
        .enumerate()
        .map(|(index, column)| format!("{column}=?{}", index + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    let sql = format!(
        "SELECT json_array({}) FROM {table} WHERE {predicates}",
        columns.join(",")
    );
    let key = match values.len() {
        2 => connection
            .query_row(&sql, params![values[0], values[1]], |row| {
                row.get::<_, String>(0)
            })
            .optional()?,
        3 => connection
            .query_row(&sql, params![values[0], values[1], values[2]], |row| {
                row.get::<_, String>(0)
            })
            .optional()?,
        _ => return Err(PlatformError::Corrupt("deletion_composite_key")),
    };
    if let Some(key_json) = key {
        let spec = delete_spec_for(table)?;
        entries.insert(PlanEntry {
            entity_kind: DeletionEntityKind::parse(table)?,
            key_json,
            delete_rank: spec.rank,
        });
    }
    Ok(())
}

fn add_entry(
    entries: &mut BTreeSet<PlanEntry>,
    table: &'static str,
    key: serde_json::Value,
) -> PlatformResult<()> {
    let spec = delete_spec_for(table)?;
    entries.insert(PlanEntry {
        entity_kind: DeletionEntityKind::parse(table)?,
        key_json: serde_json::to_string(&key)?,
        delete_rank: spec.rank,
    });
    Ok(())
}

fn add_related_work(
    connection: &Connection,
    entries: &mut BTreeSet<PlanEntry>,
    request_id: &str,
) -> PlatformResult<()> {
    let mut checks =
        connection.prepare("SELECT check_id FROM storage_checks WHERE request_id=?1")?;
    for id in checks
        .query_map([request_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
    {
        add_existing_simple(connection, entries, "storage_checks", "check_id", &id)?;
    }
    Ok(())
}

fn expand_parent_rows(
    connection: &Connection,
    entries: &mut BTreeSet<PlanEntry>,
) -> PlatformResult<()> {
    let attempts = entries
        .iter()
        .filter(|entry| entry.entity_kind == DeletionEntityKind::OutfitRecommendationAttempts)
        .filter_map(|entry| serde_json::from_str::<Vec<String>>(&entry.key_json).ok())
        .filter_map(|keys| keys.into_iter().next())
        .collect::<Vec<_>>();
    for attempt in attempts {
        let mut members = connection.prepare(
            "SELECT attempt_id,proposal_ordinal,member_ordinal
             FROM outfit_recommendation_members WHERE attempt_id=?1",
        )?;
        for (attempt_id, proposal, member) in members
            .query_map([&attempt], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            add_entry(
                entries,
                "outfit_recommendation_members",
                serde_json::json!([attempt_id, proposal, member]),
            )?;
        }
    }
    Ok(())
}

fn delete_spec_for(table: &str) -> PlatformResult<&'static DeleteSpec> {
    DELETE_SPECS
        .iter()
        .find(|spec| spec.table == table)
        .ok_or(PlatformError::Corrupt("deletion_table_inventory"))
}

fn current_revisions(connection: &Connection) -> PlatformResult<DeletionRevisionSnapshotV1> {
    let values: (i64, i64, i64, i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT catalog_revision,evidence_generation,receipt_revision,photo_revision,
                reconciliation_revision,outfit_revision,try_on_revision,photokit_revision
         FROM revision_state WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    Ok(DeletionRevisionSnapshotV1 {
        catalog_revision: values.0 as u64,
        evidence_generation: values.1 as u64,
        receipt_revision: values.2 as u64,
        photo_revision: values.3 as u64,
        reconciliation_revision: values.4 as u64,
        outfit_revision: values.5 as u64,
        try_on_revision: values.6 as u64,
        photokit_revision: values.7 as u64,
    })
}

fn remote_retention(
    connection: &Connection,
    snapshot_token: &str,
) -> PlatformResult<Vec<DeletionRemoteRetentionV1>> {
    let mut reports = Vec::new();
    let mut recommendation_statement = connection.prepare(
        "SELECT attempt.retention_mode,attempt.retention_provenance,
                attempt.transport_started_at_ms
         FROM outfit_recommendation_attempts attempt
         WHERE attempt.transport_started_at_ms IS NOT NULL
           AND EXISTS(
             SELECT 1 FROM deletion_preview_items item
             WHERE item.snapshot_token=?1
               AND item.entity_id='outfit_recommendation_attempt:'||attempt.attempt_id
           )
         ORDER BY attempt.attempt_id",
    )?;
    let recommendation_rows = recommendation_statement
        .query_map([snapshot_token], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (mode, provenance, dispatched) in recommendation_rows {
        reports.push(DeletionRemoteRetentionV1 {
            provider: CredentialProviderV1::OpenAi,
            purpose: DeletionRemotePurposeV1::OutfitRecommendation,
            retention_mode: retention_mode(&mode)?,
            retention_provenance: provenance,
            dispatched_at: format_timestamp(dispatched)?,
            policy_expires_at: policy_expiry(&mode, dispatched)?,
            status: DeletionRemoteRetentionStatusV1::ProviderDeletionUnavailable,
        });
    }

    let mut statement = connection.prepare(
        "SELECT approval.retention_mode,approval.retention_provenance,
                CAST(json_extract(attempt.audit_json,'$.transport_started_at_ms') AS INTEGER)
         FROM try_on_attempts attempt
         JOIN try_on_jobs job ON job.job_id=attempt.job_id
         JOIN try_on_approvals approval ON approval.approval_id=job.approval_id
         WHERE json_extract(attempt.audit_json,'$.transport_started_at_ms') IS NOT NULL
           AND EXISTS(
             SELECT 1 FROM deletion_preview_items item
             WHERE item.snapshot_token=?1
               AND item.entity_id='try_on_attempt:'||attempt.attempt_id
           )
         ORDER BY attempt.attempt_id",
    )?;
    let rows = statement
        .query_map([snapshot_token], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (mode, provenance, dispatched) in rows {
        reports.push(DeletionRemoteRetentionV1 {
            provider: CredentialProviderV1::OpenAi,
            purpose: DeletionRemotePurposeV1::TryOn,
            retention_mode: retention_mode(&mode)?,
            retention_provenance: provenance,
            dispatched_at: format_timestamp(dispatched)?,
            policy_expires_at: policy_expiry(&mode, dispatched)?,
            status: DeletionRemoteRetentionStatusV1::ProviderDeletionUnavailable,
        });
    }
    Ok(reports)
}

fn retention_mode(value: &str) -> PlatformResult<OpenAiRetentionModeV1> {
    match value {
        "unknown" => Ok(OpenAiRetentionModeV1::Unknown),
        "default" => Ok(OpenAiRetentionModeV1::Default),
        "MAM" => Ok(OpenAiRetentionModeV1::Mam),
        "ZDR" => Ok(OpenAiRetentionModeV1::Zdr),
        _ => Err(PlatformError::Corrupt("deletion_retention_mode")),
    }
}

fn policy_expiry(mode: &str, dispatched: i64) -> PlatformResult<Option<String>> {
    if mode == "default" {
        Ok(Some(format_timestamp(
            dispatched
                .checked_add(30 * 24 * 60 * 60 * 1_000)
                .ok_or(PlatformError::Corrupt("deletion_retention_expiry"))?,
        )?))
    } else {
        Ok(None)
    }
}

fn store_plan_reports(
    transaction: &Transaction<'_>,
    token: &str,
    backups: &[DeletionBackupRetentionV1],
    remote: &[DeletionRemoteRetentionV1],
) -> PlatformResult<()> {
    for (ordinal, report) in backups.iter().enumerate() {
        transaction.execute(
            "INSERT INTO deletion_plan_backup_retention(
                snapshot_token,ordinal,backup_id,reason,expires_at_ms)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                token,
                ordinal as i64,
                report.backup_id.to_string(),
                backup_reason_db(report.reason),
                timestamp_ms(&report.expires_at)?
            ],
        )?;
    }
    for (ordinal, report) in remote.iter().enumerate() {
        transaction.execute(
            "INSERT INTO deletion_plan_remote_retention(
                snapshot_token,ordinal,provider,purpose,retention_mode,
                retention_provenance,dispatched_at_ms,policy_expires_at_ms,status)
             VALUES(?1,?2,'open_ai',?3,?4,?5,?6,?7,'provider_deletion_unavailable')",
            params![
                token,
                ordinal as i64,
                remote_purpose_db(report.purpose),
                retention_mode_db(report.retention_mode),
                report.retention_provenance,
                timestamp_ms(&report.dispatched_at)?,
                report
                    .policy_expires_at
                    .as_deref()
                    .map(timestamp_ms)
                    .transpose()?,
            ],
        )?;
    }
    Ok(())
}

#[derive(Debug)]
struct FrozenPlan {
    target_kind: DeletionTargetKindV1,
    target_id: String,
    revisions: DeletionRevisionSnapshotV1,
    key_cleanup_actions: Vec<KeyCleanupAction>,
    plan_sha256: String,
    entries: BTreeSet<PlanEntry>,
    unique_blobs: BTreeMap<String, u64>,
    retained_shared_blob_count: u64,
}

fn rematerialize_live_plan(
    transaction: &Transaction<'_>,
    target_kind: DeletionTargetKindV1,
    target_id: &str,
    revisions: &DeletionRevisionSnapshotV1,
    now_ms: i64,
) -> PlatformResult<(CompiledPlan, Vec<DeletionRemoteRetentionV1>)> {
    let token = format!("live-{}", Uuid::new_v4().simple());
    transaction.execute(
        "INSERT INTO deletion_previews(
            snapshot_token,target_kind,target_id,catalog_revision,evidence_generation,
            photo_revision,reconciliation_revision,outfit_revision,try_on_revision,
            photokit_revision,created_at_ms
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            token,
            target_kind_db(target_kind),
            target_id,
            revisions.catalog_revision as i64,
            revisions.evidence_generation as i64,
            revisions.photo_revision as i64,
            revisions.reconciliation_revision as i64,
            revisions.outfit_revision as i64,
            revisions.try_on_revision as i64,
            revisions.photokit_revision as i64,
            now_ms,
        ],
    )?;
    crate::catalog_repository::materialize_deletion_rows(
        transaction,
        &token,
        target_kind,
        target_id,
    )?;
    let compiled = compile_entries(transaction, &token)?;
    let remote = remote_retention(transaction, &token)?;
    transaction.execute(
        "DELETE FROM deletion_preview_items WHERE snapshot_token=?1",
        [&token],
    )?;
    let removed = transaction.execute(
        "DELETE FROM deletion_previews WHERE snapshot_token=?1",
        [&token],
    )?;
    if removed != 1 {
        return Err(PlatformError::Corrupt("live_deletion_preview_cleanup"));
    }
    Ok((compiled, remote))
}

fn load_and_compare_live_plan(
    transaction: &Transaction<'_>,
    paths: &PrivateAppPaths,
    maintenance: &MaintenanceGuard,
    request: &ExecuteDeletionV1Request,
    epoch: &str,
    now_ms: i64,
) -> PlatformResult<FrozenPlan> {
    let token = request.preview_snapshot_token.as_str();
    let stored: (String, String, String, i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT target_kind,target_id,plan_sha256,expires_at_ms,
                    unique_blob_count,unique_blob_bytes,retained_shared_blob_count
             FROM deletion_plans WHERE snapshot_token=?1 AND epoch=?2",
            params![token, epoch],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::Conflict("snapshot_expired"))?;
    if stored.2 != request.plan_sha256.as_str() || stored.3 < now_ms {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }

    let target_kind = parse_target_kind(&stored.0)?;
    require_live_target(transaction, target_kind, &stored.1)?;
    let revisions = current_revisions(transaction)?;
    if revisions != request.expected_revisions {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }

    let stored_entries = load_plan_entries(transaction, token)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let (live, remote_retention) =
        rematerialize_live_plan(transaction, target_kind, &stored.1, &revisions, now_ms)?;
    if live.entries != stored_entries {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }
    let stored_key_cleanup = load_plan_key_cleanup_actions(transaction, token)?;
    if live.key_cleanup_actions != stored_key_cleanup {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }

    let unique_blobs = live
        .entries
        .iter()
        .filter(|entry| entry.entity_kind == DeletionEntityKind::Blobs)
        .map(|entry| {
            let hash = plan_blob_hash(entry)?;
            let bytes: i64 = transaction
                .query_row(
                    "SELECT byte_length FROM blobs WHERE sha256=?1",
                    [&hash],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(PlatformError::Conflict("snapshot_expired"))?;
            Ok((
                hash,
                u64::try_from(bytes).map_err(|_| PlatformError::Corrupt("deletion_blob_bytes"))?,
            ))
        })
        .collect::<PlatformResult<BTreeMap<_, _>>>()?;
    let retained_shared_blob_count = live.retained_shared_blob_count;
    let unique_blob_count =
        i64::try_from(unique_blobs.len()).map_err(|_| PlatformError::Corrupt("blob_count"))?;
    let unique_blob_bytes = unique_blobs.values().try_fold(0_i64, |total, bytes| {
        total
            .checked_add(
                i64::try_from(*bytes).map_err(|_| PlatformError::Corrupt("deletion_blob_bytes"))?,
            )
            .ok_or(PlatformError::Corrupt("deletion_blob_bytes"))
    })?;
    if unique_blob_count != stored.4
        || unique_blob_bytes != stored.5
        || retained_shared_blob_count != stored.6 as u64
    {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }

    let backup_retention = BackupRepository::new(paths).deletion_retention_locked(
        target_kind,
        &stored.1,
        &unique_blobs.keys().cloned().collect(),
        maintenance,
    )?;
    if backup_retention != load_plan_backup_reports(transaction, token)?
        || remote_retention != load_plan_remote_reports(transaction, token)?
    {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&CanonicalPlan {
            target_kind: target_kind_db(target_kind),
            target_id: &stored.1,
            revisions: &revisions,
            entries: &live.entries,
            key_cleanup_actions: &live.key_cleanup_actions,
            backup_retention: &backup_retention,
            remote_retention: &remote_retention,
        })?)
    );
    if digest != stored.2 || digest != request.plan_sha256.as_str() {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }
    Ok(FrozenPlan {
        target_kind,
        target_id: stored.1,
        revisions,
        key_cleanup_actions: live.key_cleanup_actions,
        plan_sha256: digest,
        entries: live.entries,
        unique_blobs,
        retained_shared_blob_count,
    })
}

fn plan_blob_hash(entry: &PlanEntry) -> PlatformResult<String> {
    let values: Vec<String> = serde_json::from_str(&entry.key_json)?;
    if values.len() != 1 {
        return Err(PlatformError::Corrupt("deletion_blob_key"));
    }
    Ok(values[0].clone())
}

fn require_live_target(
    connection: &Connection,
    target_kind: DeletionTargetKindV1,
    target_id: &str,
) -> PlatformResult<()> {
    let sql = match target_kind {
        DeletionTargetKindV1::ImportRoot => "SELECT 1 FROM import_roots WHERE root_id=?1",
        DeletionTargetKindV1::Source => "SELECT 1 FROM local_sources WHERE source_id=?1",
        DeletionTargetKindV1::Item => "SELECT 1 FROM catalog_items WHERE item_id=?1",
        DeletionTargetKindV1::PhotoKitEnrollment => {
            "SELECT 1 FROM photokit_enrollments WHERE enrollment_epoch=?1"
        }
        DeletionTargetKindV1::PhotoKitAsset => "SELECT 1 FROM photokit_assets WHERE asset_id=?1",
    };
    if connection
        .query_row(sql, [target_id], |_| Ok(()))
        .optional()?
        .is_none()
    {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }
    Ok(())
}

fn prepare_photokit_deletion(
    transaction: &Transaction<'_>,
    target_kind: DeletionTargetKindV1,
    target_id: &str,
    key_cleanup_actions: &[KeyCleanupAction],
    run_id: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    match target_kind {
        DeletionTargetKindV1::PhotoKitEnrollment => {
            let [action] = key_cleanup_actions else {
                return Err(PlatformError::Corrupt("photokit_key_cleanup_plan_action"));
            };
            if action.enrollment_epoch != target_id {
                return Err(PlatformError::Corrupt("photokit_key_cleanup_plan_action"));
            }
            transaction.execute(
                "UPDATE photokit_connector_state
                 SET state='unconfigured',active_enrollment_epoch=NULL,
                     active_membership_generation=NULL,observed_count=0,
                     available_count=0,unavailable_count=0,last_complete_at_ms=NULL,
                     updated_at_ms=?2
                 WHERE singleton=1 AND active_enrollment_epoch=?1",
                params![target_id, now_ms],
            )?;
            transaction.execute(
                "INSERT INTO photokit_key_cleanup_intents(
                    intent_id,deletion_run_id,enrollment_epoch,key_reference,
                    reason,state,created_at_ms
                 ) VALUES(?1,?2,?3,?4,'final_key_owner','pending',?5)",
                params![
                    Uuid::new_v4().hyphenated().to_string(),
                    run_id,
                    target_id,
                    action.key_reference,
                    now_ms
                ],
            )?;
        }
        DeletionTargetKindV1::PhotoKitAsset => {
            if !key_cleanup_actions.is_empty() {
                return Err(PlatformError::Corrupt("photokit_key_cleanup_plan_action"));
            }
            let enrollment_epoch: String = transaction.query_row(
                "SELECT enrollment_epoch FROM photokit_assets WHERE asset_id=?1",
                [target_id],
                |row| row.get(0),
            )?;
            let normalized = transaction.execute(
                "UPDATE photokit_connector_state
                 SET state='ready',active_membership_generation=NULL,
                     observed_count=0,available_count=0,unavailable_count=0,
                     last_complete_at_ms=NULL,updated_at_ms=?2
                 WHERE singleton=1 AND active_enrollment_epoch=?1",
                params![enrollment_epoch, now_ms],
            )?;
            if normalized == 1 {
                let changed = transaction.execute(
                    "UPDATE photokit_enrollments
                     SET active_membership_generation=NULL,
                         operation_fence=operation_fence+1
                     WHERE enrollment_epoch=?1 AND state='active'
                       AND operation_fence<9007199254740990",
                    [&enrollment_epoch],
                )?;
                if changed != 1 {
                    return Err(PlatformError::Corrupt("photokit_deletion_fence_transition"));
                }
            }
        }
        DeletionTargetKindV1::ImportRoot
        | DeletionTargetKindV1::Source
        | DeletionTargetKindV1::Item => {
            if !key_cleanup_actions.is_empty() {
                return Err(PlatformError::Corrupt("photokit_key_cleanup_plan_action"));
            }
        }
    }
    Ok(())
}

impl DeletionPort for Database {
    fn execute_deletion(
        &self,
        request: &ExecuteDeletionV1Request,
    ) -> CatalogPortResult<ExecuteDeletionV1Response> {
        self.execute_deletion_impl(request)
            .map_err(deletion_port_error)
    }
}

impl Database {
    fn execute_deletion_impl(
        &self,
        request: &ExecuteDeletionV1Request,
    ) -> PlatformResult<ExecuteDeletionV1Response> {
        self.execute_deletion_impl_with_keys(request, &MacOsPhotoKitKeychain)
    }

    fn execute_deletion_impl_with_keys<K: PhotoKitKeyPort>(
        &self,
        request: &ExecuteDeletionV1Request,
        keys: &K,
    ) -> PlatformResult<ExecuteDeletionV1Response> {
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let maintenance = lock_maintenance()?;
        let now_ms = unix_now_ms()?;
        let envelope_hash = format!("{:x}", Sha256::digest(serde_json::to_vec(request)?));
        if let Some(response) = self.replay_deletion(request, &envelope_hash)? {
            return Ok(response);
        }
        if let Some(run_id) = self.pending_deletion_run(request, &envelope_hash)? {
            self.drain_deletion_run_with_keys(
                &run_id,
                &maintenance,
                DeletionDrainMode::Online,
                keys,
            )?;
            let mut response =
                self.complete_deletion(&run_id, unix_now_ms()?, DeletionDrainMode::Online)?;
            response.replay_status = ReplayStatusV1::Replayed;
            return Ok(response);
        }
        let mut connection = self.connection()?;
        // Lock order ends in SQLite BEGIN IMMEDIATE after coordinator and maintenance gates.
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch: String = transaction.query_row(
            "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let plan = load_and_compare_live_plan(
            &transaction,
            &self.paths,
            &maintenance,
            request,
            &epoch,
            now_ms,
        )?;
        let run_id = DeletionRunId::new_v4();
        let run_text = run_id.to_string();
        let deadline = now_ms
            .checked_add(EXECUTION_DEADLINE_MS)
            .ok_or(PlatformError::InvalidInput("deletion_deadline"))?;
        let record_count = plan
            .entries
            .iter()
            .filter(|entry| entry.entity_kind != DeletionEntityKind::Blobs)
            .count();
        let unique_blob_bytes = plan.unique_blobs.values().try_fold(0_u64, |total, bytes| {
            total
                .checked_add(*bytes)
                .ok_or(PlatformError::Corrupt("deletion_blob_bytes"))
        })?;
        let request_json = serde_json::to_string(request)?;
        transaction.execute(
            "INSERT INTO deletion_runs(
                run_id,epoch,snapshot_token,request_id,request_json,envelope_hash,plan_sha256,state,
                accepted_at_ms,deadline_at_ms,deleted_record_count,deleted_blob_count,
                deleted_blob_bytes,retained_shared_blob_count,photokit_revision)
             VALUES(
                ?1,?2,?3,?4,?5,?6,?7,'in_progress',?8,?9,?10,?11,?12,?13,?14
             )",
            params![
                run_text,
                epoch,
                request.preview_snapshot_token.as_str(),
                request.request_id.to_string(),
                request_json,
                envelope_hash,
                plan.plan_sha256,
                now_ms,
                deadline,
                record_count as i64,
                plan.unique_blobs.len() as i64,
                unique_blob_bytes as i64,
                plan.retained_shared_blob_count as i64,
                plan.revisions.photokit_revision as i64,
            ],
        )?;
        transaction.execute(
            "INSERT INTO deletion_run_backup_retention
             SELECT ?1,ordinal,backup_id,reason,expires_at_ms
             FROM deletion_plan_backup_retention WHERE snapshot_token=?2",
            params![run_text, request.preview_snapshot_token.as_str()],
        )?;
        transaction.execute(
            "INSERT INTO deletion_run_remote_retention
             SELECT ?1,ordinal,provider,purpose,retention_mode,retention_provenance,
                    dispatched_at_ms,policy_expires_at_ms,status
             FROM deletion_plan_remote_retention WHERE snapshot_token=?2",
            params![run_text, request.preview_snapshot_token.as_str()],
        )?;
        transaction.execute(
            "INSERT INTO deletion_run_blobs(run_id,epoch,sha256,byte_length)
             SELECT ?1,?2,json_extract(entry.key_json,'$[0]'),blob.byte_length
             FROM deletion_plan_entries entry
             JOIN blobs blob ON blob.sha256=json_extract(entry.key_json,'$[0]')
             WHERE entry.snapshot_token=?3 AND entry.entity_kind='blobs'",
            params![run_text, epoch, request.preview_snapshot_token.as_str()],
        )?;
        transaction.execute(
            "INSERT INTO deletion_execution_authority(singleton,epoch,run_id,snapshot_token)
             VALUES(1,?1,?2,?3)",
            params![epoch, run_text, request.preview_snapshot_token.as_str()],
        )?;
        prepare_photokit_deletion(
            &transaction,
            plan.target_kind,
            &plan.target_id,
            &plan.key_cleanup_actions,
            &run_text,
            now_ms,
        )?;
        for entry in &plan.entries {
            let spec = delete_spec_for(entry.entity_kind.as_str())?;
            let changed = transaction.execute(spec.sql, [&entry.key_json])?;
            if changed != 1 {
                return Err(PlatformError::Conflict("snapshot_expired"));
            }
        }
        transaction.execute(
            "UPDATE revision_state SET
               catalog_revision=catalog_revision+1,
               evidence_generation=evidence_generation+1,
               receipt_revision=receipt_revision+1,
               photo_revision=photo_revision+1,
               owner_revision=owner_revision+1,
               reconciliation_revision=reconciliation_revision+1,
               outfit_revision=outfit_revision+1,
               try_on_revision=try_on_revision+1,
               photokit_revision=photokit_revision+1
             WHERE singleton=1",
            [],
        )?;
        transaction.execute(
            "DELETE FROM deletion_execution_authority WHERE singleton=1",
            [],
        )?;
        let foreign_key_errors: i64 =
            transaction.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        if foreign_key_errors != 0 {
            return Err(PlatformError::Corrupt("deletion_foreign_key_check"));
        }
        transaction.commit()?;
        self.drain_deletion_run_with_keys(
            &run_text,
            &maintenance,
            DeletionDrainMode::Online,
            keys,
        )?;
        let completed_at_ms = unix_now_ms()?;
        self.complete_deletion(&run_text, completed_at_ms, DeletionDrainMode::Online)
    }

    fn replay_deletion(
        &self,
        request: &ExecuteDeletionV1Request,
        envelope_hash: &str,
    ) -> PlatformResult<Option<ExecuteDeletionV1Response>> {
        let connection = self.connection()?;
        let epoch: String = connection.query_row(
            "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let row = connection
            .query_row(
                "SELECT envelope_hash,response_json FROM deletion_execution_receipts
                 WHERE epoch=?1 AND request_id=?2",
                params![epoch, request.request_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((stored, json)) = row else {
            return Ok(None);
        };
        if stored != envelope_hash {
            return Err(PlatformError::Conflict("command_envelope_changed"));
        }
        let mut response: ExecuteDeletionV1Response = serde_json::from_str(&json)?;
        response.replay_status = ReplayStatusV1::Replayed;
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("deletion_receipt_contract"))?;
        Ok(Some(response))
    }

    fn pending_deletion_run(
        &self,
        request: &ExecuteDeletionV1Request,
        envelope_hash: &str,
    ) -> PlatformResult<Option<String>> {
        let connection = self.connection()?;
        let epoch: String = connection.query_row(
            "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let row = connection
            .query_row(
                "SELECT run_id,envelope_hash,state FROM deletion_runs
                 WHERE epoch=?1 AND request_id=?2",
                params![epoch, request.request_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((run_id, stored_hash, state)) = row else {
            return Ok(None);
        };
        if stored_hash != envelope_hash {
            return Err(PlatformError::Conflict("command_envelope_changed"));
        }
        match state.as_str() {
            "in_progress" | "needs_attention" => Ok(Some(run_id)),
            "complete" => Err(PlatformError::Corrupt("deletion_receipt_missing")),
            _ => Err(PlatformError::Corrupt("deletion_run_state")),
        }
    }

    fn drain_deletion_run(
        &self,
        run_id: &str,
        maintenance: &MaintenanceGuard,
        mode: DeletionDrainMode,
    ) -> PlatformResult<()> {
        self.drain_deletion_run_with_keys(run_id, maintenance, mode, &MacOsPhotoKitKeychain)
    }

    fn drain_deletion_run_with_keys<K: PhotoKitKeyPort>(
        &self,
        run_id: &str,
        _maintenance: &MaintenanceGuard,
        mode: DeletionDrainMode,
        keys: &K,
    ) -> PlatformResult<()> {
        let deadline_at_ms: i64 = self.connection()?.query_row(
            "SELECT deadline_at_ms FROM deletion_runs
             WHERE run_id=?1 AND state IN ('in_progress','needs_attention')",
            [run_id],
            |row| row.get(0),
        )?;
        let mut transient_retries = 0_u8;
        loop {
            if mode == DeletionDrainMode::Online && unix_now_ms()? > deadline_at_ms {
                self.mark_deletion_needs_attention(run_id)?;
                return Err(PlatformError::Conflict("deletion_deadline_exceeded"));
            }
            match self.drain_deletion_run_inner(run_id, keys) {
                Ok(()) => {
                    if mode == DeletionDrainMode::Online && unix_now_ms()? > deadline_at_ms {
                        self.mark_deletion_needs_attention(run_id)?;
                        return Err(PlatformError::Conflict("deletion_deadline_exceeded"));
                    }
                    return Ok(());
                }
                Err(error)
                    if is_transient_deletion_error(&error)
                        && transient_retries < TRANSIENT_DRAIN_RETRY_LIMIT =>
                {
                    transient_retries += 1;
                    thread::sleep(TRANSIENT_DRAIN_RETRY_DELAY);
                }
                Err(error) => {
                    self.mark_deletion_needs_attention(run_id)?;
                    return Err(error);
                }
            }
        }
    }

    fn mark_deletion_needs_attention(&self, run_id: &str) -> PlatformResult<()> {
        self.connection()?.execute(
            "UPDATE deletion_runs SET state='needs_attention'
             WHERE run_id=?1 AND state IN ('in_progress','needs_attention')",
            [run_id],
        )?;
        Ok(())
    }

    fn drain_deletion_run_inner<K: PhotoKitKeyPort>(
        &self,
        run_id: &str,
        keys: &K,
    ) -> PlatformResult<()> {
        if Uuid::parse_str(run_id)
            .map(|value| value.to_string())
            .map_err(|_| PlatformError::Corrupt("deletion_run_id"))?
            != run_id
        {
            return Err(PlatformError::Corrupt("deletion_run_id"));
        }
        let connection = self.connection()?;
        #[cfg(test)]
        let test_request_id: String = connection.query_row(
            "SELECT request_id FROM deletion_runs WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )?;
        #[cfg(test)]
        if consume_test_transient_failure(&test_request_id)? {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock).into());
        }
        let mut statement = connection.prepare(
            "SELECT sha256,byte_length FROM deletion_run_blobs
             WHERE run_id=?1 ORDER BY sha256",
        )?;
        let blobs = statement
            .query_map([run_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        drop(connection);
        let run_directory = self.paths.deletion_trash.join(run_id);
        create_private_directory(&run_directory)?;
        let expected = blobs
            .iter()
            .map(|(hash, length)| {
                validate_blob_hash(hash)?;
                Ok((hash.clone(), *length))
            })
            .collect::<PlatformResult<BTreeMap<_, _>>>()?;
        validate_run_trash_entries(&run_directory, &expected)?;
        for (hash, length) in blobs {
            let length = u64::try_from(length)
                .map_err(|_| PlatformError::Corrupt("deletion_blob_length"))?;
            let active = crate::BlobStore::new(&self.paths).path_for_hash(&hash)?;
            let trash = run_directory.join(&hash);
            #[cfg(test)]
            drain_blob_with_post_rename(&active, &trash, &hash, length, || {
                if consume_test_interrupt_after_blob(&test_request_id)? {
                    Err(PlatformError::Conflict("test_deletion_interruption"))
                } else {
                    Ok(())
                }
            })?;
            #[cfg(not(test))]
            drain_blob(&active, &trash, &hash, length)?;
            let changed = self.connection()?.execute(
                "DELETE FROM deletion_run_blobs WHERE run_id=?1 AND sha256=?2",
                params![run_id, hash],
            )?;
            if changed != 1 {
                return Err(PlatformError::Corrupt("deletion_manifest_transition"));
            }
        }
        match fs::symlink_metadata(&run_directory) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.mode() & 0o777 == 0o700 =>
            {
                fs::remove_dir(&run_directory)?;
                sync_directory(&self.paths.deletion_trash)?;
            }
            Ok(_) => return Err(PlatformError::Corrupt("deletion_trash_identity")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.drain_photokit_key_cleanup(run_id, keys)?;
        Ok(())
    }

    fn drain_photokit_key_cleanup<K: PhotoKitKeyPort>(
        &self,
        run_id: &str,
        keys: &K,
    ) -> PlatformResult<()> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT intent_id,key_reference
             FROM photokit_key_cleanup_intents
             WHERE deletion_run_id=?1 AND state='pending'
             ORDER BY created_at_ms,intent_id",
        )?;
        let intents = statement
            .query_map([run_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        drop(connection);
        for (intent_id, key_reference) in intents {
            let now_ms = unix_now_ms()?;
            match keys.delete_root_key(&key_reference) {
                Ok(()) | Err(PhotoKitKeyError::NotFound) => {
                    let changed = self.connection()?.execute(
                        "UPDATE photokit_key_cleanup_intents
                         SET state='complete',failure_code=NULL,last_attempt_at_ms=?2,
                             completed_at_ms=?2
                         WHERE intent_id=?1 AND state='pending'",
                        params![intent_id, now_ms],
                    )?;
                    if changed != 1 {
                        return Err(PlatformError::Corrupt("photokit_key_cleanup_transition"));
                    }
                }
                Err(error) => {
                    let failure_code = match error {
                        PhotoKitKeyError::Locked => "locked",
                        PhotoKitKeyError::Unavailable => "unavailable",
                        PhotoKitKeyError::Integrity | PhotoKitKeyError::Internal => "internal",
                        PhotoKitKeyError::NotFound => unreachable!(),
                    };
                    self.connection()?.execute(
                        "UPDATE photokit_key_cleanup_intents
                         SET failure_code=?2,last_attempt_at_ms=?3
                         WHERE intent_id=?1 AND state='pending'",
                        params![intent_id, failure_code, now_ms],
                    )?;
                    return Err(PlatformError::Conflict("photokit_key_cleanup_pending"));
                }
            }
        }
        Ok(())
    }

    fn complete_deletion(
        &self,
        run_id: &str,
        completed_at_ms: i64,
        mode: DeletionDrainMode,
    ) -> PlatformResult<ExecuteDeletionV1Response> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run: (String, String, String, String, i64) = transaction
            .query_row(
                "SELECT snapshot_token,request_id,request_json,envelope_hash,deadline_at_ms
                 FROM deletion_runs
                 WHERE run_id=?1 AND state IN ('in_progress','needs_attention')",
                [run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::Conflict("deletion_run_not_pending"))?;
        if mode == DeletionDrainMode::Online && completed_at_ms > run.4 {
            transaction.execute(
                "UPDATE deletion_runs SET state='needs_attention'
                 WHERE run_id=?1 AND state IN ('in_progress','needs_attention')",
                [run_id],
            )?;
            transaction.commit()?;
            return Err(PlatformError::Conflict("deletion_deadline_exceeded"));
        }
        let pending: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM deletion_run_blobs WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )?;
        if pending != 0 {
            return Err(PlatformError::Conflict("deletion_manifest_pending"));
        }
        let pending_key_cleanup: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM photokit_key_cleanup_intents
             WHERE deletion_run_id=?1 AND state='pending'",
            [run_id],
            |row| row.get(0),
        )?;
        if pending_key_cleanup != 0 {
            return Err(PlatformError::Conflict("photokit_key_cleanup_pending"));
        }
        let request: ExecuteDeletionV1Request = serde_json::from_str(&run.2)?;
        if request.request_id.to_string() != run.1
            || format!("{:x}", Sha256::digest(run.2.as_bytes())) != run.3
        {
            return Err(PlatformError::Corrupt("deletion_run_envelope"));
        }
        let mut response = load_run_response(&transaction, &request, run_id, completed_at_ms)?;
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("deletion_receipt_contract"))?;
        let response_json = serde_json::to_string(&response)?;
        let changed = transaction.execute(
            "UPDATE deletion_runs SET state='complete',completed_at_ms=?2,snapshot_token=NULL
             WHERE run_id=?1 AND state IN ('in_progress','needs_attention')
               AND NOT EXISTS(SELECT 1 FROM deletion_run_blobs WHERE run_id=?1)",
            params![run_id, completed_at_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::Corrupt("deletion_run_transition"));
        }
        let epoch: String = transaction.query_row(
            "SELECT epoch FROM deletion_runs WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )?;
        let receipt_inserted = transaction.execute(
            "INSERT INTO deletion_execution_receipts(
                epoch,request_id,envelope_hash,run_id,response_json,completed_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                epoch,
                request.request_id.to_string(),
                run.3,
                run_id,
                response_json,
                completed_at_ms
            ],
        )?;
        if receipt_inserted != 1 {
            return Err(PlatformError::Corrupt("deletion_receipt_transition"));
        }
        transaction.execute(
            "DELETE FROM deletion_execution_authority
             WHERE run_id=?1 AND snapshot_token=?2",
            params![run_id, run.0],
        )?;
        transaction.execute(
            "DELETE FROM deletion_plan_entries WHERE snapshot_token=?1",
            [&run.0],
        )?;
        transaction.execute(
            "DELETE FROM deletion_plan_photokit_key_cleanup WHERE snapshot_token=?1",
            [&run.0],
        )?;
        transaction.execute(
            "DELETE FROM deletion_plan_backup_retention WHERE snapshot_token=?1",
            [&run.0],
        )?;
        transaction.execute(
            "DELETE FROM deletion_plan_remote_retention WHERE snapshot_token=?1",
            [&run.0],
        )?;
        transaction.execute(
            "DELETE FROM deletion_preview_items WHERE snapshot_token=?1",
            [&run.0],
        )?;
        transaction.execute(
            "DELETE FROM deletion_previews WHERE snapshot_token=?1",
            [&run.0],
        )?;
        let purged = transaction.execute(
            "DELETE FROM deletion_plans WHERE snapshot_token=?1",
            [&run.0],
        )?;
        if purged != 1 {
            return Err(PlatformError::Corrupt("deletion_plan_purge"));
        }
        transaction.commit()?;
        response.replay_status = ReplayStatusV1::Created;
        Ok(response)
    }

    pub(crate) fn deletion_health(&self, now_ms: i64) -> PlatformResult<DeletionHealthV1> {
        let connection = self.connection()?;
        let (in_progress, overdue, needs_attention, deadline): (i64, i64, i64, Option<i64>) =
            connection.query_row(
                "SELECT
                   SUM(CASE WHEN state='in_progress' AND deadline_at_ms>=?1 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN state='in_progress' AND deadline_at_ms<?1 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN state='needs_attention' THEN 1 ELSE 0 END),
                   MIN(CASE WHEN state<>'complete' THEN deadline_at_ms END)
                 FROM deletion_runs",
                [now_ms],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                        row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                        row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                        row.get(3)?,
                    ))
                },
            )?;
        let status = if needs_attention > 0 {
            DeletionHealthStatusV1::NeedsAttention
        } else if overdue > 0 {
            DeletionHealthStatusV1::Overdue
        } else if in_progress > 0 {
            DeletionHealthStatusV1::InProgress
        } else {
            DeletionHealthStatusV1::None
        };
        Ok(DeletionHealthV1 {
            status,
            deadline_at: deadline.map(format_timestamp).transpose()?,
            counts: DeletionHealthCountsV1 {
                in_progress: in_progress as u32,
                overdue: overdue as u32,
                needs_attention: needs_attention as u32,
            },
        })
    }

    pub(crate) fn recover_deletions(&self, _now_ms: i64) -> PlatformResult<()> {
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let maintenance = lock_maintenance()?;
        self.recover_deletions_locked(&maintenance)
    }

    pub(crate) fn recover_deletions_before_restore(
        paths: &PrivateAppPaths,
        maintenance: &MaintenanceGuard,
    ) -> PlatformResult<()> {
        match fs::symlink_metadata(&paths.database) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(PlatformError::Corrupt("database_file_identity")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return require_empty_deletion_trash(paths)
            }
            Err(error) => return Err(error.into()),
        }
        let database = Self {
            paths: paths.clone(),
        };
        let connection = database.connection()?;
        let has_deletion_schema: bool = connection.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM sqlite_schema WHERE type='table' AND name='deletion_runs'
             )",
            [],
            |row| row.get(0),
        )?;
        drop(connection);
        if has_deletion_schema {
            database.recover_deletions_locked(maintenance)?;
        }
        require_empty_deletion_trash(paths)
    }

    fn recover_deletions_locked(&self, maintenance: &MaintenanceGuard) -> PlatformResult<()> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT run_id FROM deletion_runs WHERE state IN ('in_progress','needs_attention')
             ORDER BY accepted_at_ms,run_id",
        )?;
        let runs = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        drop(connection);
        validate_deletion_trash_runs(&self.paths, &runs)?;
        for run_id in runs {
            self.drain_deletion_run(&run_id, maintenance, DeletionDrainMode::Recovery)?;
            self.complete_deletion(&run_id, unix_now_ms()?, DeletionDrainMode::Recovery)?;
        }
        let remaining: i64 = self.connection()?.query_row(
            "SELECT COUNT(*) FROM deletion_runs
             WHERE state IN ('in_progress','needs_attention')",
            [],
            |row| row.get(0),
        )?;
        if remaining != 0 {
            return Err(PlatformError::Corrupt("deletion_recovery_incomplete"));
        }
        Ok(())
    }
}

fn is_transient_deletion_error(error: &PlatformError) -> bool {
    matches!(
        error,
        PlatformError::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
            )
    )
}

#[cfg(test)]
fn set_test_drain_fault(request_id: &str, fault: TestDrainFault) {
    TEST_DRAIN_FAULTS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap()
        .insert(request_id.to_owned(), fault);
}

#[cfg(test)]
fn consume_test_transient_failure(request_id: &str) -> PlatformResult<bool> {
    let mut faults = TEST_DRAIN_FAULTS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| PlatformError::Corrupt("deletion_test_fault_lock"))?;
    let Some(fault) = faults.get_mut(request_id) else {
        return Ok(false);
    };
    if fault.transient_failures == 0 {
        return Ok(false);
    }
    fault.transient_failures -= 1;
    Ok(true)
}

#[cfg(test)]
fn consume_test_interrupt_after_blob(request_id: &str) -> PlatformResult<bool> {
    let mut faults = TEST_DRAIN_FAULTS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| PlatformError::Corrupt("deletion_test_fault_lock"))?;
    let Some(fault) = faults.get_mut(request_id) else {
        return Ok(false);
    };
    if !fault.interrupt_after_blob {
        if fault.transient_failures == 0 {
            faults.remove(request_id);
        }
        return Ok(false);
    }
    fault.interrupt_after_blob = false;
    if fault.transient_failures == 0 {
        faults.remove(request_id);
    }
    Ok(true)
}

fn require_empty_deletion_trash(paths: &PrivateAppPaths) -> PlatformResult<()> {
    let metadata = fs::symlink_metadata(&paths.deletion_trash)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(PlatformError::Corrupt("deletion_trash_identity"));
    }
    let mut entries = fs::read_dir(&paths.deletion_trash)?;
    if entries.next().transpose()?.is_some() {
        return Err(PlatformError::Corrupt("deletion_trash_residual"));
    }
    Ok(())
}

fn validate_deletion_trash_runs(
    paths: &PrivateAppPaths,
    pending_runs: &[String],
) -> PlatformResult<()> {
    let expected = pending_runs.iter().cloned().collect::<BTreeSet<_>>();
    for entry in fs::read_dir(&paths.deletion_trash)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PlatformError::Corrupt("deletion_trash_entry"))?;
        if !expected.contains(&name) {
            return Err(PlatformError::Corrupt("deletion_trash_residual"));
        }
    }
    Ok(())
}

fn validate_run_trash_entries(
    run_directory: &Path,
    expected: &BTreeMap<String, i64>,
) -> PlatformResult<()> {
    for entry in fs::read_dir(run_directory)? {
        let entry = entry?;
        let hash = entry
            .file_name()
            .into_string()
            .map_err(|_| PlatformError::Corrupt("deletion_trash_entry"))?;
        let length = expected
            .get(&hash)
            .copied()
            .ok_or(PlatformError::Corrupt("deletion_trash_residual"))?;
        let length =
            u64::try_from(length).map_err(|_| PlatformError::Corrupt("deletion_blob_length"))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        validate_deletion_file_metadata(&metadata, length, "deletion_trash_identity")?;
    }
    Ok(())
}

fn load_plan_entries(connection: &Connection, token: &str) -> PlatformResult<Vec<PlanEntry>> {
    let mut statement = connection.prepare(
        "SELECT entity_kind,key_json,delete_rank FROM deletion_plan_entries
         WHERE snapshot_token=?1 ORDER BY delete_rank,entity_kind,key_json",
    )?;
    let rows = statement
        .query_map([token], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(kind, key_json, delete_rank)| {
            let entity_kind = DeletionEntityKind::parse(&kind)?;
            let spec = delete_spec_for(&kind)?;
            let expected_rank = if matches!(
                entity_kind,
                DeletionEntityKind::MimeParts
                    | DeletionEntityKind::LocalSources
                    | DeletionEntityKind::PhotoOwnerDecisions
            ) {
                let key = serde_json::from_str::<Vec<String>>(&key_json)?;
                if key.len() != 1 {
                    return Err(PlatformError::Corrupt("deletion_plan_key"));
                }
                delete_rank_for_simple_key(connection, &kind, &key[0], spec.rank)?
            } else {
                spec.rank
            };
            if delete_rank != expected_rank {
                return Err(PlatformError::Corrupt("deletion_plan_rank"));
            }
            Ok(PlanEntry {
                entity_kind,
                key_json,
                delete_rank,
            })
        })
        .collect()
}

fn load_plan_key_cleanup_actions(
    connection: &Connection,
    token: &str,
) -> PlatformResult<Vec<KeyCleanupAction>> {
    let mut statement = connection.prepare(
        "SELECT enrollment_epoch,key_reference
         FROM deletion_plan_photokit_key_cleanup
         WHERE snapshot_token=?1 ORDER BY enrollment_epoch",
    )?;
    let actions = statement
        .query_map([token], |row| {
            Ok(KeyCleanupAction {
                enrollment_epoch: row.get(0)?,
                key_reference: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(actions)
}

fn load_run_response(
    connection: &Connection,
    request: &ExecuteDeletionV1Request,
    run_id: &str,
    completed_at_ms: i64,
) -> PlatformResult<ExecuteDeletionV1Response> {
    let row: (i64, i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT accepted_at_ms,deadline_at_ms,deleted_record_count,deleted_blob_count,
                deleted_blob_bytes,retained_shared_blob_count
         FROM deletion_runs WHERE run_id=?1",
        [run_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    Ok(ExecuteDeletionV1Response {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request.request_id,
        run_id: DeletionRunId::new(
            Uuid::parse_str(run_id).map_err(|_| PlatformError::Corrupt("deletion_run_id"))?,
        )
        .map_err(|_| PlatformError::Corrupt("deletion_run_id"))?,
        complete: true,
        accepted_at: format_timestamp(row.0)?,
        deadline_at: format_timestamp(row.1)?,
        completed_at: format_timestamp(completed_at_ms)?,
        deleted_local_record_count: row.2 as u64,
        deleted_unique_blob_count: row.3 as u64,
        deleted_unique_blob_bytes: row.4 as u64,
        retained_shared_blob_count: row.5 as u64,
        backup_retention: load_backup_reports(connection, run_id)?,
        remote_retention: load_remote_reports(connection, run_id)?,
        replay_status: ReplayStatusV1::Created,
    })
}

fn load_backup_reports(
    connection: &Connection,
    run_id: &str,
) -> PlatformResult<Vec<DeletionBackupRetentionV1>> {
    let mut statement = connection.prepare(
        "SELECT backup_id,reason,expires_at_ms FROM deletion_run_backup_retention
         WHERE run_id=?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, reason, expires)| {
            Ok(DeletionBackupRetentionV1 {
                backup_id: BackupId::new(
                    Uuid::parse_str(&id).map_err(|_| PlatformError::Corrupt("backup_id"))?,
                )
                .map_err(|_| PlatformError::Corrupt("backup_id"))?,
                reason: backup_reason(&reason)?,
                expires_at: format_timestamp(expires)?,
            })
        })
        .collect()
}

fn load_plan_backup_reports(
    connection: &Connection,
    token: &str,
) -> PlatformResult<Vec<DeletionBackupRetentionV1>> {
    let mut statement = connection.prepare(
        "SELECT backup_id,reason,expires_at_ms FROM deletion_plan_backup_retention
         WHERE snapshot_token=?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([token], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, reason, expires)| {
            Ok(DeletionBackupRetentionV1 {
                backup_id: BackupId::new(
                    Uuid::parse_str(&id).map_err(|_| PlatformError::Corrupt("backup_id"))?,
                )
                .map_err(|_| PlatformError::Corrupt("backup_id"))?,
                reason: backup_reason(&reason)?,
                expires_at: format_timestamp(expires)?,
            })
        })
        .collect()
}

fn load_remote_reports(
    connection: &Connection,
    run_id: &str,
) -> PlatformResult<Vec<DeletionRemoteRetentionV1>> {
    let mut statement = connection.prepare(
        "SELECT purpose,retention_mode,retention_provenance,dispatched_at_ms,
                policy_expires_at_ms FROM deletion_run_remote_retention
         WHERE run_id=?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(purpose, mode, provenance, dispatched, expires)| {
            Ok(DeletionRemoteRetentionV1 {
                provider: CredentialProviderV1::OpenAi,
                purpose: match purpose.as_str() {
                    "outfit_recommendation" => DeletionRemotePurposeV1::OutfitRecommendation,
                    "try_on" => DeletionRemotePurposeV1::TryOn,
                    _ => return Err(PlatformError::Corrupt("deletion_remote_purpose")),
                },
                retention_mode: retention_mode(&mode)?,
                retention_provenance: provenance,
                dispatched_at: format_timestamp(dispatched)?,
                policy_expires_at: expires.map(format_timestamp).transpose()?,
                status: DeletionRemoteRetentionStatusV1::ProviderDeletionUnavailable,
            })
        })
        .collect()
}

fn load_plan_remote_reports(
    connection: &Connection,
    token: &str,
) -> PlatformResult<Vec<DeletionRemoteRetentionV1>> {
    let mut statement = connection.prepare(
        "SELECT purpose,retention_mode,retention_provenance,dispatched_at_ms,
                policy_expires_at_ms FROM deletion_plan_remote_retention
         WHERE snapshot_token=?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([token], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(purpose, mode, provenance, dispatched, expires)| {
            Ok(DeletionRemoteRetentionV1 {
                provider: CredentialProviderV1::OpenAi,
                purpose: match purpose.as_str() {
                    "outfit_recommendation" => DeletionRemotePurposeV1::OutfitRecommendation,
                    "try_on" => DeletionRemotePurposeV1::TryOn,
                    _ => return Err(PlatformError::Corrupt("deletion_remote_purpose")),
                },
                retention_mode: retention_mode(&mode)?,
                retention_provenance: provenance,
                dispatched_at: format_timestamp(dispatched)?,
                policy_expires_at: expires.map(format_timestamp).transpose()?,
                status: DeletionRemoteRetentionStatusV1::ProviderDeletionUnavailable,
            })
        })
        .collect()
}

fn drain_blob(active: &Path, trash: &Path, hash: &str, length: u64) -> PlatformResult<()> {
    drain_blob_with_post_rename(active, trash, hash, length, || Ok(()))
}

fn drain_blob_with_post_rename<F>(
    active: &Path,
    trash: &Path,
    hash: &str,
    length: u64,
    post_rename: F,
) -> PlatformResult<()>
where
    F: FnOnce() -> PlatformResult<()>,
{
    let active_metadata = entry_metadata(active)?;
    let trash_metadata = entry_metadata(trash)?;
    if active_metadata.is_some() && trash_metadata.is_some() {
        return Err(PlatformError::Corrupt("deletion_blob_ambiguous"));
    }
    if let Some(metadata) = active_metadata {
        validate_deletion_file_metadata(&metadata, length, "deletion_blob_identity")?;
        if hash_private_file(active, Some(length))? != hash {
            return Err(PlatformError::Corrupt("deletion_blob_identity"));
        }
        fs::rename(active, trash)?;
        sync_directory(
            active
                .parent()
                .ok_or(PlatformError::Corrupt("deletion_blob_parent"))?,
        )?;
        sync_directory(
            trash
                .parent()
                .ok_or(PlatformError::Corrupt("deletion_trash_parent"))?,
        )?;
        post_rename()?;
    }
    if let Some(metadata) = entry_metadata(trash)? {
        validate_deletion_file_metadata(&metadata, length, "deletion_trash_identity")?;
        if hash_private_file(trash, Some(length))? != hash {
            return Err(PlatformError::Corrupt("deletion_trash_identity"));
        }
        fs::remove_file(trash)?;
        sync_directory(
            trash
                .parent()
                .ok_or(PlatformError::Corrupt("deletion_trash_parent"))?,
        )?;
    }
    Ok(())
}

fn entry_metadata(path: &Path) -> PlatformResult<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn validate_deletion_file_metadata(
    metadata: &fs::Metadata,
    length: u64,
    error: &'static str,
) -> PlatformResult<()> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != length
    {
        return Err(PlatformError::Corrupt(error));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> PlatformResult<()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(PlatformError::Corrupt("deletion_trash_identity"));
    }
    Ok(())
}

fn target_kind_db(value: DeletionTargetKindV1) -> &'static str {
    match value {
        DeletionTargetKindV1::ImportRoot => "import_root",
        DeletionTargetKindV1::Source => "source",
        DeletionTargetKindV1::Item => "item",
        DeletionTargetKindV1::PhotoKitEnrollment => "photokit_enrollment",
        DeletionTargetKindV1::PhotoKitAsset => "photokit_asset",
    }
}

fn parse_target_kind(value: &str) -> PlatformResult<DeletionTargetKindV1> {
    match value {
        "import_root" => Ok(DeletionTargetKindV1::ImportRoot),
        "source" => Ok(DeletionTargetKindV1::Source),
        "item" => Ok(DeletionTargetKindV1::Item),
        "photokit_enrollment" => Ok(DeletionTargetKindV1::PhotoKitEnrollment),
        "photokit_asset" => Ok(DeletionTargetKindV1::PhotoKitAsset),
        _ => Err(PlatformError::Corrupt("deletion_target_kind")),
    }
}

fn backup_reason_db(value: BackupReasonV1) -> &'static str {
    match value {
        BackupReasonV1::Manual => "manual",
        BackupReasonV1::Scheduled => "scheduled",
        BackupReasonV1::PreUpgrade => "pre_upgrade",
        BackupReasonV1::PreRestore => "pre_restore",
    }
}

fn backup_reason(value: &str) -> PlatformResult<BackupReasonV1> {
    match value {
        "manual" => Ok(BackupReasonV1::Manual),
        "scheduled" => Ok(BackupReasonV1::Scheduled),
        "pre_upgrade" => Ok(BackupReasonV1::PreUpgrade),
        "pre_restore" => Ok(BackupReasonV1::PreRestore),
        _ => Err(PlatformError::Corrupt("backup_reason")),
    }
}

fn remote_purpose_db(value: DeletionRemotePurposeV1) -> &'static str {
    match value {
        DeletionRemotePurposeV1::OutfitRecommendation => "outfit_recommendation",
        DeletionRemotePurposeV1::TryOn => "try_on",
    }
}

fn retention_mode_db(value: OpenAiRetentionModeV1) -> &'static str {
    match value {
        OpenAiRetentionModeV1::Unknown => "unknown",
        OpenAiRetentionModeV1::Default => "default",
        OpenAiRetentionModeV1::Mam => "MAM",
        OpenAiRetentionModeV1::Zdr => "ZDR",
    }
}

fn timestamp_ms(value: &str) -> PlatformResult<i64> {
    let value = value
        .strip_suffix('Z')
        .ok_or(PlatformError::Corrupt("deletion_timestamp"))?;
    let (date, clock) = value
        .split_once('T')
        .ok_or(PlatformError::Corrupt("deletion_timestamp"))?;
    let date = date
        .split('-')
        .map(str::parse::<i32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PlatformError::Corrupt("deletion_timestamp"))?;
    let (whole_clock, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    let clock = whole_clock
        .split(':')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PlatformError::Corrupt("deletion_timestamp"))?;
    if date.len() != 3 || clock.len() != 3 || fraction.len() > 9 {
        return Err(PlatformError::Corrupt("deletion_timestamp"));
    }
    let mut nanos = fraction.to_owned();
    nanos.extend(std::iter::repeat_n('0', 9 - nanos.len()));
    let nanosecond = if nanos.is_empty() {
        0
    } else {
        nanos
            .parse::<u32>()
            .map_err(|_| PlatformError::Corrupt("deletion_timestamp"))?
    };
    let month = time::Month::try_from(date[1] as u8)
        .map_err(|_| PlatformError::Corrupt("deletion_timestamp"))?;
    let date = time::Date::from_calendar_date(date[0], month, date[2] as u8)
        .map_err(|_| PlatformError::Corrupt("deletion_timestamp"))?;
    let clock = time::Time::from_hms_nano(clock[0], clock[1], clock[2], nanosecond)
        .map_err(|_| PlatformError::Corrupt("deletion_timestamp"))?;
    time::PrimitiveDateTime::new(date, clock)
        .assume_utc()
        .unix_timestamp_nanos()
        .checked_div(1_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(PlatformError::Corrupt("deletion_timestamp"))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

fn deletion_port_error(error: PlatformError) -> CatalogPortError {
    let kind = match error {
        PlatformError::Conflict("snapshot_expired") => CatalogPortErrorKind::SnapshotExpired,
        PlatformError::InvalidInput(_) => CatalogPortErrorKind::InvalidState,
        PlatformError::Conflict(_) | PlatformError::LeaseLost => CatalogPortErrorKind::Conflict,
        PlatformError::Unsupported(_) => CatalogPortErrorKind::Internal,
        PlatformError::Corrupt(_)
        | PlatformError::Io(_)
        | PlatformError::Json(_)
        | PlatformError::Keychain(_)
        | PlatformError::Sqlite(_) => CatalogPortErrorKind::DataIntegrity,
    };
    CatalogPortError::new(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlobStore, PhotoKitEnrollment, PhotoKitRepository, PhotoKitRootKey, RestoreRepository,
        StoreLock,
    };
    use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tempfile::TempDir;
    use wardrobe_core::{
        CatalogPort, CorrectPhotoOwnerV1Request, CorrectPhotoPersonDetectionV1Request,
        CreatePhotoScopeV1Request, DecidePhotoOwnerV1Request, DeletionConfirmationV1,
        DeletionDependencyClassV1, DeletionPort, DetectPhotoScopePeopleV1Request,
        ImportLocalSourcesV1Request, ListImportedPhotoRootsV1Request,
        ListPhotoOwnerReviewsV1Request, LocalPersonDetectionProviderV1, PersonDetectionOutcomeV1,
        PersonDetectionProviderDescriptorV1, PersonDetectionProviderResult,
        PersonDetectionRequestV1, PersonDetectionResultV1, PhotoAnalysisPort, PhotoOwnerActionV1,
        PhotoOwnerReviewStateV1, PhotoScopeId, PreviewDeletionV1Request, PreviewDeletionV1Response,
        RectV1, RequestId, UnavailableGarmentSegmentationProviderV1,
        APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1, LOCAL_PERSON_DETECTION_CONTRACT_V1,
        PHOTO_PREPROCESSING_REVISION_V1, SCHEMA_VERSION_V1,
    };

    #[derive(Default)]
    struct CleanupKeys {
        failures: Mutex<VecDeque<PhotoKitKeyError>>,
        deleted: Mutex<Vec<String>>,
    }

    impl CleanupKeys {
        fn failing_once(error: PhotoKitKeyError) -> Self {
            Self {
                failures: Mutex::new(VecDeque::from([error])),
                deleted: Mutex::new(Vec::new()),
            }
        }
    }

    impl PhotoKitKeyPort for CleanupKeys {
        fn create_root_key(
            &self,
            _key_reference: &str,
        ) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
            Err(PhotoKitKeyError::Internal)
        }

        fn load_root_key(
            &self,
            _key_reference: &str,
            _allow_authentication_ui: bool,
        ) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
            Err(PhotoKitKeyError::Internal)
        }

        fn delete_root_key(&self, key_reference: &str) -> Result<(), PhotoKitKeyError> {
            if let Some(error) = self.failures.lock().unwrap().pop_front() {
                return Err(error);
            }
            self.deleted.lock().unwrap().push(key_reference.to_owned());
            Ok(())
        }
    }

    #[derive(Default)]
    struct ZeroPeopleProvider {
        calls: AtomicUsize,
    }

    impl LocalPersonDetectionProviderV1 for ZeroPeopleProvider {
        fn describe(&self) -> PersonDetectionProviderDescriptorV1 {
            PersonDetectionProviderDescriptorV1 {
                contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
                provider_revision: APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
                preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
                vision_request_revision: 2,
                os_build: "p04-deletion-test-os".to_owned(),
                vision_framework_build: "p04-deletion-test-vision".to_owned(),
            }
        }

        fn detect(
            &self,
            request: &PersonDetectionRequestV1,
        ) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(PersonDetectionOutcomeV1 {
                contract_revision: request.contract_revision.clone(),
                request_handle: request.request_handle,
                source_revision_sha256: request.source_revision_sha256.clone(),
                input_blob_sha256: request.input_blob_sha256.clone(),
                result: PersonDetectionResultV1::SucceededZero,
            })
        }
    }

    #[test]
    fn photokit_enrollment_deletion_freezes_and_completes_final_key_cleanup() {
        let (_temporary, _paths, database) = test_database();
        let enrollment = seed_photokit_enrollment(&database, "cleanup-success-key");
        let preview = preview_photokit(
            &database,
            DeletionTargetKindV1::PhotoKitEnrollment,
            &enrollment.enrollment_epoch,
        );
        assert!(preview.counts.iter().any(|count| {
            count.class == DeletionDependencyClassV1::DecisionRecords && count.count == 1
        }));
        let connection = database.connection().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT key_reference
                     FROM deletion_plan_photokit_key_cleanup
                     WHERE snapshot_token=?1",
                    [preview.preview_snapshot_token.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "cleanup-success-key"
        );
        drop(connection);

        let keys = CleanupKeys::default();
        let response = database
            .execute_deletion_impl_with_keys(&execute_request(&preview), &keys)
            .unwrap();
        assert!(response.complete);
        assert_eq!(
            keys.deleted.lock().unwrap().as_slice(),
            ["cleanup-success-key"]
        );
        let connection = database.connection().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM photokit_key_cleanup_intents
                     WHERE key_reference='cleanup-success-key'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "complete"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM photokit_connector_state WHERE singleton=1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "unconfigured"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM photokit_enrollments", [], |row| row
                    .get::<_, i64>(
                    0
                ),)
                .unwrap(),
            0
        );
    }

    #[test]
    fn photokit_enrollment_deletion_retries_locked_key_cleanup_after_restart_boundary() {
        let (_temporary, _paths, database) = test_database();
        let enrollment = seed_photokit_enrollment(&database, "cleanup-retry-key");
        let preview = preview_photokit(
            &database,
            DeletionTargetKindV1::PhotoKitEnrollment,
            &enrollment.enrollment_epoch,
        );
        let request = execute_request(&preview);
        let keys = CleanupKeys::failing_once(PhotoKitKeyError::Locked);
        assert!(matches!(
            database.execute_deletion_impl_with_keys(&request, &keys),
            Err(PlatformError::Conflict("photokit_key_cleanup_pending"))
        ));
        let connection = database.connection().unwrap();
        let state: (String, String, String) = connection
            .query_row(
                "SELECT run.state,intent.state,intent.failure_code
                 FROM deletion_runs run
                 JOIN photokit_key_cleanup_intents intent
                   ON intent.deletion_run_id=run.run_id
                 WHERE run.request_id=?1",
                [request.request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            state,
            (
                "needs_attention".to_owned(),
                "pending".to_owned(),
                "locked".to_owned()
            )
        );
        drop(connection);

        let replay = database
            .execute_deletion_impl_with_keys(&request, &keys)
            .unwrap();
        assert!(replay.complete);
        assert_eq!(replay.replay_status, ReplayStatusV1::Replayed);
        assert_eq!(
            keys.deleted.lock().unwrap().as_slice(),
            ["cleanup-retry-key"]
        );
    }

    #[test]
    fn photokit_asset_deletion_invalidates_generation_without_deleting_enrollment_key() {
        let (_temporary, _paths, database) = test_database();
        let enrollment = seed_photokit_enrollment(&database, "asset-owner-key");
        let asset_id = seed_photokit_asset(&database, &enrollment.enrollment_epoch);
        let preview = preview_photokit(&database, DeletionTargetKindV1::PhotoKitAsset, &asset_id);
        let keys = CleanupKeys::default();
        database
            .execute_deletion_impl_with_keys(&execute_request(&preview), &keys)
            .unwrap();

        let connection = database.connection().unwrap();
        let state: (i64, i64, i64) = connection
            .query_row(
                "SELECT
                   EXISTS(SELECT 1 FROM photokit_enrollments
                          WHERE enrollment_epoch=?1),
                   EXISTS(SELECT 1 FROM photokit_assets WHERE asset_id=?2),
                   (SELECT operation_fence FROM photokit_enrollments
                    WHERE enrollment_epoch=?1)",
                params![enrollment.enrollment_epoch, asset_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, (1, 0, 1));
        assert!(keys.deleted.lock().unwrap().is_empty());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM photokit_key_cleanup_intents",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn hard_deletion_schema_inventory_and_blob_classification() {
        let (_temporary, paths, database) = test_database();
        let connection = database.connection().unwrap();
        validate_schema_classification(&connection).unwrap();
        let tables = DELETE_SPECS
            .iter()
            .map(|spec| spec.table)
            .collect::<BTreeSet<_>>();
        assert_eq!(tables.len(), DELETE_SPECS.len());
        let migration = format!(
            "{}\n{}\n{}",
            include_str!("../migrations/0011_hard_deletion.sql"),
            include_str!("../migrations/0012_photokit_connector.sql"),
            include_str!("../migrations/0014_photo_owner_authority.sql")
        );
        let compact_migration = migration
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        for table in tables {
            assert!(migration.contains(&format!("BEFORE DELETE ON {table}")));
            let primary_key_sql = format!(
                "SELECT name FROM pragma_table_info('{table}')
                 WHERE pk>0 ORDER BY pk"
            );
            let primary_key = connection
                .prepare(&primary_key_sql)
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(
                !primary_key.is_empty(),
                "{table} has no bounded primary key"
            );
            let exact_key = primary_key
                .iter()
                .map(|column| format!("OLD.{column}"))
                .collect::<Vec<_>>()
                .join(",");
            assert!(
                compact_migration.contains(&format!("json_array({exact_key})")),
                "missing exact primary/composite trigger key for {table}"
            );
        }
        for owner in BLOB_OWNER_SPECS {
            assert!(DeletionEntityKind::ALL.contains(&owner.kind));
            assert!(migration.contains(&format!("BEFORE DELETE ON {}", owner.kind.as_str())));
        }
        assert!(paths.database.is_file());
    }

    #[test]
    fn hard_deletion_trigger_authority_requires_exact_key() {
        let (temporary, _paths, database) = test_database();
        let first = import_png(&database, &temporary, "first.png", [1, 2, 3]);
        let second = import_png(&database, &temporary, "second.png", [4, 5, 6]);
        let preview = preview_source(&database, &first);
        let connection = database.connection().unwrap();
        let epoch: String = connection
            .query_row(
                "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let run_id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO deletion_runs(
                    run_id,epoch,snapshot_token,request_id,request_json,envelope_hash,
                    plan_sha256,state,accepted_at_ms,deadline_at_ms)
                 VALUES(?1,?2,?3,?4,'{}',?5,?6,'in_progress',1,2)",
                params![
                    run_id,
                    epoch,
                    preview.preview_snapshot_token.as_str(),
                    Uuid::new_v4().to_string(),
                    "0".repeat(64),
                    preview.plan_sha256.as_str(),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO deletion_execution_authority(
                    singleton,epoch,run_id,snapshot_token)
                 VALUES(1,?1,?2,?3)",
                params![epoch, run_id, preview.preview_snapshot_token.as_str()],
            )
            .unwrap();
        let error = connection
            .execute("DELETE FROM local_sources WHERE source_id=?1", [&second])
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("hard deletion authority required"));

        let gmail_request_id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO gmail_operations(
                    request_id,command_name,request_envelope_sha256,stage,
                    created_at_ms,updated_at_ms)
                 VALUES(?1,'sync_gmail_v1',?2,'syncing',1,1)",
                params![gmail_request_id, "a".repeat(64)],
            )
            .unwrap();
        let error = connection
            .execute(
                "DELETE FROM gmail_operations WHERE request_id=?1",
                [&gmail_request_id],
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("hard deletion authority required"));
    }

    #[test]
    fn hard_deletion_orders_deep_source_and_mime_hierarchies() {
        let (_temporary, _paths, database) = test_database();
        let root_id = Uuid::new_v4().to_string();
        let source_ids = [
            Uuid::new_v4().to_string(),
            Uuid::new_v4().to_string(),
            Uuid::new_v4().to_string(),
        ];
        let part_ids = [
            Uuid::new_v4().to_string(),
            Uuid::new_v4().to_string(),
            Uuid::new_v4().to_string(),
        ];
        let now_ms = unix_now_ms().unwrap();
        let connection = database.connection().unwrap();
        connection
            .execute(
                "INSERT INTO import_roots(
                    root_id,canonical_path,device_id,file_id,status,created_at_ms,updated_at_ms)
                 VALUES(?1,'/synthetic/deep-hierarchy',900,901,'available',?2,?2)",
                params![root_id, now_ms],
            )
            .unwrap();
        for (index, source_id) in source_ids.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO local_sources(
                        source_id,root_id,parent_source_id,source_kind,identity_key,
                        canonical_locator,status,no_blob_reason,created_at_ms,updated_at_ms)
                     VALUES(?1,?2,?3,'eml',?4,?5,'missing','synthetic',?6,?6)",
                    params![
                        source_id,
                        root_id,
                        if index > 0 {
                            Some(&source_ids[index - 1])
                        } else {
                            None
                        },
                        format!("deep-source-{index}"),
                        format!("deep-source-{index}.eml"),
                        now_ms,
                    ],
                )
                .unwrap();
        }
        for (index, part_id) in part_ids.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO mime_parts(
                        part_id,source_id,parent_part_id,ordinal,content_type,body_kind,
                        decoded_bytes)
                     VALUES(?1,?2,?3,?4,?5,?6,0)",
                    params![
                        part_id,
                        source_ids[2],
                        if index > 0 {
                            Some(&part_ids[index - 1])
                        } else {
                            None
                        },
                        index as i64,
                        if index < 2 {
                            "multipart/mixed"
                        } else {
                            "text/plain"
                        },
                        if index < 2 { "multipart" } else { "text" },
                    ],
                )
                .unwrap();
        }
        drop(connection);

        let preview = database
            .preview_deletion(&PreviewDeletionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                target_kind: DeletionTargetKindV1::ImportRoot,
                target_id: root_id.clone(),
                limit: 100,
            })
            .unwrap();
        let response = database
            .execute_deletion(&execute_request(&preview))
            .unwrap();
        response.validate().unwrap();
        assert!(response.deleted_local_record_count >= 7);
        let remaining: i64 = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM import_roots WHERE root_id=?1)
                   +(SELECT COUNT(*) FROM local_sources WHERE root_id=?1)
                   +(SELECT COUNT(*) FROM mime_parts WHERE source_id=?2)",
                params![root_id, source_ids[2]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(0, remaining);
    }

    #[test]
    fn hard_deletion_stale_backup_retention_remote_retention_and_replay() {
        let (temporary, paths, database) = test_database();
        let source = import_png(&database, &temporary, "stale.png", [9, 8, 7]);
        let stale = preview_source(&database, &source);
        BackupRepository::new(&paths)
            .create(BackupReasonV1::Manual, unix_now_ms().unwrap())
            .unwrap();
        let stale_request = execute_request(&stale);
        assert!(database.execute_deletion(&stale_request).is_err());

        let remote_stale = preview_source(&database, &source);
        let blob_sha256: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT blob_sha256 FROM local_sources WHERE source_id=?1",
                [&source],
                |row| row.get(0),
            )
            .unwrap();
        seed_try_on_transport(&database, &source, &blob_sha256);
        assert!(database
            .execute_deletion(&execute_request(&remote_stale))
            .is_err());

        let fresh = preview_source(&database, &source);
        assert!(!fresh.backup_retention.is_empty());
        assert_eq!(fresh.remote_retention.len(), 1);
        let request = execute_request(&fresh);
        set_test_drain_fault(
            &request.request_id.to_string(),
            TestDrainFault {
                transient_failures: 2,
                interrupt_after_blob: false,
            },
        );
        let created = database.execute_deletion(&request).unwrap();
        created.validate().unwrap();
        assert!(created.completed_at <= created.deadline_at);
        assert_eq!(ReplayStatusV1::Created, created.replay_status);
        assert!(!created.backup_retention.is_empty());
        assert_eq!(created.remote_retention.len(), 1);
        let replay = database.execute_deletion(&request).unwrap();
        assert_eq!(ReplayStatusV1::Replayed, replay.replay_status);
        assert_eq!(created.run_id, replay.run_id);
    }

    #[test]
    fn hard_deletion_reports_outfit_recommendation_transport() {
        let (_temporary, _paths, database) = test_database();
        let item_id = Uuid::new_v4().to_string();
        seed_outfit_recommendation_transport(&database, &item_id);

        let preview = database
            .preview_deletion(&PreviewDeletionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                target_kind: DeletionTargetKindV1::Item,
                target_id: item_id,
                limit: 100,
            })
            .unwrap();
        assert_eq!(1, preview.remote_retention.len());
        assert_eq!(
            DeletionRemotePurposeV1::OutfitRecommendation,
            preview.remote_retention[0].purpose
        );
        assert_eq!(
            DeletionRemoteRetentionStatusV1::ProviderDeletionUnavailable,
            preview.remote_retention[0].status
        );
    }

    #[test]
    fn hard_deletion_filesystem_rejects_dangling_symlink_directory_and_hard_link() {
        let temporary = tempfile::tempdir().unwrap();
        let active = temporary.path().join("active");
        let trash = temporary.path().join("trash");
        symlink(temporary.path().join("missing"), &active).unwrap();
        assert!(drain_blob(&active, &trash, &"0".repeat(64), 0).is_err());
        fs::remove_file(&active).unwrap();

        fs::write(&active, b"x").unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&active, temporary.path().join("other")).unwrap();
        let hash = format!("{:x}", Sha256::digest(b"x"));
        assert!(drain_blob(&active, &trash, &hash, 1).is_err());
        fs::remove_file(&active).unwrap();
        fs::create_dir(&active).unwrap();
        assert!(drain_blob(&active, &trash, &hash, 1).is_err());
        fs::remove_dir(&active).unwrap();

        fs::write(&active, b"x").unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(drain_blob(&active, &trash, &hash, 1).is_err());
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(drain_blob(&active, &trash, &hash, 2).is_err());
        assert!(drain_blob(&active, &trash, &"f".repeat(64), 1).is_err());

        fs::write(&trash, b"x").unwrap();
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(drain_blob(&active, &trash, &hash, 1).is_err());
        fs::remove_file(&active).unwrap();
        fs::remove_file(&trash).unwrap();

        let run_directory = temporary.path().join("run");
        create_private_directory(&run_directory).unwrap();
        let unexpected = run_directory.join("unexpected");
        fs::write(&unexpected, b"x").unwrap();
        fs::set_permissions(&unexpected, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_run_trash_entries(&run_directory, &BTreeMap::new()).is_err());
    }

    #[test]
    fn hard_deletion_crash_trash_identity_failure_marks_needs_attention() {
        let (temporary, paths, database) = test_database();
        let source = import_png(&database, &temporary, "crash.png", [5, 15, 25]);
        let hash: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT blob_sha256 FROM local_sources WHERE source_id=?1",
                [&source],
                |row| row.get(0),
            )
            .unwrap();
        let request = execute_request(&preview_source(&database, &source));
        let run_id = simulate_crash_after_relational_commit(&database, &request);
        let trash = paths.deletion_trash.join(&run_id).join(&hash);
        fs::remove_file(&trash).unwrap();
        symlink(temporary.path().join("missing-after-crash"), &trash).unwrap();
        let maintenance = lock_maintenance().unwrap();
        assert!(database
            .drain_deletion_run(&run_id, &maintenance, DeletionDrainMode::Recovery)
            .is_err());
        drop(maintenance);
        let state: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT state FROM deletion_runs WHERE run_id=?1",
                [&run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!("needs_attention", state);
    }

    #[test]
    fn hard_deletion_restart_completes_an_overdue_drained_run() {
        let (temporary, paths, database) = test_database();
        let source = import_png(&database, &temporary, "overdue.png", [35, 45, 55]);
        let request = execute_request(&preview_source(&database, &source));
        let run_id = simulate_crash_after_relational_commit(&database, &request);
        set_test_drain_fault(
            &request.request_id.to_string(),
            TestDrainFault {
                transient_failures: 2,
                interrupt_after_blob: false,
            },
        );
        database
            .connection()
            .unwrap()
            .execute(
                "UPDATE deletion_runs SET deadline_at_ms=accepted_at_ms+1 WHERE run_id=?1",
                [&run_id],
            )
            .unwrap();
        assert!(matches!(
            database.execute_deletion(&request),
            Err(CatalogPortError {
                kind: CatalogPortErrorKind::Conflict,
                ..
            })
        ));
        drop(database);

        let restarted =
            Database::open(&paths, unix_now_ms().unwrap().saturating_add(10_000)).unwrap();
        let state: String = restarted
            .connection()
            .unwrap()
            .query_row(
                "SELECT state FROM deletion_runs WHERE run_id=?1",
                [&run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!("complete", state);
        let response_json: String = restarted
            .connection()
            .unwrap()
            .query_row(
                "SELECT response_json FROM deletion_execution_receipts WHERE run_id=?1",
                [&run_id],
                |row| row.get(0),
            )
            .unwrap();
        let response: ExecuteDeletionV1Response = serde_json::from_str(&response_json).unwrap();
        response.validate().unwrap();
        assert!(response.completed_at > response.deadline_at);
    }

    #[test]
    fn hard_deletion_populated_p04_restart_has_no_relational_json_or_blob_residuals() {
        let (temporary, paths, database) = test_database();
        let provider = ZeroPeopleProvider::default();

        let invalid_root = temporary.path().join("p04-invalid-root");
        fs::create_dir(&invalid_root).unwrap();
        let invalid_path = invalid_root.join("p04-invalid.jpg");
        fs::write(&invalid_path, b"not an image").unwrap();
        let invalid_import = database
            .import_local_sources(&ImportLocalSourcesV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                paths: vec![invalid_root.to_string_lossy().into_owned()],
            })
            .unwrap();
        let invalid_root_id = invalid_import.summaries[0]
            .import_root_id
            .unwrap()
            .to_string();
        let invalid_source: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT source_id FROM local_sources WHERE root_id=?1",
                [&invalid_root_id],
                |row| row.get(0),
            )
            .unwrap();
        let invalid_scope = create_p04_scope(&database, &invalid_source);
        let zero_attempt_request = RequestId::new_v4();
        let zero_attempt = database
            .detect_photo_scope_people(
                &DetectPhotoScopePeopleV1Request {
                    schema_version: SCHEMA_VERSION_V1,
                    request_id: zero_attempt_request,
                    scope_id: invalid_scope,
                },
                &provider,
            )
            .unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert_eq!(zero_attempt.skipped_count, 1);
        assert_eq!(
            database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM photo_person_detection_attempts
                     WHERE run_id=?1",
                    [zero_attempt.run_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        let invalid_preview = preview_source(&database, &invalid_source);
        assert_eq!(
            database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM deletion_preview_items
                     WHERE snapshot_token=?1 AND entity_id=?2",
                    params![
                        invalid_preview.preview_snapshot_token.as_str(),
                        format!("photo_person_detection_run:{}", zero_attempt.run_id)
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        database
            .execute_deletion(&execute_request(&invalid_preview))
            .unwrap();
        let connection = database.connection().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM photo_person_detection_runs
                     WHERE run_id=?1",
                    [zero_attempt.run_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM command_receipts WHERE request_id=?1",
                    [zero_attempt_request.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(connection);

        let populated_root = temporary.path().join("p04-populated-root");
        fs::create_dir(&populated_root).unwrap();
        write_png(&populated_root.join("p04-populated.png"), [12, 34, 56]);
        let populated_import = database
            .import_local_sources(&ImportLocalSourcesV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                paths: vec![populated_root.to_string_lossy().into_owned()],
            })
            .unwrap();
        let populated_root_id = populated_import.summaries[0]
            .import_root_id
            .unwrap()
            .to_string();
        let source: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT source_id FROM local_sources WHERE root_id=?1",
                [&populated_root_id],
                |row| row.get(0),
            )
            .unwrap();
        let scope = create_p04_scope(&database, &source);
        let detected = database
            .detect_photo_scope_people(
                &DetectPhotoScopePeopleV1Request {
                    schema_version: SCHEMA_VERSION_V1,
                    request_id: RequestId::new_v4(),
                    scope_id: scope,
                },
                &provider,
            )
            .unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(detected.no_person_detected_count, 1);
        let review = database
            .list_photo_owner_reviews(&ListPhotoOwnerReviewsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                state: PhotoOwnerReviewStateV1::NoPersonDetected,
                cursor: None,
                limit: 10,
            })
            .unwrap()
            .reviews
            .remove(0);
        let correction = database
            .correct_photo_person_detection(&CorrectPhotoPersonDetectionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                owner_review_id: review.owner_review_id,
                manual_rectangle: RectV1 {
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 2,
                },
                expected_terminal_attempt_id: review.terminal_attempt_id,
                expected_detection_revision: review.detection_revision,
                expected_owner_head_revision: review.owner_head_revision,
                expected_photo_revision: review.photo_revision,
            })
            .unwrap();
        let selected = database
            .decide_photo_owner(&DecidePhotoOwnerV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                owner_review_id: correction.review.owner_review_id,
                action: PhotoOwnerActionV1::SelectPerson,
                selected_person_instance_id: Some(correction.instance.person_instance_id),
                expected_detection_revision: correction.review.detection_revision,
                expected_owner_head_revision: correction.review.owner_head_revision,
                expected_photo_revision: correction.review.photo_revision,
            })
            .unwrap();
        assert_eq!(
            database
                .process_photo_owner_work(&UnavailableGarmentSegmentationProviderV1)
                .unwrap(),
            0
        );
        database
            .correct_photo_owner(&CorrectPhotoOwnerV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                owner_review_id: selected.review.owner_review_id,
                superseded_owner_decision_id: selected.decision.owner_decision_id,
                action: PhotoOwnerActionV1::OwnerAbsent,
                selected_person_instance_id: None,
                expected_detection_revision: selected.review.detection_revision,
                expected_owner_head_revision: selected.decision.owner_revision,
                expected_photo_revision: selected.decision.photo_revision,
            })
            .unwrap();

        let connection = database.connection().unwrap();
        for table in [
            "photo_person_detection_runs",
            "photo_person_detection_attempts",
            "photo_owner_preview_references",
            "photo_owner_reviews",
            "photo_detection_corrections",
            "photo_person_instances",
            "photo_owner_decisions",
            "photo_owner_heads",
            "photo_owner_work_claims",
            "photo_observations",
            "photo_observation_owner_links",
            "photo_owner_command_entities",
        ] {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert!(count > 0, "{table} was not populated");
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM photo_segmentation_attempts
                     WHERE provider_invoked=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let source_blob: String = connection
            .query_row(
                "SELECT blob_sha256 FROM local_sources WHERE source_id=?1",
                [&source],
                |row| row.get(0),
            )
            .unwrap();
        let source_blob_path = BlobStore::new(&paths).path_for_hash(&source_blob).unwrap();
        assert!(source_blob_path.is_file());
        let response_ids = [
            detected.run_id.to_string(),
            correction.instance.person_instance_id.to_string(),
            selected.decision.owner_decision_id.to_string(),
        ];
        for id in &response_ids {
            assert!(
                connection
                    .query_row(
                        "SELECT COUNT(*)
                         FROM command_receipts receipt, json_tree(receipt.response_json) node
                         WHERE CAST(node.atom AS TEXT)=?1",
                        [id],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap()
                    > 0,
                "receipt JSON did not contain {id}"
            );
        }
        let request_ids = connection
            .prepare(
                "SELECT DISTINCT request_id FROM photo_owner_command_entities
                 ORDER BY request_id",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        drop(connection);

        let preview = preview_source(&database, &source);
        let connection = database.connection().unwrap();
        for prefix in [
            "photo_person_detection_run:",
            "photo_person_detection_attempt:",
            "photo_owner_preview:",
            "photo_owner_review:",
            "photo_detection_correction:",
            "photo_person_instance:",
            "photo_owner_decision:",
            "photo_owner_head:",
            "photo_owner_work:",
            "photo_observation_owner_link:",
            "photo_owner_command_entity:",
            "photo_command_receipt:",
        ] {
            let count = connection
                .query_row(
                    "SELECT COUNT(*) FROM deletion_preview_items
                     WHERE snapshot_token=?1 AND entity_id LIKE ?2",
                    params![
                        preview.preview_snapshot_token.as_str(),
                        format!("{prefix}%")
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            assert!(count > 0, "preview omitted {prefix}");
        }
        drop(connection);

        let request = execute_request(&preview);
        set_test_drain_fault(
            &request.request_id.to_string(),
            TestDrainFault {
                transient_failures: 0,
                interrupt_after_blob: true,
            },
        );
        assert!(matches!(
            database.execute_deletion(&request),
            Err(CatalogPortError {
                kind: CatalogPortErrorKind::Conflict,
                ..
            })
        ));
        let run_id: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT run_id FROM deletion_runs WHERE request_id=?1",
                [request.request_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(fs::symlink_metadata(&source_blob_path).is_err());
        drop(database);

        let restarted = Database::open(&paths, unix_now_ms().unwrap()).unwrap();
        let connection = restarted.connection().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM deletion_runs WHERE run_id=?1",
                    [&run_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "complete"
        );
        for table in [
            "photo_person_detection_runs",
            "photo_person_detection_attempts",
            "photo_owner_preview_references",
            "photo_owner_reviews",
            "photo_detection_corrections",
            "photo_person_instances",
            "photo_owner_decisions",
            "photo_owner_heads",
            "photo_owner_work_claims",
            "photo_observations",
            "photo_observation_owner_links",
            "photo_owner_command_entities",
        ] {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} left a relational residual");
        }
        for request_id in request_ids {
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM command_receipts WHERE request_id=?1",
                        [&request_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0,
                "owner command receipt survived"
            );
        }
        for id in response_ids {
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*)
                         FROM command_receipts receipt, json_tree(receipt.response_json) node
                         WHERE CAST(node.atom AS TEXT)=?1",
                        [&id],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0,
                "receipt JSON retained {id}"
            );
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM blobs WHERE sha256=?1",
                    [&source_blob],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert!(fs::symlink_metadata(&source_blob_path).is_err());
        assert!(fs::read_dir(&paths.deletion_trash)
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn hard_deletion_store_lock_restore_sanitization_rotates_authority() {
        let (temporary, paths, database) = test_database();
        let lock = StoreLock::acquire(&paths).unwrap();
        assert!(StoreLock::acquire(&paths).is_err());
        drop(lock);
        drop(StoreLock::acquire(&paths).unwrap());

        let source = import_png(&database, &temporary, "restore.png", [22, 33, 44]);
        let preview = preview_source(&database, &source);
        let before_epoch: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let backup = BackupRepository::new(&paths)
            .create(BackupReasonV1::Manual, unix_now_ms().unwrap())
            .unwrap();
        RestoreRepository::new(&paths)
            .prepare(
                backup.backup_id,
                &backup.manifest_sha256,
                unix_now_ms().unwrap(),
            )
            .unwrap();
        drop(database);
        let restored = Database::open(&paths, unix_now_ms().unwrap()).unwrap();
        let connection = restored.connection().unwrap();
        let after_epoch: String = connection
            .query_row(
                "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(before_epoch, after_epoch);
        let plan_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM deletion_plans WHERE snapshot_token=?1",
                [preview.preview_snapshot_token.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(0, plan_count);
        let transient: i64 = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM deletion_execution_authority)
                   +(SELECT COUNT(*) FROM deletion_runs WHERE state<>'complete')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(0, transient);
    }

    #[test]
    fn hard_deletion_compiled_sqlite_filesystem_restart_residual_smoke() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, unix_now_ms().unwrap()).unwrap();
        let root = temporary.path().join("root");
        std::fs::create_dir(&root).unwrap();
        write_png(&root.join("shared.png"), [70, 80, 90]);
        write_png(&root.join("unique.png"), [10, 20, 30]);
        let shared_copy = temporary.path().join("shared-copy.png");
        write_png(&shared_copy, [70, 80, 90]);
        let root_import = database
            .import_local_sources(&ImportLocalSourcesV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                paths: vec![root.to_string_lossy().into_owned()],
            })
            .unwrap();
        database
            .import_local_sources(&ImportLocalSourcesV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                paths: vec![shared_copy.to_string_lossy().into_owned()],
            })
            .unwrap();
        let root_id = root_import.summaries[0].import_root_id.unwrap().to_string();
        let connection = database.connection().unwrap();
        let shared_hash: String = connection
            .query_row(
                "SELECT blob_sha256 FROM local_sources
                 WHERE canonical_locator LIKE '%shared.png' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let unique_hash: String = connection
            .query_row(
                "SELECT blob_sha256 FROM local_sources
                 WHERE canonical_locator LIKE '%unique.png' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);
        let target_source: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT source_id FROM local_sources
                 WHERE canonical_locator LIKE '%shared.png' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        seed_try_on_transport(&database, &target_source, &shared_hash);
        BackupRepository::new(&paths)
            .create(BackupReasonV1::Manual, unix_now_ms().unwrap())
            .unwrap();
        let preview = database
            .preview_deletion(&PreviewDeletionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                target_kind: DeletionTargetKindV1::ImportRoot,
                target_id: root_id,
                limit: 100,
            })
            .unwrap();
        assert_eq!(1, preview.unique_blob_count);
        assert_eq!(1, preview.retained_shared_blob_count);
        assert!(!preview.backup_retention.is_empty());
        assert_eq!(1, preview.remote_retention.len());
        assert_eq!(
            DeletionRemoteRetentionStatusV1::ProviderDeletionUnavailable,
            preview.remote_retention[0].status
        );
        let request = execute_request(&preview);
        set_test_drain_fault(
            &request.request_id.to_string(),
            TestDrainFault {
                transient_failures: 0,
                interrupt_after_blob: true,
            },
        );
        assert!(database.execute_deletion(&request).is_err());
        let run_id: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT run_id FROM deletion_runs WHERE request_id=?1",
                [request.request_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let unique_path = BlobStore::new(&paths).path_for_hash(&unique_hash).unwrap();
        assert!(fs::symlink_metadata(&unique_path).is_err());
        assert!(paths
            .deletion_trash
            .join(&run_id)
            .join(&unique_hash)
            .is_file());
        drop(database);

        let restart = Database::open(&paths, unix_now_ms().unwrap()).unwrap();
        BlobStore::new(&paths).verify(&shared_hash).unwrap();
        assert!(fs::symlink_metadata(&unique_path).is_err());
        let connection = restart.connection().unwrap();
        let (state, response_json): (String, String) = connection
            .query_row(
                "SELECT run.state,receipt.response_json
                 FROM deletion_runs run
                 JOIN deletion_execution_receipts receipt ON receipt.run_id=run.run_id
                 WHERE run.run_id=?1",
                [&run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!("complete", state);
        let response: ExecuteDeletionV1Response = serde_json::from_str(&response_json).unwrap();
        response.validate().unwrap();
        assert!(!response.backup_retention.is_empty());
        assert_eq!(1, response.remote_retention.len());
        assert_eq!(
            DeletionRemoteRetentionStatusV1::ProviderDeletionUnavailable,
            response.remote_retention[0].status
        );
        let (shared_row, unique_row): (i64, i64) = connection
            .query_row(
                "SELECT
                   EXISTS(SELECT 1 FROM blobs WHERE sha256=?1),
                   EXISTS(SELECT 1 FROM blobs WHERE sha256=?2)",
                params![shared_hash, unique_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((shared_row, unique_row), (1, 0));
        let residual_trash_absent = fs::read_dir(&paths.deletion_trash)
            .unwrap()
            .next()
            .is_none();
        assert!(residual_trash_absent);
    }

    fn test_database() -> (TempDir, PrivateAppPaths, Database) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, unix_now_ms().unwrap()).unwrap();
        (temporary, paths, database)
    }

    fn seed_photokit_enrollment(database: &Database, key_reference: &str) -> PhotoKitEnrollment {
        let repository = PhotoKitRepository::new(database.clone());
        let pending = repository
            .reserve_enrollment(key_reference, false, unix_now_ms().unwrap())
            .unwrap();
        repository
            .activate_enrollment(
                &pending.enrollment_epoch,
                &PhotoKitRootKey::from_bytes([0x41; 32]),
                "test-private-album",
                unix_now_ms().unwrap(),
            )
            .unwrap()
    }

    fn seed_photokit_asset(database: &Database, enrollment_epoch: &str) -> String {
        let asset_id = Uuid::new_v4().hyphenated().to_string();
        let locator_id = Uuid::new_v4().hyphenated().to_string();
        let connection = database.connection().unwrap();
        connection
            .execute(
                "INSERT INTO photokit_locator_records(
                    locator_id,enrollment_epoch,operation_id,record_kind,
                    stable_row_id,key_version,lookup_hmac,nonce,ciphertext,
                    finalized,created_at_ms
                 ) VALUES(?1,?2,NULL,'asset',?3,1,randomblob(32),randomblob(24),
                          randomblob(17),1,?4)",
                params![
                    locator_id,
                    enrollment_epoch,
                    asset_id,
                    unix_now_ms().unwrap()
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO photokit_assets(
                    asset_id,enrollment_epoch,locator_id,created_at_ms
                 ) VALUES(?1,?2,?3,?4)",
                params![
                    asset_id,
                    enrollment_epoch,
                    locator_id,
                    unix_now_ms().unwrap()
                ],
            )
            .unwrap();
        asset_id
    }

    fn preview_photokit(
        database: &Database,
        target_kind: DeletionTargetKindV1,
        target_id: &str,
    ) -> PreviewDeletionV1Response {
        database
            .preview_deletion(&PreviewDeletionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                target_kind,
                target_id: target_id.to_owned(),
                limit: 100,
            })
            .unwrap()
    }

    fn write_png(path: &Path, color: [u8; 3]) {
        let mut bytes = Vec::new();
        DynamicImage::ImageRgb8(RgbImage::from_pixel(2, 2, Rgb(color)))
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn import_png(database: &Database, temporary: &TempDir, name: &str, color: [u8; 3]) -> String {
        let path = temporary.path().join(name);
        write_png(&path, color);
        database
            .import_local_sources(&ImportLocalSourcesV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                paths: vec![path.to_string_lossy().into_owned()],
            })
            .unwrap()
            .summaries[0]
            .source_id
            .unwrap()
            .to_string()
    }

    fn create_p04_scope(database: &Database, source_id: &str) -> PhotoScopeId {
        let root_id: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT root_id FROM local_sources WHERE source_id=?1",
                [source_id],
                |row| row.get(0),
            )
            .unwrap();
        let root = database
            .list_imported_photo_roots(&ListImportedPhotoRootsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                cursor: None,
                limit: 100,
            })
            .unwrap()
            .roots
            .into_iter()
            .find(|root| root.import_root_id.to_string() == root_id)
            .unwrap();
        database
            .create_photo_scope(&CreatePhotoScopeV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                import_root_id: root.import_root_id,
                expected_manifest_generation: root.manifest_generation,
            })
            .unwrap()
            .scope
            .scope_id
    }

    fn preview_source(database: &Database, source_id: &str) -> PreviewDeletionV1Response {
        database
            .preview_deletion(&PreviewDeletionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                target_kind: DeletionTargetKindV1::Source,
                target_id: source_id.to_owned(),
                limit: 100,
            })
            .unwrap()
    }

    fn execute_request(preview: &PreviewDeletionV1Response) -> ExecuteDeletionV1Request {
        ExecuteDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            preview_snapshot_token: preview.preview_snapshot_token.clone(),
            plan_sha256: preview.plan_sha256.clone(),
            expected_revisions: preview.revisions.clone(),
            confirmation: DeletionConfirmationV1::DeleteActiveLocalData,
        }
    }

    fn seed_try_on_transport(database: &Database, source_id: &str, blob_sha256: &str) {
        let connection = database.connection().unwrap();
        let now_ms = unix_now_ms().unwrap();
        let approval_id = Uuid::new_v4().to_string();
        let preview_request_id = Uuid::new_v4().to_string();
        let submit_request_id = Uuid::new_v4().to_string();
        let job_id = Uuid::new_v4().to_string();
        let attempt_id = Uuid::new_v4().to_string();
        for request_id in [&preview_request_id, &submit_request_id] {
            connection
                .execute(
                    "INSERT INTO command_receipts(
                        request_id,command_name,envelope_hash,response_json,created_at_ms)
                     VALUES(?1,'try_on_test',?2,'{}',?3)",
                    params![request_id, "1".repeat(64), now_ms],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO try_on_approvals(
                    approval_id,preview_request_id,envelope_hash,outfit_id,outfit_name,
                    outfit_created_revision,expected_outfit_revision,credential_id,
                    provider,model,prompt_revision,disclosure_revision,retention_mode,
                    retention_provenance,asset_snapshot_sha256,garment_count,
                    expires_at_ms,created_at_ms)
                 VALUES(?1,?2,?3,?4,'Test outfit',1,0,'test-credential',
                    'openai','gpt-image-2','prompt-v1','disclosure-v1','default',
                    'test.project.default',?3,2,?5,?6)",
                params![
                    approval_id,
                    preview_request_id,
                    "2".repeat(64),
                    Uuid::new_v4().to_string(),
                    now_ms + 60_000,
                    now_ms,
                ],
            )
            .unwrap();
        let blob_length: i64 = connection
            .query_row(
                "SELECT byte_length FROM blobs WHERE sha256=?1",
                [blob_sha256],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO try_on_assets(
                    approval_id,asset_ordinal,role,item_id,evidence_id,source_id,
                    item_updated_revision,attributes_json,parent_blob_sha256,
                    parent_media_type,parent_byte_length,parent_width,parent_height,
                    canonical_png_sha256,canonical_byte_length,canonical_width,canonical_height)
                 VALUES(?1,1,'garment',?2,?3,?4,1,'{}',?5,'image/png',?6,2,2,
                    ?5,?6,2,2)",
                params![
                    approval_id,
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string(),
                    source_id,
                    blob_sha256,
                    blob_length,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO try_on_jobs(
                    job_id,request_id,approval_id,envelope_hash,pipeline_revision,state,
                    available_at_ms,attempt_count,retry_limit,fence,created_at_ms,updated_at_ms)
                 VALUES(?1,?2,?3,?4,'pipeline-v1','queued',?5,0,0,0,?5,?5)",
                params![
                    job_id,
                    submit_request_id,
                    approval_id,
                    "3".repeat(64),
                    now_ms,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO try_on_attempts(
                    attempt_id,job_id,attempt_ordinal,fence,state,audit_json,
                    retryable,created_at_ms,updated_at_ms)
                 VALUES(?1,?2,1,1,'dispatched',json_object(
                    'transport_started_at_ms',?3),0,?3,?3)",
                params![attempt_id, job_id, now_ms],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE revision_state SET try_on_revision=try_on_revision+1 WHERE singleton=1",
                [],
            )
            .unwrap();
    }

    fn seed_outfit_recommendation_transport(database: &Database, item_id: &str) {
        let connection = database.connection().unwrap();
        let now_ms = unix_now_ms().unwrap();
        let approval_id = Uuid::new_v4().to_string();
        let attempt_id = Uuid::new_v4().to_string();
        let preview_request_id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO command_receipts(
                    request_id,command_name,envelope_hash,response_json,created_at_ms)
                 VALUES(?1,'outfit_recommendation_test',?2,'{}',?3)",
                params![preview_request_id, "4".repeat(64), now_ms],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO catalog_items(
                    item_id,display_name,attributes_json,active,
                    created_revision,updated_revision)
                 VALUES(?1,'Test item','{}',1,1,1)",
                [item_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outfit_recommendation_approvals(
                    approval_id,preview_request_id,request_hash,credential_id,
                    catalog_revision,outfit_revision,retention_mode,retention_provenance,
                    disclosure_revision,expires_at_ms,created_at_ms)
                 VALUES(?1,?2,?3,'test-credential',1,0,'default',
                    'test.project.default','disclosure-v1',?4,?5)",
                params![
                    approval_id,
                    preview_request_id,
                    "5".repeat(64),
                    now_ms + 60_000,
                    now_ms,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outfit_recommendation_attempts(
                    attempt_id,request_id,approval_id,request_hash,credential_id,state,
                    catalog_revision,outfit_revision,input_hash,tool_snapshot_hash,
                    provider,model,prompt_revision,schema_revision,compatibility_revision,
                    retention_mode,retention_provenance,created_at_ms,transport_started_at_ms)
                 VALUES(?1,?2,?3,?4,'test-credential','reserved',1,0,?5,?6,
                    'openai','gpt-5.2','prompt-v1','schema-v1','compat-v1',
                    'default','test.project.default',?7,?7)",
                params![
                    attempt_id,
                    Uuid::new_v4().to_string(),
                    approval_id,
                    "6".repeat(64),
                    "7".repeat(64),
                    "8".repeat(64),
                    now_ms,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outfit_recommendation_proposals(
                    attempt_id,ordinal,proposal_name)
                 VALUES(?1,0,'Test proposal')",
                [&attempt_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outfit_recommendation_members(
                    attempt_id,proposal_ordinal,member_ordinal,item_id)
                 VALUES(?1,0,0,?2)",
                params![attempt_id, item_id],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE revision_state
                 SET catalog_revision=catalog_revision+1,outfit_revision=outfit_revision+1
                 WHERE singleton=1",
                [],
            )
            .unwrap();
    }

    fn simulate_crash_after_relational_commit(
        database: &Database,
        request: &ExecuteDeletionV1Request,
    ) -> String {
        let now_ms = unix_now_ms().unwrap();
        let request_json = serde_json::to_string(request).unwrap();
        let envelope_hash = format!("{:x}", Sha256::digest(request_json.as_bytes()));
        let run_id = Uuid::new_v4().to_string();
        let mut connection = database.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let epoch: String = transaction
            .query_row(
                "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let (plan_sha256, unique_count, unique_bytes, shared_count): (String, i64, i64, i64) =
            transaction
                .query_row(
                    "SELECT plan_sha256,unique_blob_count,unique_blob_bytes,
                        retained_shared_blob_count
                 FROM deletion_plans WHERE snapshot_token=?1",
                    [request.preview_snapshot_token.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
        let entries =
            load_plan_entries(&transaction, request.preview_snapshot_token.as_str()).unwrap();
        let record_count = entries
            .iter()
            .filter(|entry| entry.entity_kind != DeletionEntityKind::Blobs)
            .count() as i64;
        transaction
            .execute(
                "INSERT INTO deletion_runs(
                    run_id,epoch,snapshot_token,request_id,request_json,envelope_hash,
                    plan_sha256,state,accepted_at_ms,deadline_at_ms,deleted_record_count,
                    deleted_blob_count,deleted_blob_bytes,retained_shared_blob_count)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,'in_progress',?8,?9,?10,?11,?12,?13)",
                params![
                    run_id,
                    epoch,
                    request.preview_snapshot_token.as_str(),
                    request.request_id.to_string(),
                    request_json,
                    envelope_hash,
                    plan_sha256,
                    now_ms,
                    now_ms + EXECUTION_DEADLINE_MS,
                    record_count,
                    unique_count,
                    unique_bytes,
                    shared_count,
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO deletion_run_backup_retention
                 SELECT ?1,ordinal,backup_id,reason,expires_at_ms
                 FROM deletion_plan_backup_retention WHERE snapshot_token=?2",
                params![run_id, request.preview_snapshot_token.as_str()],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO deletion_run_remote_retention
                 SELECT ?1,ordinal,provider,purpose,retention_mode,retention_provenance,
                        dispatched_at_ms,policy_expires_at_ms,status
                 FROM deletion_plan_remote_retention WHERE snapshot_token=?2",
                params![run_id, request.preview_snapshot_token.as_str()],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO deletion_run_blobs(run_id,epoch,sha256,byte_length)
                 SELECT ?1,?2,json_extract(entry.key_json,'$[0]'),blob.byte_length
                 FROM deletion_plan_entries entry
                 JOIN blobs blob ON blob.sha256=json_extract(entry.key_json,'$[0]')
                 WHERE entry.snapshot_token=?3 AND entry.entity_kind='blobs'",
                params![run_id, epoch, request.preview_snapshot_token.as_str()],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO deletion_execution_authority(singleton,epoch,run_id,snapshot_token)
                 VALUES(1,?1,?2,?3)",
                params![epoch, run_id, request.preview_snapshot_token.as_str()],
            )
            .unwrap();
        for entry in entries {
            let spec = delete_spec_for(entry.entity_kind.as_str()).unwrap();
            assert_eq!(1, transaction.execute(spec.sql, [entry.key_json]).unwrap());
        }
        transaction
            .execute("DELETE FROM deletion_execution_authority", [])
            .unwrap();
        transaction.commit().unwrap();
        let manifest_hash: String = database
            .connection()
            .unwrap()
            .query_row(
                "SELECT sha256 FROM deletion_run_blobs WHERE run_id=?1",
                [&run_id],
                |row| row.get(0),
            )
            .unwrap();
        let active = BlobStore::new(&database.paths)
            .path_for_hash(&manifest_hash)
            .unwrap();
        let run_directory = database.paths.deletion_trash.join(&run_id);
        create_private_directory(&run_directory).unwrap();
        let trash = run_directory.join(&manifest_hash);
        fs::rename(&active, &trash).unwrap();
        sync_directory(active.parent().unwrap()).unwrap();
        sync_directory(&run_directory).unwrap();
        run_id
    }
}
