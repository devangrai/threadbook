mod backup_repository;
mod blob;
mod catalog_repository;
mod credential;
mod database;
mod deletion_repository;
mod diagnostics;
mod diagnostics_export;
mod error;
mod gmail_connector;
mod gmail_http;
#[allow(clippy::too_many_arguments)]
mod gmail_repository;
mod gmail_sync;
mod imports;
mod local_only;
mod maintenance;
mod outfit_recommendation_http;
mod outfit_recommendation_provider;
mod outfit_recommendation_repository;
mod outfit_recommender;
mod outfit_repository;
mod paths;
mod person_detection_native;
mod person_repository;
mod photo_repository;
mod photokit_connector_runtime;
mod photokit_coordinator;
mod photokit_keychain;
mod photokit_native;
mod photokit_repository;
mod receipt_image_downloader;
#[allow(clippy::needless_borrow, clippy::too_many_arguments)]
mod receipt_parser;
mod receipt_provider;
mod receipt_repository;
mod reconciliation_repository;
mod restore_repository;
mod source_image;
mod try_on_http;
mod try_on_renderer;
mod try_on_repository;
mod update_package;
mod worker;

pub use backup_repository::{
    BackupReason, BackupRecord, BackupRepository, VerifiedBackup, BACKUP_FORMAT_VERSION,
};
pub use blob::{
    BlobRecord, BlobStore, PreparedBlob, UnknownLengthBlobLimits, UnknownLengthBlobSession,
    UnknownLengthBlobSink,
};
pub use credential::MacOsKeychain;
pub use database::{
    CredentialRecord, Database, DatabaseCompatibility, FoundationCounts, FoundationSnapshot,
    JobSnapshot, StorageCheckOutcome,
};
pub use diagnostics::JsonlDiagnostics;
pub use diagnostics_export::DiagnosticsExporter;
pub use error::{PlatformError, PlatformResult};
pub use gmail_connector::{
    GmailCredentialStore, GmailDisconnectCompletion, ProductionGmailConnector,
};
pub use gmail_http::*;
pub use gmail_sync::*;
pub use local_only::{
    LocalOnlyModeSnapshot, LocalOnlyModeStore, LocalOnlyStoreError, LocalOnlyStoreResult,
};
pub use maintenance::{
    ExclusiveMaintenancePermit, MaintenanceCoordinator, SharedMaintenancePermit, StoreLock,
};
pub use outfit_recommendation_http::*;
pub use outfit_recommendation_provider::*;
pub use outfit_recommendation_repository::*;
pub use outfit_recommender::*;
pub use paths::PrivateAppPaths;
pub use person_detection_native::MacOsVisionPersonDetectionProviderV1;
pub use photokit_connector_runtime::ProductionPhotoKitConnector;
pub use photokit_coordinator::*;
pub use photokit_keychain::*;
pub use photokit_native::*;
pub use photokit_repository::*;
pub use receipt_image_downloader::*;
pub use receipt_parser::{
    parse_receipt_bundle_v1, parse_receipt_v1, verify_citation_v1, ParsedReceiptBundleV1,
    ReceiptImageCandidateEligibilityV1, ReceiptImageCandidateInputV1, ReceiptParseError,
    ReceiptParserV1,
};
pub use receipt_provider::LocalDeterministicReceiptProviderV1;
pub use restore_repository::{PrepareRestoreResult, RestoreRepository};
pub use try_on_http::*;
pub use try_on_renderer::*;
pub use try_on_repository::*;
pub use update_package::*;
pub use worker::{PlatformJobQueue, RunOutcome, VerifyBlobWorker};
