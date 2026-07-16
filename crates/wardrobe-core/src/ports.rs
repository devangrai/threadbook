use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;

use crate::{
    AnalyzePhotoScopeV1Request, AnalyzePhotoScopeV1Response, AnalyzeReceiptV1Request,
    AnalyzeReceiptV1Response, ApproveAndFetchReceiptImageV1Request,
    ApproveAndFetchReceiptImageV1Response, BeginPhotoKitSetupV1Request,
    BeginPhotoKitSetupV1Response, ConfigurePhotoKitScopeV1Request,
    ConfigurePhotoKitScopeV1Response, CorrectPhotoOwnerV1Request, CorrectPhotoOwnerV1Response,
    CorrectPhotoPersonDetectionV1Request, CorrectPhotoPersonDetectionV1Response,
    CreateManualOutfitV1Request, CreateManualOutfitV1Response, CreatePhotoScopeV1Request,
    CreatePhotoScopeV1Response, CredentialId, CredentialProviderV1, CredentialReferenceV1,
    DecideEvidenceV1Request, DecideEvidenceV1Response, DecidePhotoOwnerV1Request,
    DecidePhotoOwnerV1Response, DecideReconciliationCaseV1Request,
    DecideReconciliationCaseV1Response, DecideReconciliationCaseV2Request,
    DecideReconciliationCaseV2Response, DetectPhotoScopePeopleV1Request,
    DetectPhotoScopePeopleV1Response, DiagnosticEventV1, DisablePhotoKitV1Request,
    DisablePhotoKitV1Response, ErrorCodeV1, FoundationVersionsV1, GetOutfitCollageV1Request,
    GetOutfitCollageV1Response, GetPhotoKitConnectorV1Request, GetPhotoKitConnectorV1Response,
    ImportLocalSourcesV1Request, ImportLocalSourcesV1Response, JobId, JobKindV1, JobSnapshotV1,
    ListCatalogV1Request, ListCatalogV1Response, ListDeletionPlanItemsV1Request,
    ListDeletionPlanItemsV1Response, ListImportedPhotoRootsV1Request,
    ListImportedPhotoRootsV1Response, ListInboxV1Request, ListInboxV1Response,
    ListOutfitsV1Request, ListOutfitsV1Response, ListPhotoObservationsV1Request,
    ListPhotoObservationsV1Response, ListPhotoOwnerReviewsV1Request,
    ListPhotoOwnerReviewsV1Response, ListReceiptImageCandidatesV1Request,
    ListReceiptImageCandidatesV1Response, ListReceiptsV1Request, ListReceiptsV1Response,
    ListReconciliationCasesV2Request, ListReconciliationCasesV2Response, LocalSettingsSnapshotV1,
    MergeItemsV1Request, MergeItemsV1Response, OpenReconciliationCaseV1Request,
    OpenReconciliationCaseV1Response, OpenReconciliationCaseV2Request,
    OpenReconciliationCaseV2Response, ParsedReceiptEvidenceV1, PersonDetectionOutcomeV1,
    PersonDetectionProviderDescriptorV1, PersonDetectionRequestV1, PhotoKitReconcileTriggerV1,
    PreviewDeletionV1Request, PreviewDeletionV1Response, PromptPhotoObservationV1Request,
    PromptPhotoObservationV1Response, ReadPhotoArtifactV1Request, ReadPhotoArtifactV1Response,
    ReadPhotoOwnerPreviewV1Request, ReadPhotoOwnerPreviewV1Response, ReceiptExtractionEnvelopeV1,
    ReceiptImageAttemptId, ReceiptImageFailureCodeV1, ReceiptReviewHeadV1,
    RefreshImportRootsV1Request, RefreshImportRootsV1Response, ReplayStatusV1, RequestId,
    RetryPhotoPersonDetectionV1Request, RetryPhotoPersonDetectionV1Response,
    ReviewPhotoObservationV1Request, ReviewPhotoObservationV1Response, ReviewReceiptV1Request,
    ReviewReceiptV1Response, SaveItemV1Request, SaveItemV1Response, SecretString,
    SegmentationCapabilityV1, SegmentationOutcomeV1, SegmentationProviderDescriptorV1,
    SegmentationRequestV1, SegmentationUnavailableReasonV1, SplitItemV1Request,
    SplitItemV1Response, StorageCheckId, SyncPhotoKitV1Request, SyncPhotoKitV1Response,
    UndoDecisionV1Request, UndoDecisionV1Response, UserActionKeyV1, Validate,
    GARMENT_SEGMENTATION_CONTRACT_V1, PHOTO_PREPROCESSING_REVISION_V1,
    UNAVAILABLE_SEGMENTATION_PROVIDER_ID_V1, UNAVAILABLE_SEGMENTATION_PROVIDER_REVISION_V1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortErrorKind {
    Unavailable,
    Conflict,
    PermissionDenied,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortError {
    pub kind: PortErrorKind,
}

impl PortError {
    pub const fn new(kind: PortErrorKind) -> Self {
        Self { kind }
    }
}

pub type PortResult<T> = Result<T, PortError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogPortErrorKind {
    Unavailable,
    Conflict,
    SnapshotExpired,
    InvalidState,
    PermissionDenied,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogPortError {
    pub kind: CatalogPortErrorKind,
}

impl CatalogPortError {
    pub const fn new(kind: CatalogPortErrorKind) -> Self {
        Self { kind }
    }
}

pub type CatalogPortResult<T> = Result<T, CatalogPortError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptPortErrorKind {
    Unavailable,
    Conflict,
    SnapshotExpired,
    InvalidState,
    PermissionDenied,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptPortError {
    pub kind: ReceiptPortErrorKind,
}

impl ReceiptPortError {
    pub const fn new(kind: ReceiptPortErrorKind) -> Self {
        Self { kind }
    }
}

pub type ReceiptPortResult<T> = Result<T, ReceiptPortError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptProviderErrorKind {
    Unavailable,
    MalformedOutput,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptProviderError {
    pub kind: ReceiptProviderErrorKind,
}

impl ReceiptProviderError {
    pub const fn new(kind: ReceiptProviderErrorKind) -> Self {
        Self { kind }
    }
}

pub type ReceiptProviderResult<T> = Result<T, ReceiptProviderError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhotoAnalysisPortErrorKind {
    Unavailable,
    Conflict,
    SnapshotExpired,
    InvalidState,
    PermissionDenied,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhotoAnalysisPortError {
    pub kind: PhotoAnalysisPortErrorKind,
}

impl PhotoAnalysisPortError {
    pub const fn new(kind: PhotoAnalysisPortErrorKind) -> Self {
        Self { kind }
    }
}

pub type PhotoAnalysisPortResult<T> = Result<T, PhotoAnalysisPortError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationPortErrorKind {
    Unavailable,
    Conflict,
    SnapshotExpired,
    InvalidState,
    PermissionDenied,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationPortError {
    pub kind: ReconciliationPortErrorKind,
}

impl ReconciliationPortError {
    pub const fn new(kind: ReconciliationPortErrorKind) -> Self {
        Self { kind }
    }
}

pub type ReconciliationPortResult<T> = Result<T, ReconciliationPortError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhotoKitConnectorPortErrorKind {
    Unavailable,
    Conflict,
    Busy,
    InvalidState,
    PermissionDenied,
    CredentialUnavailable,
    ScopeTooLarge,
    SessionExpired,
    SelectionTokenConsumed,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhotoKitConnectorPortError {
    pub kind: PhotoKitConnectorPortErrorKind,
}

impl PhotoKitConnectorPortError {
    pub const fn new(kind: PhotoKitConnectorPortErrorKind) -> Self {
        Self { kind }
    }
}

pub type PhotoKitConnectorPortResult<T> = Result<T, PhotoKitConnectorPortError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutfitPortErrorKind {
    Unavailable,
    Conflict,
    SnapshotExpired,
    InvalidState,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutfitPortError {
    pub kind: OutfitPortErrorKind,
}

impl OutfitPortError {
    pub const fn new(kind: OutfitPortErrorKind) -> Self {
        Self { kind }
    }
}

pub type OutfitPortResult<T> = Result<T, OutfitPortError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentationProviderErrorKind {
    InvalidRequest,
    MalformedOutput,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentationProviderError {
    pub kind: SegmentationProviderErrorKind,
}

impl SegmentationProviderError {
    pub const fn new(kind: SegmentationProviderErrorKind) -> Self {
        Self { kind }
    }
}

pub type SegmentationProviderResult<T> = Result<T, SegmentationProviderError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersonDetectionProviderErrorKind {
    InvalidRequest,
    MalformedOutput,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonDetectionProviderError {
    pub kind: PersonDetectionProviderErrorKind,
}

impl PersonDetectionProviderError {
    pub const fn new(kind: PersonDetectionProviderErrorKind) -> Self {
        Self { kind }
    }
}

pub type PersonDetectionProviderResult<T> = Result<T, PersonDetectionProviderError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptAnalysisFailureV1 {
    ProviderUnavailable,
    ProviderMalformedOutput,
    ProviderInternal,
    OutputValidationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ReceiptAnalysisPlanV1 {
    Replay(AnalyzeReceiptV1Response),
    ReplayFailure(ReceiptAnalysisFailureV1),
    Extract {
        parsed: ParsedReceiptEvidenceV1,
        preserved_review_head: Option<ReceiptReviewHeadV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptImageHopProvenanceV1 {
    pub ordinal: u8,
    pub host_sha256: Sha256Digest,
    pub url_sha256: Sha256Digest,
    pub pinned_addresses: Vec<String>,
    pub http_status: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptImageDownloadV1 {
    pub source_bytes: Vec<u8>,
    pub source_sha256: Sha256Digest,
    pub source_media_type: String,
    pub display_png_bytes: Vec<u8>,
    pub display_sha256: Sha256Digest,
    pub width: u32,
    pub height: u32,
    pub final_url_sha256: Sha256Digest,
    pub declared_length: Option<u64>,
    pub hops: Vec<ReceiptImageHopProvenanceV1>,
    pub policy_revision: String,
    pub decoder_revision: String,
    pub derivative_revision: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptImageAttemptPlanV1 {
    Replay(ApproveAndFetchReceiptImageV1Response),
    Download {
        attempt_id: ReceiptImageAttemptId,
        download_token: String,
        normalized_url: String,
        approved_display_host: String,
    },
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("SHA-256 digest must be 64 lowercase hexadecimal characters");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobRecordV1 {
    pub digest: Sha256Digest,
    pub byte_length: u64,
}

pub trait BlobPort {
    fn put_verified(
        &self,
        expected_digest: &Sha256Digest,
        bytes: &[u8],
        max_bytes: u64,
    ) -> PortResult<BlobRecordV1>;

    fn verify(&self, expected: &BlobRecordV1) -> PortResult<()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoundationStateV1 {
    pub versions: FoundationVersionsV1,
    pub local_settings: LocalSettingsSnapshotV1,
    pub credential_references: Vec<CredentialReferenceV1>,
    pub recent_jobs: Vec<JobSnapshotV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageCheckRecordV1 {
    pub check_id: StorageCheckId,
    pub job_id: JobId,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialLocator(String);

impl CredentialLocator {
    pub fn new(value: String) -> Result<Self, &'static str> {
        if value.is_empty()
            || value.len() > 128
            || !value.is_ascii()
            || value.chars().any(char::is_control)
        {
            return Err("credential locator must be bounded printable ASCII");
        }
        Ok(Self(value))
    }

    pub fn expose_locator(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialLocator([OPAQUE])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SaveCredentialPlanV1 {
    WriteSecret {
        locator: CredentialLocator,
        pending_reference: CredentialReferenceV1,
    },
    Replay {
        reference: CredentialReferenceV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeleteCredentialPlanV1 {
    DeleteSecret {
        locator: CredentialLocator,
        credential_id: CredentialId,
    },
    Replay {
        credential_id: CredentialId,
        deleted: bool,
    },
}

pub trait DatabasePort {
    fn load_foundation_state(&self, recent_jobs_limit: usize) -> PortResult<FoundationStateV1>;

    // Implementations commit the check, job, dependencies, retry policy, and receipt atomically.
    fn record_storage_check_and_enqueue(
        &self,
        request_id: RequestId,
        blob: &BlobRecordV1,
    ) -> PortResult<StorageCheckRecordV1>;

    fn reserve_credential_save(
        &self,
        request_id: RequestId,
        provider: CredentialProviderV1,
        display_label: &str,
    ) -> PortResult<SaveCredentialPlanV1>;

    fn activate_credential(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PortResult<CredentialReferenceV1>;

    fn prepare_credential_delete(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PortResult<DeleteCredentialPlanV1>;

    fn finish_credential_delete(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PortResult<()>;
}

pub trait CatalogPort {
    fn import_local_sources(
        &self,
        request: &ImportLocalSourcesV1Request,
    ) -> CatalogPortResult<ImportLocalSourcesV1Response>;

    fn refresh_import_roots(
        &self,
        request: &RefreshImportRootsV1Request,
    ) -> CatalogPortResult<RefreshImportRootsV1Response>;

    fn list_catalog(
        &self,
        request: &ListCatalogV1Request,
    ) -> CatalogPortResult<ListCatalogV1Response>;

    fn list_inbox(&self, request: &ListInboxV1Request) -> CatalogPortResult<ListInboxV1Response>;

    // Implementations perform the CAS update, projection write, decision append, and receipt
    // persistence in one transaction. Exact request replay returns the persisted response.
    fn save_item_and_append_decision(
        &self,
        request: &SaveItemV1Request,
    ) -> CatalogPortResult<SaveItemV1Response>;

    fn decide_evidence_and_append_decision(
        &self,
        request: &DecideEvidenceV1Request,
    ) -> CatalogPortResult<DecideEvidenceV1Response>;

    fn merge_items_and_append_decision(
        &self,
        request: &MergeItemsV1Request,
    ) -> CatalogPortResult<MergeItemsV1Response>;

    fn split_item_and_append_decision(
        &self,
        request: &SplitItemV1Request,
    ) -> CatalogPortResult<SplitItemV1Response>;

    // Undo is a new append-only decision that compensates the referenced decision.
    fn append_compensating_undo(
        &self,
        request: &UndoDecisionV1Request,
    ) -> CatalogPortResult<UndoDecisionV1Response>;

    fn preview_deletion(
        &self,
        request: &PreviewDeletionV1Request,
    ) -> CatalogPortResult<PreviewDeletionV1Response>;

    fn list_deletion_plan_items(
        &self,
        request: &ListDeletionPlanItemsV1Request,
    ) -> CatalogPortResult<ListDeletionPlanItemsV1Response>;
}

pub trait DeletionPort {
    // Implementations atomically consume the exact frozen plan. Success is returned only after
    // active relational and unique-blob deletion is complete.
    fn execute_deletion(
        &self,
        request: &crate::ExecuteDeletionV1Request,
    ) -> CatalogPortResult<crate::ExecuteDeletionV1Response>;
}

pub trait ReceiptPort {
    fn list_receipts(
        &self,
        request: &ListReceiptsV1Request,
    ) -> ReceiptPortResult<ListReceiptsV1Response>;

    // Implementations return a stored exact-envelope replay or a validated immutable parse.
    fn prepare_receipt_analysis(
        &self,
        request: &AnalyzeReceiptV1Request,
    ) -> ReceiptPortResult<ReceiptAnalysisPlanV1>;

    // Implementations atomically finish the run and complete order graph, preserve the guarded
    // review head, and persist the exact response receipt. Changed envelopes conflict.
    fn commit_receipt_analysis(
        &self,
        request: &AnalyzeReceiptV1Request,
        parsed: &ParsedReceiptEvidenceV1,
        envelope: &ReceiptExtractionEnvelopeV1,
        preserved_review_head: Option<&ReceiptReviewHeadV1>,
    ) -> ReceiptPortResult<AnalyzeReceiptV1Response>;

    // Implementations atomically persist one failed extraction run linked to the exact request
    // envelope and committed parse. Exact replay returns the stored classification, a changed
    // envelope conflicts, error classification is allowlisted, and no order, line, variant,
    // field, or citation row is written.
    fn record_receipt_analysis_failure(
        &self,
        request: &AnalyzeReceiptV1Request,
        parsed: &ParsedReceiptEvidenceV1,
        failure: ReceiptAnalysisFailureV1,
    ) -> ReceiptPortResult<ReceiptAnalysisFailureV1>;

    // Implementations perform CAS, append one immutable decision, update the head, increment the
    // receipt revision once, and persist the exact response in one transaction.
    fn review_receipt_and_append_decision(
        &self,
        request: &ReviewReceiptV1Request,
    ) -> ReceiptPortResult<ReviewReceiptV1Response>;

    fn list_receipt_image_candidates(
        &self,
        _request: &ListReceiptImageCandidatesV1Request,
    ) -> ReceiptPortResult<ListReceiptImageCandidatesV1Response> {
        Err(ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }

    fn prepare_image_attempt(
        &self,
        _request: &ApproveAndFetchReceiptImageV1Request,
    ) -> ReceiptPortResult<ReceiptImageAttemptPlanV1> {
        Err(ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }

    fn finalize_image_attempt(
        &self,
        _request: &ApproveAndFetchReceiptImageV1Request,
        _attempt_id: ReceiptImageAttemptId,
        _download_token: &str,
        _result: Result<ReceiptImageDownloadV1, ReceiptImageFailureCodeV1>,
    ) -> ReceiptPortResult<ApproveAndFetchReceiptImageV1Response> {
        Err(ReceiptPortError::new(ReceiptPortErrorKind::Internal))
    }
}

pub trait ReceiptEvidenceProvider {
    fn extract(
        &self,
        parsed: &ParsedReceiptEvidenceV1,
    ) -> ReceiptProviderResult<ReceiptExtractionEnvelopeV1>;
}

pub trait ReceiptImageDownloader {
    fn download(
        &self,
        normalized_url: String,
        approved_display_host: String,
    ) -> impl std::future::Future<Output = Result<ReceiptImageDownloadV1, ReceiptImageFailureCodeV1>>
           + Send;
}

pub trait PhotoAnalysisPort {
    fn list_imported_photo_roots(
        &self,
        request: &ListImportedPhotoRootsV1Request,
    ) -> PhotoAnalysisPortResult<ListImportedPhotoRootsV1Response>;

    // Implementations freeze the current completed generation and persist the exact command
    // receipt atomically. A changed envelope using the same request ID must conflict.
    fn create_photo_scope(
        &self,
        request: &CreatePhotoScopeV1Request,
    ) -> PhotoAnalysisPortResult<CreatePhotoScopeV1Response>;

    // Implementations may invoke the provider only for immutable eligible scope members. The
    // supplied provider validates every request and outcome at the core boundary.
    fn analyze_photo_scope(
        &self,
        request: &AnalyzePhotoScopeV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PhotoAnalysisPortResult<AnalyzePhotoScopeV1Response>;

    // Implementations claim and publish person-detection attempts under their storage fence.
    // Provider execution occurs outside storage transactions.
    fn detect_photo_scope_people(
        &self,
        _request: &DetectPhotoScopePeopleV1Request,
        _provider: &dyn LocalPersonDetectionProviderV1,
    ) -> PhotoAnalysisPortResult<DetectPhotoScopePeopleV1Response> {
        Err(PhotoAnalysisPortError::new(
            PhotoAnalysisPortErrorKind::Internal,
        ))
    }

    fn list_photo_observations(
        &self,
        request: &ListPhotoObservationsV1Request,
    ) -> PhotoAnalysisPortResult<ListPhotoObservationsV1Response>;

    // Reads return authorized bounded bytes only. Implementations must not expose paths or
    // locators and must re-verify the parent source blob before returning.
    fn read_photo_artifact(
        &self,
        request: &ReadPhotoArtifactV1Request,
    ) -> PhotoAnalysisPortResult<ReadPhotoArtifactV1Response>;

    fn prompt_photo_observation(
        &self,
        request: &PromptPhotoObservationV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PhotoAnalysisPortResult<PromptPhotoObservationV1Response>;

    // Implementations perform the review CAS, append the immutable user decision, update the
    // review head, and persist the exact response in one transaction. Automated work may append
    // evidence but must never replace or remove this head.
    fn review_photo_observation(
        &self,
        request: &ReviewPhotoObservationV1Request,
    ) -> PhotoAnalysisPortResult<ReviewPhotoObservationV1Response>;

    fn list_photo_owner_reviews(
        &self,
        _request: &ListPhotoOwnerReviewsV1Request,
    ) -> PhotoAnalysisPortResult<ListPhotoOwnerReviewsV1Response> {
        Err(PhotoAnalysisPortError::new(
            PhotoAnalysisPortErrorKind::Internal,
        ))
    }

    fn read_photo_owner_preview(
        &self,
        _request: &ReadPhotoOwnerPreviewV1Request,
    ) -> PhotoAnalysisPortResult<ReadPhotoOwnerPreviewV1Response> {
        Err(PhotoAnalysisPortError::new(
            PhotoAnalysisPortErrorKind::Internal,
        ))
    }

    fn decide_photo_owner(
        &self,
        _request: &DecidePhotoOwnerV1Request,
    ) -> PhotoAnalysisPortResult<DecidePhotoOwnerV1Response> {
        Err(PhotoAnalysisPortError::new(
            PhotoAnalysisPortErrorKind::Internal,
        ))
    }

    fn correct_photo_owner(
        &self,
        _request: &CorrectPhotoOwnerV1Request,
    ) -> PhotoAnalysisPortResult<CorrectPhotoOwnerV1Response> {
        Err(PhotoAnalysisPortError::new(
            PhotoAnalysisPortErrorKind::Internal,
        ))
    }

    fn correct_photo_person_detection(
        &self,
        _request: &CorrectPhotoPersonDetectionV1Request,
    ) -> PhotoAnalysisPortResult<CorrectPhotoPersonDetectionV1Response> {
        Err(PhotoAnalysisPortError::new(
            PhotoAnalysisPortErrorKind::Internal,
        ))
    }

    fn retry_photo_person_detection(
        &self,
        _request: &RetryPhotoPersonDetectionV1Request,
    ) -> PhotoAnalysisPortResult<RetryPhotoPersonDetectionV1Response> {
        Err(PhotoAnalysisPortError::new(
            PhotoAnalysisPortErrorKind::Internal,
        ))
    }
}

pub trait ReconciliationPort {
    // Implementations validate the pinned P04 review state, snapshot bounded local candidates,
    // and atomically persist one complete case and exact command receipt.
    fn open_reconciliation_case(
        &self,
        request: &OpenReconciliationCaseV1Request,
    ) -> ReconciliationPortResult<OpenReconciliationCaseV1Response>;

    // Implementations perform CAS, append one immutable user decision, update the decision head,
    // advance the reconciliation revision, and persist the exact response atomically.
    fn decide_reconciliation_case(
        &self,
        request: &DecideReconciliationCaseV1Request,
    ) -> ReconciliationPortResult<DecideReconciliationCaseV1Response>;

    fn open_reconciliation_case_v2(
        &self,
        _request: &OpenReconciliationCaseV2Request,
    ) -> ReconciliationPortResult<OpenReconciliationCaseV2Response> {
        Err(ReconciliationPortError::new(
            ReconciliationPortErrorKind::Internal,
        ))
    }

    fn decide_reconciliation_case_v2(
        &self,
        _request: &DecideReconciliationCaseV2Request,
    ) -> ReconciliationPortResult<DecideReconciliationCaseV2Response> {
        Err(ReconciliationPortError::new(
            ReconciliationPortErrorKind::Internal,
        ))
    }

    fn list_reconciliation_cases_v2(
        &self,
        _request: &ListReconciliationCasesV2Request,
    ) -> ReconciliationPortResult<ListReconciliationCasesV2Response> {
        Err(ReconciliationPortError::new(
            ReconciliationPortErrorKind::Internal,
        ))
    }
}

pub trait PhotoKitConnectorPort {
    fn snapshot(
        &self,
        request: &GetPhotoKitConnectorV1Request,
    ) -> PhotoKitConnectorPortResult<GetPhotoKitConnectorV1Response>;

    fn begin_setup(
        &self,
        request: &BeginPhotoKitSetupV1Request,
    ) -> PhotoKitConnectorPortResult<BeginPhotoKitSetupV1Response>;

    fn configure_scope(
        &self,
        request: &ConfigurePhotoKitScopeV1Request,
    ) -> PhotoKitConnectorPortResult<ConfigurePhotoKitScopeV1Response>;

    fn reconcile(
        &self,
        request: &SyncPhotoKitV1Request,
        trigger: PhotoKitReconcileTriggerV1,
    ) -> PhotoKitConnectorPortResult<SyncPhotoKitV1Response>;

    fn disable(
        &self,
        request: &DisablePhotoKitV1Request,
    ) -> PhotoKitConnectorPortResult<DisablePhotoKitV1Response>;
}

pub trait OutfitPort {
    fn create_manual_outfit(
        &self,
        request: &CreateManualOutfitV1Request,
    ) -> OutfitPortResult<CreateManualOutfitV1Response>;

    fn list_outfits(
        &self,
        request: &ListOutfitsV1Request,
    ) -> OutfitPortResult<ListOutfitsV1Response>;

    fn get_outfit_collage(
        &self,
        request: &GetOutfitCollageV1Request,
    ) -> OutfitPortResult<GetOutfitCollageV1Response>;
}

pub trait GarmentSegmentationProvider {
    fn describe(&self) -> SegmentationProviderDescriptorV1;

    fn segment(
        &self,
        request: &SegmentationRequestV1,
    ) -> SegmentationProviderResult<SegmentationOutcomeV1>;
}

pub trait LocalPersonDetectionProviderV1 {
    fn describe(&self) -> PersonDetectionProviderDescriptorV1;

    fn detect(
        &self,
        request: &PersonDetectionRequestV1,
    ) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1>;

    fn detect_people(
        &self,
        request: &PersonDetectionRequestV1,
    ) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
        self.detect(request)
    }
}

pub struct ConformingLocalPersonDetectionProviderV1<'a> {
    inner: &'a dyn LocalPersonDetectionProviderV1,
    descriptor: PersonDetectionProviderDescriptorV1,
}

impl<'a> ConformingLocalPersonDetectionProviderV1<'a> {
    pub fn new(
        inner: &'a dyn LocalPersonDetectionProviderV1,
    ) -> PersonDetectionProviderResult<Self> {
        let descriptor = inner.describe();
        descriptor.validate().map_err(|_| {
            PersonDetectionProviderError::new(PersonDetectionProviderErrorKind::MalformedOutput)
        })?;
        Ok(Self { inner, descriptor })
    }
}

impl LocalPersonDetectionProviderV1 for ConformingLocalPersonDetectionProviderV1<'_> {
    fn describe(&self) -> PersonDetectionProviderDescriptorV1 {
        self.descriptor.clone()
    }

    fn detect(
        &self,
        request: &PersonDetectionRequestV1,
    ) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
        request.validate().map_err(|_| {
            PersonDetectionProviderError::new(PersonDetectionProviderErrorKind::InvalidRequest)
        })?;
        if request.contract_revision != crate::LOCAL_PERSON_DETECTION_CONTRACT_V1
            || request.preprocessing_revision != self.descriptor.preprocessing_revision
        {
            return Err(PersonDetectionProviderError::new(
                PersonDetectionProviderErrorKind::InvalidRequest,
            ));
        }
        let outcome = self.inner.detect(request)?;
        outcome
            .validate_against(&self.descriptor, request)
            .map_err(|_| {
                PersonDetectionProviderError::new(PersonDetectionProviderErrorKind::MalformedOutput)
            })?;
        Ok(outcome)
    }
}

pub struct ConformingGarmentSegmentationProviderV1<'a> {
    inner: &'a dyn GarmentSegmentationProvider,
    descriptor: SegmentationProviderDescriptorV1,
}

impl<'a> ConformingGarmentSegmentationProviderV1<'a> {
    pub fn new(inner: &'a dyn GarmentSegmentationProvider) -> SegmentationProviderResult<Self> {
        let descriptor = inner.describe();
        descriptor.validate().map_err(|_| {
            SegmentationProviderError::new(SegmentationProviderErrorKind::MalformedOutput)
        })?;
        Ok(Self { inner, descriptor })
    }
}

impl GarmentSegmentationProvider for ConformingGarmentSegmentationProviderV1<'_> {
    fn describe(&self) -> SegmentationProviderDescriptorV1 {
        self.descriptor.clone()
    }

    fn segment(
        &self,
        request: &SegmentationRequestV1,
    ) -> SegmentationProviderResult<SegmentationOutcomeV1> {
        request.validate().map_err(|_| {
            SegmentationProviderError::new(SegmentationProviderErrorKind::InvalidRequest)
        })?;
        if request.contract_revision != GARMENT_SEGMENTATION_CONTRACT_V1
            || request.preprocessing_revision != self.descriptor.preprocessing_revision
        {
            return Err(SegmentationProviderError::new(
                SegmentationProviderErrorKind::InvalidRequest,
            ));
        }
        let outcome = self.inner.segment(request)?;
        outcome
            .validate_against(&self.descriptor, request)
            .map_err(|_| {
                SegmentationProviderError::new(SegmentationProviderErrorKind::MalformedOutput)
            })?;
        Ok(outcome)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableGarmentSegmentationProviderV1;

impl GarmentSegmentationProvider for UnavailableGarmentSegmentationProviderV1 {
    fn describe(&self) -> SegmentationProviderDescriptorV1 {
        SegmentationProviderDescriptorV1 {
            contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
            provider_id: UNAVAILABLE_SEGMENTATION_PROVIDER_ID_V1.to_owned(),
            provider_revision: UNAVAILABLE_SEGMENTATION_PROVIDER_REVISION_V1.to_owned(),
            model_revision: None,
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            automatic_capability: SegmentationCapabilityV1::Unavailable,
            interactive_capability: SegmentationCapabilityV1::Unavailable,
            maximum_masks: crate::MAX_SEGMENTATION_MASKS as u8,
        }
    }

    fn segment(
        &self,
        request: &SegmentationRequestV1,
    ) -> SegmentationProviderResult<SegmentationOutcomeV1> {
        request.validate().map_err(|_| {
            SegmentationProviderError::new(SegmentationProviderErrorKind::InvalidRequest)
        })?;
        if request.contract_revision != GARMENT_SEGMENTATION_CONTRACT_V1
            || request.preprocessing_revision != PHOTO_PREPROCESSING_REVISION_V1
        {
            return Err(SegmentationProviderError::new(
                SegmentationProviderErrorKind::InvalidRequest,
            ));
        }
        Ok(SegmentationOutcomeV1::unavailable(
            request,
            SegmentationUnavailableReasonV1::ReviewedModelPackAbsent,
        ))
    }
}

pub trait CredentialPort {
    fn put(&self, locator: &CredentialLocator, secret: &SecretString) -> PortResult<()>;
    fn get(&self, _locator: &CredentialLocator) -> PortResult<SecretString> {
        Err(PortError::new(PortErrorKind::Unavailable))
    }
    fn contains(&self, locator: &CredentialLocator) -> PortResult<bool>;
    fn delete(&self, locator: &CredentialLocator) -> PortResult<()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobClaimV1 {
    pub job_id: JobId,
    pub kind: JobKindV1,
    pub input_digest: Sha256Digest,
    pub attempt: u16,
    pub max_attempts: u16,
    pub fence: u64,
}

pub trait JobPort {
    fn claim_next(&self, lease_seconds: u32) -> PortResult<Option<JobClaimV1>>;
    fn complete(&self, job_id: JobId, fence: u64) -> PortResult<()>;
    fn fail(
        &self,
        job_id: JobId,
        fence: u64,
        code: ErrorCodeV1,
        user_action: UserActionKeyV1,
        retryable: bool,
    ) -> PortResult<()>;
}

pub trait DiagnosticPort {
    fn emit(&self, event: &DiagnosticEventV1) -> PortResult<()>;
}
