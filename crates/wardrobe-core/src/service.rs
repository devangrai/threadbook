use sha2::{Digest, Sha256};

use crate::ports::{
    BlobPort, CatalogPort, CatalogPortError, CatalogPortErrorKind,
    ConformingGarmentSegmentationProviderV1, DatabasePort, DeleteCredentialPlanV1, DeletionPort,
    GarmentSegmentationProvider, OutfitPort, OutfitPortError, OutfitPortErrorKind,
    PhotoAnalysisPort, PhotoAnalysisPortError, PhotoAnalysisPortErrorKind, PhotoKitConnectorPort,
    PhotoKitConnectorPortError, PhotoKitConnectorPortErrorKind, PortError, PortErrorKind,
    ReceiptAnalysisFailureV1, ReceiptAnalysisPlanV1, ReceiptEvidenceProvider,
    ReceiptImageAttemptPlanV1, ReceiptImageDownloader, ReceiptPort, ReceiptPortError,
    ReceiptPortErrorKind, ReceiptProviderError, ReceiptProviderErrorKind, ReconciliationPort,
    ReconciliationPortError, ReconciliationPortErrorKind, SaveCredentialPlanV1,
    SegmentationProviderErrorKind, Sha256Digest,
};
use crate::{
    AnalyzePhotoScopeV1Request, AnalyzePhotoScopeV1Response, AnalyzeReceiptV1Request,
    AnalyzeReceiptV1Response, ApproveAndFetchReceiptImageV1Request,
    ApproveAndFetchReceiptImageV1Response, BeginPhotoKitSetupV1Request,
    BeginPhotoKitSetupV1Response, CatalogSnapshotV1, CommandErrorV1, CommandResult,
    ConfigurePhotoKitScopeV1Request, ConfigurePhotoKitScopeV1Response, ConnectGmailV1Request,
    ConnectGmailV1Response, CorrectPhotoOwnerV1Request, CorrectPhotoOwnerV1Response,
    CorrectPhotoPersonDetectionV1Request, CorrectPhotoPersonDetectionV1Response,
    CreateManualOutfitV1Request, CreateManualOutfitV1Response, CreatePhotoScopeV1Request,
    CreatePhotoScopeV1Response, CredentialPort, CredentialStatusV1, DecideEvidenceV1Request,
    DecideEvidenceV1Response, DecidePhotoOwnerV1Request, DecidePhotoOwnerV1Response,
    DecideReconciliationCaseV1Request, DecideReconciliationCaseV1Response,
    DecideReconciliationCaseV2Request, DecideReconciliationCaseV2Response, DecisionKindV1,
    DeleteCredentialV1Request, DeleteCredentialV1Response, DeletionDependencyClassV1,
    DetectPhotoScopePeopleV1Request, DetectPhotoScopePeopleV1Response, DisablePhotoKitV1Request,
    DisablePhotoKitV1Response, DisconnectGmailV1Request, DisconnectGmailV1Response, ErrorCodeV1,
    EvidenceDecisionActionV1, EvidenceStateV1, FoundationSnapshotV1,
    GetFoundationSnapshotV1Request, GetFoundationSnapshotV1Response, GetGmailConnectorV1Request,
    GetGmailConnectorV1Response, GetOutfitCollageV1Request, GetOutfitCollageV1Response,
    GetPhotoKitConnectorV1Request, GetPhotoKitConnectorV1Response, GmailConnectorPort,
    GmailConnectorPortError, GmailConnectorPortErrorKind, ImportLocalSourcesV1Request,
    ImportLocalSourcesV1Response, InboxStateV1, ListCatalogV1Request, ListCatalogV1Response,
    ListDeletionPlanItemsV1Request, ListDeletionPlanItemsV1Response,
    ListImportedPhotoRootsV1Request, ListImportedPhotoRootsV1Response, ListInboxV1Request,
    ListInboxV1Response, ListOutfitsV1Request, ListOutfitsV1Response,
    ListPhotoObservationsV1Request, ListPhotoObservationsV1Response,
    ListPhotoOwnerReviewsV1Request, ListPhotoOwnerReviewsV1Response,
    ListReceiptImageCandidatesV1Request, ListReceiptImageCandidatesV1Response,
    ListReceiptsV1Request, ListReceiptsV1Response, ListReconciliationCasesV2Request,
    ListReconciliationCasesV2Response, MergeItemsV1Request, MergeItemsV1Response,
    OpenReconciliationCaseV1Request, OpenReconciliationCaseV1Response,
    OpenReconciliationCaseV2Request, OpenReconciliationCaseV2Response, PhotoKitReconcileTriggerV1,
    PhotoReviewActionV1, PreviewDeletionV1Request, PreviewDeletionV1Response,
    PromptPhotoObservationV1Request, PromptPhotoObservationV1Response, ReadPhotoArtifactV1Request,
    ReadPhotoArtifactV1Response, ReadPhotoOwnerPreviewV1Request, ReadPhotoOwnerPreviewV1Response,
    RefreshImportRootsV1Request, RefreshImportRootsV1Response, ReplayStatusV1,
    RetryPhotoPersonDetectionV1Request, RetryPhotoPersonDetectionV1Response,
    ReviewPhotoObservationV1Request, ReviewPhotoObservationV1Response, ReviewReceiptV1Request,
    ReviewReceiptV1Response, RunStorageCheckV1Request, RunStorageCheckV1Response,
    SaveCredentialV1Request, SaveCredentialV1Response, SaveGmailSettingsV1Request,
    SaveGmailSettingsV1Response, SaveItemV1Request, SaveItemV1Response, SplitItemV1Request,
    SplitItemV1Response, SyncGmailV1Request, SyncGmailV1Response, SyncPhotoKitV1Request,
    SyncPhotoKitV1Response, UndoDecisionV1Request, UndoDecisionV1Response, UserActionKeyV1,
    Validate, MAX_RECENT_JOBS, SCHEMA_VERSION_V1, STORAGE_CHECK_BYTES,
};

pub struct ApplicationService<D, B, C, R = (), I = (), S = (), G = (), P = ()> {
    database: D,
    blobs: B,
    credentials: C,
    receipt_provider: R,
    receipt_image_downloader: I,
    garment_segmentation_provider: S,
    gmail_connector: G,
    photokit_connector: P,
}

impl<D, B, C> ApplicationService<D, B, C, (), (), (), (), ()> {
    pub fn new(database: D, blobs: B, credentials: C) -> Self {
        Self {
            database,
            blobs,
            credentials,
            receipt_provider: (),
            receipt_image_downloader: (),
            garment_segmentation_provider: (),
            gmail_connector: (),
            photokit_connector: (),
        }
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P> {
    pub fn database(&self) -> &D {
        &self.database
    }

    pub fn blobs(&self) -> &B {
        &self.blobs
    }

    pub fn credentials(&self) -> &C {
        &self.credentials
    }

    pub fn receipt_provider(&self) -> &R {
        &self.receipt_provider
    }

    pub fn receipt_image_downloader(&self) -> &I {
        &self.receipt_image_downloader
    }

    pub fn garment_segmentation_provider(&self) -> &S {
        &self.garment_segmentation_provider
    }

    pub fn gmail_connector(&self) -> &G {
        &self.gmail_connector
    }

    pub fn photokit_connector(&self) -> &P {
        &self.photokit_connector
    }

    pub fn with_receipt_provider<N>(
        self,
        receipt_provider: N,
    ) -> ApplicationService<D, B, C, N, I, S, G, P> {
        ApplicationService {
            database: self.database,
            blobs: self.blobs,
            credentials: self.credentials,
            receipt_provider,
            receipt_image_downloader: self.receipt_image_downloader,
            garment_segmentation_provider: self.garment_segmentation_provider,
            gmail_connector: self.gmail_connector,
            photokit_connector: self.photokit_connector,
        }
    }

    pub fn with_receipt_image_downloader<J>(
        self,
        receipt_image_downloader: J,
    ) -> ApplicationService<D, B, C, R, J, S, G, P> {
        ApplicationService {
            database: self.database,
            blobs: self.blobs,
            credentials: self.credentials,
            receipt_provider: self.receipt_provider,
            receipt_image_downloader,
            garment_segmentation_provider: self.garment_segmentation_provider,
            gmail_connector: self.gmail_connector,
            photokit_connector: self.photokit_connector,
        }
    }

    pub fn with_garment_segmentation_provider<N>(
        self,
        garment_segmentation_provider: N,
    ) -> ApplicationService<D, B, C, R, I, N, G, P> {
        ApplicationService {
            database: self.database,
            blobs: self.blobs,
            credentials: self.credentials,
            receipt_provider: self.receipt_provider,
            receipt_image_downloader: self.receipt_image_downloader,
            garment_segmentation_provider,
            gmail_connector: self.gmail_connector,
            photokit_connector: self.photokit_connector,
        }
    }

    pub fn with_gmail_connector<N>(
        self,
        gmail_connector: N,
    ) -> ApplicationService<D, B, C, R, I, S, N, P> {
        ApplicationService {
            database: self.database,
            blobs: self.blobs,
            credentials: self.credentials,
            receipt_provider: self.receipt_provider,
            receipt_image_downloader: self.receipt_image_downloader,
            garment_segmentation_provider: self.garment_segmentation_provider,
            gmail_connector,
            photokit_connector: self.photokit_connector,
        }
    }

    pub fn with_photokit_connector<N>(
        self,
        photokit_connector: N,
    ) -> ApplicationService<D, B, C, R, I, S, G, N> {
        ApplicationService {
            database: self.database,
            blobs: self.blobs,
            credentials: self.credentials,
            receipt_provider: self.receipt_provider,
            receipt_image_downloader: self.receipt_image_downloader,
            garment_segmentation_provider: self.garment_segmentation_provider,
            gmail_connector: self.gmail_connector,
            photokit_connector,
        }
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    D: OutfitPort,
{
    pub fn create_manual_outfit_v1(
        &self,
        request: CreateManualOutfitV1Request,
    ) -> CommandResult<CreateManualOutfitV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .create_manual_outfit(&request)
            .map_err(map_outfit_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }

    pub fn list_outfits_v1(
        &self,
        request: ListOutfitsV1Request,
    ) -> CommandResult<ListOutfitsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_outfits(&request)
            .map_err(map_outfit_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err() || response.outfits.len() > usize::from(request.limit) {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn get_outfit_collage_v1(
        &self,
        request: GetOutfitCollageV1Request,
    ) -> CommandResult<GetOutfitCollageV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .get_outfit_collage(&request)
            .map_err(map_outfit_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    G: GmailConnectorPort,
{
    pub fn get_gmail_connector_v1(
        &self,
        request: GetGmailConnectorV1Request,
    ) -> CommandResult<GetGmailConnectorV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .gmail_connector
            .get_gmail_connector(&request)
            .map_err(map_gmail_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }

    pub fn save_gmail_settings_v1(
        &self,
        request: SaveGmailSettingsV1Request,
    ) -> CommandResult<SaveGmailSettingsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .gmail_connector
            .save_gmail_settings(&request)
            .map_err(map_gmail_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        if response.settings.oauth_client_id != request.client_id
            || response.settings.label_name != request.label_name
            || response.settings.limits != request.limits
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn connect_gmail_v1(
        &self,
        request: ConnectGmailV1Request,
    ) -> CommandResult<ConnectGmailV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .gmail_connector
            .connect_gmail(&request)
            .map_err(map_gmail_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }

    pub fn sync_gmail_v1(&self, request: SyncGmailV1Request) -> CommandResult<SyncGmailV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .gmail_connector
            .sync_gmail(&request)
            .map_err(map_gmail_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }

    pub fn disconnect_gmail_v1(
        &self,
        request: DisconnectGmailV1Request,
    ) -> CommandResult<DisconnectGmailV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .gmail_connector
            .disconnect_gmail(&request)
            .map_err(map_gmail_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    P: PhotoKitConnectorPort,
{
    pub fn get_photokit_connector_v1(
        &self,
        request: GetPhotoKitConnectorV1Request,
    ) -> CommandResult<GetPhotoKitConnectorV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .photokit_connector
            .snapshot(&request)
            .map_err(map_photokit_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }

    pub fn begin_photokit_setup_v1(
        &self,
        request: BeginPhotoKitSetupV1Request,
    ) -> CommandResult<BeginPhotoKitSetupV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .photokit_connector
            .begin_setup(&request)
            .map_err(map_photokit_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }

    pub fn configure_photokit_scope_v1(
        &self,
        request: ConfigurePhotoKitScopeV1Request,
    ) -> CommandResult<ConfigurePhotoKitScopeV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .photokit_connector
            .configure_scope(&request)
            .map_err(map_photokit_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.snapshot.allow_icloud_downloads != request.allow_icloud_downloads
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn sync_photokit_v1(
        &self,
        request: SyncPhotoKitV1Request,
    ) -> CommandResult<SyncPhotoKitV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .photokit_connector
            .reconcile(&request, PhotoKitReconcileTriggerV1::User)
            .map_err(map_photokit_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err() || response.trigger != PhotoKitReconcileTriggerV1::User {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn disable_photokit_v1(
        &self,
        request: DisablePhotoKitV1Request,
    ) -> CommandResult<DisablePhotoKitV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .photokit_connector
            .disable(&request)
            .map_err(map_photokit_connector_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.photokit_revision.get() <= request.expected_photokit_revision.get()
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    D: CatalogPort,
{
    pub fn import_local_sources_v1(
        &self,
        request: ImportLocalSourcesV1Request,
    ) -> CommandResult<ImportLocalSourcesV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .import_local_sources(&request)
            .map_err(map_catalog_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.summaries.len() > request.paths.len() {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn refresh_import_roots_v1(
        &self,
        request: RefreshImportRootsV1Request,
    ) -> CommandResult<RefreshImportRootsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .refresh_import_roots(&request)
            .map_err(map_catalog_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.summaries.len() > request.import_root_ids.len() {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn list_catalog_v1(
        &self,
        request: ListCatalogV1Request,
    ) -> CommandResult<ListCatalogV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_catalog(&request)
            .map_err(map_catalog_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.items.len() > usize::from(request.limit)
            || response.total_count < response.items.len() as u64
            || response.items.iter().any(|item| item.validate().is_err())
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn list_inbox_v1(&self, request: ListInboxV1Request) -> CommandResult<ListInboxV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_inbox(&request)
            .map_err(map_catalog_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        let returned = response.evidence.len() + response.quarantines.len();
        let valid_partition = match request.state {
            InboxStateV1::Unresolved => {
                response.quarantines.is_empty()
                    && response
                        .evidence
                        .iter()
                        .all(|evidence| evidence.state == EvidenceStateV1::Unresolved)
            }
            InboxStateV1::Deferred => {
                response.quarantines.is_empty()
                    && response
                        .evidence
                        .iter()
                        .all(|evidence| evidence.state == EvidenceStateV1::Deferred)
            }
            InboxStateV1::Quarantine => {
                response.evidence.is_empty()
                    && response
                        .quarantines
                        .iter()
                        .all(|quarantine| quarantine.validate().is_ok())
            }
        };
        if returned > usize::from(request.limit)
            || response.total_count < returned as u64
            || !valid_partition
            || response
                .evidence
                .iter()
                .any(|evidence| evidence.validate().is_err())
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn save_item_v1(&self, request: SaveItemV1Request) -> CommandResult<SaveItemV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .save_item_and_append_decision(&request)
            .map_err(map_catalog_error)?;
        validate_mutation(
            response.schema_version,
            response.request_id,
            request.request_id,
            request.expected_catalog_revision,
            response.new_catalog_revision,
            &response.decision,
            DecisionKindV1::SaveItem,
        )?;
        if response.item.validate().is_err()
            || request
                .item_id
                .is_some_and(|item_id| item_id != response.item.item_id)
            || response.item.evidence_ids != request.evidence_ids
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn decide_evidence_v1(
        &self,
        request: DecideEvidenceV1Request,
    ) -> CommandResult<DecideEvidenceV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .decide_evidence_and_append_decision(&request)
            .map_err(map_catalog_error)?;
        validate_mutation(
            response.schema_version,
            response.request_id,
            request.request_id,
            request.expected_catalog_revision,
            response.new_catalog_revision,
            &response.decision,
            DecisionKindV1::DecideEvidence,
        )?;
        let expected_state = match request.action {
            EvidenceDecisionActionV1::Assign => EvidenceStateV1::Assigned,
            EvidenceDecisionActionV1::Reject => EvidenceStateV1::Rejected,
            EvidenceDecisionActionV1::Defer => EvidenceStateV1::Deferred,
        };
        if response.evidence.validate().is_err()
            || response.evidence.evidence_id != request.evidence_id
            || response.evidence.state != expected_state
            || response.evidence.assigned_item_id != request.item_id
            || !response
                .decision
                .affected_evidence_ids
                .contains(&request.evidence_id)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn merge_items_v1(
        &self,
        request: MergeItemsV1Request,
    ) -> CommandResult<MergeItemsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .merge_items_and_append_decision(&request)
            .map_err(map_catalog_error)?;
        validate_mutation(
            response.schema_version,
            response.request_id,
            request.request_id,
            request.expected_catalog_revision,
            response.new_catalog_revision,
            &response.decision,
            DecisionKindV1::MergeItems,
        )?;
        if response.item.validate().is_err()
            || !request.item_ids.contains(&response.item.item_id)
            || !request
                .item_ids
                .iter()
                .all(|id| response.decision.affected_item_ids.contains(id))
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn split_item_v1(&self, request: SplitItemV1Request) -> CommandResult<SplitItemV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .split_item_and_append_decision(&request)
            .map_err(map_catalog_error)?;
        validate_mutation(
            response.schema_version,
            response.request_id,
            request.request_id,
            request.expected_catalog_revision,
            response.new_catalog_revision,
            &response.decision,
            DecisionKindV1::SplitItem,
        )?;
        let mut expected_evidence = request
            .groups
            .iter()
            .flat_map(|group| group.evidence_ids.iter().copied())
            .collect::<Vec<_>>();
        let mut actual_evidence = response
            .items
            .iter()
            .flat_map(|item| item.evidence_ids.iter().copied())
            .collect::<Vec<_>>();
        expected_evidence.sort_unstable();
        actual_evidence.sort_unstable();
        if response.items.len() != request.groups.len()
            || response.items.iter().any(|item| item.validate().is_err())
            || expected_evidence != actual_evidence
            || !response
                .decision
                .affected_item_ids
                .contains(&request.item_id)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn undo_decision_v1(
        &self,
        request: UndoDecisionV1Request,
    ) -> CommandResult<UndoDecisionV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .append_compensating_undo(&request)
            .map_err(map_catalog_error)?;
        validate_mutation(
            response.schema_version,
            response.request_id,
            request.request_id,
            request.expected_catalog_revision,
            response.new_catalog_revision,
            &response.decision,
            DecisionKindV1::Undo,
        )?;
        if response.decision.compensates_decision_id != Some(request.decision_id)
            || response
                .restored_items
                .iter()
                .any(|item| item.validate().is_err())
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn preview_deletion_v1(
        &self,
        request: PreviewDeletionV1Request,
    ) -> CommandResult<PreviewDeletionV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .preview_deletion(&request)
            .map_err(map_catalog_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        let expected_classes = [
            DeletionDependencyClassV1::Originals,
            DeletionDependencyClassV1::Derivatives,
            DeletionDependencyClassV1::SourceRecords,
            DeletionDependencyClassV1::EvidenceRecords,
            DeletionDependencyClassV1::DecisionRecords,
            DeletionDependencyClassV1::RemoteReferences,
            DeletionDependencyClassV1::RetainedSharedBlobs,
        ];
        let retained_count = response
            .counts
            .iter()
            .find(|count| count.class == DeletionDependencyClassV1::RetainedSharedBlobs)
            .map(|count| count.count);
        let overall = response
            .counts
            .iter()
            .filter(|count| count.class != DeletionDependencyClassV1::RetainedSharedBlobs)
            .try_fold(0_u64, |total, count| total.checked_add(count.count));
        if response.validate().is_err()
            || response.counts.len() != expected_classes.len()
            || !expected_classes
                .iter()
                .all(|class| response.counts.iter().any(|count| count.class == *class))
            || retained_count != Some(response.retained_shared_blob_count)
            || overall != Some(response.overall_count)
            || response.first_page.len() > usize::from(request.limit)
            || response
                .first_page
                .iter()
                .any(|item| item.class != response.first_class || item.validate().is_err())
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn list_deletion_plan_items_v1(
        &self,
        request: ListDeletionPlanItemsV1Request,
    ) -> CommandResult<ListDeletionPlanItemsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_deletion_plan_items(&request)
            .map_err(map_catalog_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.preview_snapshot_token != request.preview_snapshot_token
            || response.class != request.class
            || response.items.len() > usize::from(request.limit)
            || response.total_count < response.items.len() as u64
            || response
                .items
                .iter()
                .any(|item| item.class != request.class || item.validate().is_err())
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    D: DeletionPort,
{
    pub fn execute_deletion_v1(
        &self,
        request: crate::ExecuteDeletionV1Request,
    ) -> CommandResult<crate::ExecuteDeletionV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .execute_deletion(&request)
            .map_err(map_catalog_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        response.validate().map_err(|_| internal_data_error())?;
        Ok(response)
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    D: PhotoAnalysisPort,
{
    pub fn list_imported_photo_roots_v1(
        &self,
        request: ListImportedPhotoRootsV1Request,
    ) -> CommandResult<ListImportedPhotoRootsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_imported_photo_roots(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.roots.len() > usize::from(request.limit)
            || response.total_count < response.roots.len() as u64
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn create_photo_scope_v1(
        &self,
        request: CreatePhotoScopeV1Request,
    ) -> CommandResult<CreatePhotoScopeV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .create_photo_scope(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.scope.import_root_id != request.import_root_id
            || response.scope.manifest_generation != request.expected_manifest_generation
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn analyze_photo_scope_v1(
        &self,
        request: AnalyzePhotoScopeV1Request,
    ) -> CommandResult<AnalyzePhotoScopeV1Response>
    where
        S: GarmentSegmentationProvider,
    {
        request.validate().map_err(CommandErrorV1::from)?;
        let provider =
            ConformingGarmentSegmentationProviderV1::new(&self.garment_segmentation_provider)
                .map_err(map_segmentation_boundary_error)?;
        let response = self
            .database
            .analyze_photo_scope(&request, &provider)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err() || response.scope_id != request.scope_id {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn detect_photo_scope_people_v1(
        &self,
        request: DetectPhotoScopePeopleV1Request,
        provider: &dyn crate::LocalPersonDetectionProviderV1,
    ) -> CommandResult<DetectPhotoScopePeopleV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let provider = crate::ConformingLocalPersonDetectionProviderV1::new(provider)
            .map_err(map_person_detection_boundary_error)?;
        let response = self
            .database
            .detect_photo_scope_people(&request, &provider)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err() || response.scope_id != request.scope_id {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn list_photo_observations_v1(
        &self,
        request: ListPhotoObservationsV1Request,
    ) -> CommandResult<ListPhotoObservationsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_photo_observations(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.scope_id != request.scope_id
            || response.state != request.state
            || response.observations.len() > usize::from(request.limit)
            || response.total_count < response.observations.len() as u64
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn read_photo_artifact_v1(
        &self,
        request: ReadPhotoArtifactV1Request,
    ) -> CommandResult<ReadPhotoArtifactV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .read_photo_artifact(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err() || response.artifact_id != request.artifact_id {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn prompt_photo_observation_v1(
        &self,
        request: PromptPhotoObservationV1Request,
    ) -> CommandResult<PromptPhotoObservationV1Response>
    where
        S: GarmentSegmentationProvider,
    {
        request.validate().map_err(CommandErrorV1::from)?;
        let provider =
            ConformingGarmentSegmentationProviderV1::new(&self.garment_segmentation_provider)
                .map_err(map_segmentation_boundary_error)?;
        let response = self
            .database
            .prompt_photo_observation(&request, &provider)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        let artifact = &response.observation.artifact;
        if response.validate().is_err()
            || response.observation.observation_id != request.observation_id
            || request
                .validate_geometry_within(artifact.source_width, artifact.source_height)
                .is_err()
            || (artifact.kind == crate::PhotoArtifactKindV1::RectangleSourceCrop
                && artifact.rectangle != Some(request.box_rectangle))
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn review_photo_observation_v1(
        &self,
        request: ReviewPhotoObservationV1Request,
    ) -> CommandResult<ReviewPhotoObservationV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .review_photo_observation(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        let replacement_matches = match request.action {
            PhotoReviewActionV1::ReplaceCrop => {
                response.observation.artifact.rectangle == request.replacement_rectangle
                    && request.replacement_rectangle.is_some_and(|rectangle| {
                        rectangle
                            .validate_within(
                                response.observation.artifact.source_width,
                                response.observation.artifact.source_height,
                            )
                            .is_ok()
                    })
            }
            _ => true,
        };
        if response.validate().is_err()
            || response.observation.observation_id != request.observation_id
            || response.decision.observation_id != request.observation_id
            || response.decision.action != request.action
            || response.observation.state != request.action.resulting_state()
            || request.expected_photo_revision.checked_add(1) != Some(response.new_photo_revision)
            || !replacement_matches
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn list_photo_owner_reviews_v1(
        &self,
        request: ListPhotoOwnerReviewsV1Request,
    ) -> CommandResult<ListPhotoOwnerReviewsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_photo_owner_reviews(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.state != request.state
            || response.reviews.len() > usize::from(request.limit)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn read_photo_owner_preview_v1(
        &self,
        request: ReadPhotoOwnerPreviewV1Request,
    ) -> CommandResult<ReadPhotoOwnerPreviewV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .read_photo_owner_preview(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.owner_review_id != request.owner_review_id
            || response.preview_id != request.preview_id
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn decide_photo_owner_v1(
        &self,
        request: DecidePhotoOwnerV1Request,
    ) -> CommandResult<DecidePhotoOwnerV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .decide_photo_owner(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        let selected_instance_matches = request.selected_person_instance_id.is_none_or(|id| {
            response
                .review
                .instances
                .iter()
                .any(|instance| instance.person_instance_id == id)
        });
        if response.validate().is_err()
            || response.review.owner_review_id != request.owner_review_id
            || response.decision.action != request.action
            || response.decision.selected_person_instance_id != request.selected_person_instance_id
            || response.decision.detection_revision != request.expected_detection_revision
            || request.expected_owner_head_revision.checked_add(1)
                != Some(response.decision.owner_revision)
            || request.expected_photo_revision.checked_add(1)
                != Some(response.decision.photo_revision)
            || !selected_instance_matches
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn correct_photo_owner_v1(
        &self,
        request: CorrectPhotoOwnerV1Request,
    ) -> CommandResult<CorrectPhotoOwnerV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .correct_photo_owner(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        let selected_instance_matches = request.selected_person_instance_id.is_none_or(|id| {
            response
                .review
                .instances
                .iter()
                .any(|instance| instance.person_instance_id == id)
        });
        if response.validate().is_err()
            || response.review.owner_review_id != request.owner_review_id
            || response.decision.action != request.action
            || response.decision.selected_person_instance_id != request.selected_person_instance_id
            || response.decision.supersedes_owner_decision_id
                != Some(request.superseded_owner_decision_id)
            || response.decision.detection_revision != request.expected_detection_revision
            || request.expected_owner_head_revision.checked_add(1)
                != Some(response.decision.owner_revision)
            || request.expected_photo_revision.checked_add(1)
                != Some(response.decision.photo_revision)
            || !selected_instance_matches
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn correct_photo_person_detection_v1(
        &self,
        request: CorrectPhotoPersonDetectionV1Request,
    ) -> CommandResult<CorrectPhotoPersonDetectionV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .correct_photo_person_detection(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.review.owner_review_id != request.owner_review_id
            || response.review.terminal_attempt_id != request.expected_terminal_attempt_id
            || response.instance.rectangle != request.manual_rectangle
            || response.review.owner_head_revision != request.expected_owner_head_revision
            || request.expected_detection_revision.checked_add(1)
                != Some(response.review.detection_revision)
            || request.expected_photo_revision.checked_add(1)
                != Some(response.review.photo_revision)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn retry_photo_person_detection_v1(
        &self,
        request: RetryPhotoPersonDetectionV1Request,
    ) -> CommandResult<RetryPhotoPersonDetectionV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .retry_photo_person_detection(&request)
            .map_err(map_photo_analysis_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.owner_review_id != request.owner_review_id
            || response.owner_revision != request.expected_owner_head_revision
            || request.expected_detection_revision.checked_add(1)
                != Some(response.detection_revision)
            || request.expected_photo_revision.checked_add(1) != Some(response.photo_revision)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    D: ReconciliationPort,
{
    pub fn open_reconciliation_case_v1(
        &self,
        request: OpenReconciliationCaseV1Request,
    ) -> CommandResult<OpenReconciliationCaseV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .open_reconciliation_case(&request)
            .map_err(map_reconciliation_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.case.observation_id != request.observation_id
            || response.case.artifact_id != request.selected_artifact_id
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn decide_reconciliation_case_v1(
        &self,
        request: DecideReconciliationCaseV1Request,
    ) -> CommandResult<DecideReconciliationCaseV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .decide_reconciliation_case(&request)
            .map_err(map_reconciliation_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.case.case_id != request.case_id
            || response.decision.case_id != request.case_id
            || response.decision.outcome != request.outcome
            || response.decision.selected_candidate_id != request.selected_candidate_id
            || request.expected_case_revision.checked_add(1) != Some(response.case.case_revision)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn open_reconciliation_case_v2(
        &self,
        request: OpenReconciliationCaseV2Request,
    ) -> CommandResult<OpenReconciliationCaseV2Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .open_reconciliation_case_v2(&request)
            .map_err(map_reconciliation_error)?;
        if response.request_id != request.request_id
            || response.schema_version != request.schema_version
            || response.validate().is_err()
            || response.case.observation_id != request.observation_id
            || response.case.artifact_id != request.selected_artifact_id
            || response.owner_revision != request.expected_owner_revision
            || response.photo_revision != request.expected_photo_revision
            || response.case.authority_state != crate::ReconciliationAuthorityStateV2::OpenEligible
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn decide_reconciliation_case_v2(
        &self,
        request: DecideReconciliationCaseV2Request,
    ) -> CommandResult<DecideReconciliationCaseV2Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .decide_reconciliation_case_v2(&request)
            .map_err(map_reconciliation_error)?;
        if response.request_id != request.request_id
            || response.schema_version != request.schema_version
            || response.validate().is_err()
            || response.case.case_id != request.case_id
            || response.decision.case_id != request.case_id
            || response.decision.outcome != request.outcome
            || response.decision.selected_candidate_id != request.selected_candidate_id
            || request.expected_case_revision.checked_add(1) != Some(response.case.case_revision)
            || response.owner_revision != request.expected_owner_revision
            || response.photo_revision != request.expected_photo_revision
            || request.expected_reconciliation_revision.checked_add(1)
                != Some(response.reconciliation_revision)
            || response.case.authority_state != crate::ReconciliationAuthorityStateV2::OpenEligible
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn list_reconciliation_cases_v2(
        &self,
        request: ListReconciliationCasesV2Request,
    ) -> CommandResult<ListReconciliationCasesV2Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_reconciliation_cases_v2(&request)
            .map_err(map_reconciliation_error)?;
        if response.request_id != request.request_id
            || response.schema_version != request.schema_version
            || response.validate().is_err()
            || response.observation_id != request.observation_id
            || response.state != request.state
            || response.cases.len() > usize::from(request.limit)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    D: ReceiptPort,
    R: ReceiptEvidenceProvider,
{
    pub fn list_receipts_v1(
        &self,
        request: ListReceiptsV1Request,
    ) -> CommandResult<ListReceiptsV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_receipts(&request)
            .map_err(map_receipt_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.receipts.len() > usize::from(request.limit)
            || response.total_count < response.receipts.len() as u64
            || response
                .receipts
                .iter()
                .any(|receipt| receipt.state != request.state)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub fn analyze_receipt_v1(
        &self,
        request: AnalyzeReceiptV1Request,
    ) -> CommandResult<AnalyzeReceiptV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let plan = self
            .database
            .prepare_receipt_analysis(&request)
            .map_err(map_receipt_error)?;
        match plan {
            ReceiptAnalysisPlanV1::Replay(response) => {
                validate_analyze_response(&response, &request, ReplayStatusV1::Replayed, None)?;
                Ok(response)
            }
            ReceiptAnalysisPlanV1::ReplayFailure(failure) => {
                Err(map_receipt_analysis_failure(failure))
            }
            ReceiptAnalysisPlanV1::Extract {
                parsed,
                preserved_review_head,
            } => {
                parsed.validate().map_err(|_| internal_data_error())?;
                if parsed.source_id != request.source_id {
                    return Err(internal_data_error());
                }
                let envelope = match self.receipt_provider.extract(&parsed) {
                    Ok(envelope) => envelope,
                    Err(error) => {
                        let failure = classify_receipt_provider_failure(error);
                        let recorded = self
                            .database
                            .record_receipt_analysis_failure(&request, &parsed, failure)
                            .map_err(map_receipt_error)?;
                        return Err(map_receipt_analysis_failure(recorded));
                    }
                };
                if envelope.validate_against(&parsed).is_err() {
                    let failure = ReceiptAnalysisFailureV1::OutputValidationFailed;
                    let recorded = self
                        .database
                        .record_receipt_analysis_failure(&request, &parsed, failure)
                        .map_err(map_receipt_error)?;
                    return Err(map_receipt_analysis_failure(recorded));
                }
                let response = self
                    .database
                    .commit_receipt_analysis(
                        &request,
                        &parsed,
                        &envelope,
                        preserved_review_head.as_ref(),
                    )
                    .map_err(map_receipt_error)?;
                validate_analyze_response(
                    &response,
                    &request,
                    ReplayStatusV1::Created,
                    Some(&envelope),
                )?;
                if response.parsed != parsed
                    || response.order.review_head != preserved_review_head
                    || !response.order.matches_extraction(&envelope.output)
                {
                    return Err(internal_data_error());
                }
                Ok(response)
            }
        }
    }

    pub fn review_receipt_v1(
        &self,
        request: ReviewReceiptV1Request,
    ) -> CommandResult<ReviewReceiptV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .review_receipt_and_append_decision(&request)
            .map_err(map_receipt_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        let expected_revision = request.expected_receipt_revision.checked_add(1);
        if response.validate().is_err()
            || expected_revision != Some(response.new_receipt_revision)
            || response.order.order_evidence_id != request.order_evidence_id
            || response.decision.order_evidence_id != request.order_evidence_id
            || response.decision.action != request.action
            || response.decision.corrected_order != request.corrected_order
            || response.decision.receipt_revision != response.new_receipt_revision
            || response.order.state() != request.action.state()
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    D: ReceiptPort,
    I: ReceiptImageDownloader,
{
    pub fn list_receipt_image_candidates_v1(
        &self,
        request: ListReceiptImageCandidatesV1Request,
    ) -> CommandResult<ListReceiptImageCandidatesV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let response = self
            .database
            .list_receipt_image_candidates(&request)
            .map_err(map_receipt_error)?;
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err() || response.source_id != request.source_id {
            return Err(internal_data_error());
        }
        Ok(response)
    }

    pub async fn approve_and_fetch_receipt_image_v1(
        &self,
        request: ApproveAndFetchReceiptImageV1Request,
    ) -> CommandResult<ApproveAndFetchReceiptImageV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let plan = self
            .database
            .prepare_image_attempt(&request)
            .map_err(map_receipt_error)?;
        let replayed = matches!(&plan, ReceiptImageAttemptPlanV1::Replay(_));
        let response = match plan {
            ReceiptImageAttemptPlanV1::Replay(response) => response,
            ReceiptImageAttemptPlanV1::Download {
                attempt_id,
                download_token,
                normalized_url,
                approved_display_host,
            } => {
                let result = self
                    .receipt_image_downloader
                    .download(normalized_url, approved_display_host)
                    .await;
                self.database
                    .finalize_image_attempt(&request, attempt_id, &download_token, result)
                    .map_err(map_receipt_error)?
            }
        };
        validate_response_header(
            response.schema_version,
            response.request_id,
            request.request_id,
        )?;
        if response.validate().is_err()
            || response.candidate_id != request.candidate_id
            || replayed != (response.replay_status == ReplayStatusV1::Replayed)
        {
            return Err(internal_data_error());
        }
        Ok(response)
    }
}

fn validate_analyze_response(
    response: &AnalyzeReceiptV1Response,
    request: &AnalyzeReceiptV1Request,
    expected_replay: ReplayStatusV1,
    envelope: Option<&crate::ReceiptExtractionEnvelopeV1>,
) -> CommandResult<()> {
    validate_response_header(
        response.schema_version,
        response.request_id,
        request.request_id,
    )?;
    if response.validate().is_err()
        || response.replay_status != expected_replay
        || response.parsed.source_id != request.source_id
        || response.order.source_id != request.source_id
        || envelope.is_some_and(|value| response.processing != value.processing)
    {
        return Err(internal_data_error());
    }
    Ok(())
}

fn validate_response_header(
    schema_version: u8,
    response_request_id: crate::RequestId,
    expected_request_id: crate::RequestId,
) -> CommandResult<()> {
    if schema_version == SCHEMA_VERSION_V1 && response_request_id == expected_request_id {
        Ok(())
    } else {
        Err(internal_data_error())
    }
}

fn validate_mutation(
    schema_version: u8,
    response_request_id: crate::RequestId,
    expected_request_id: crate::RequestId,
    expected_revision: u64,
    new_revision: u64,
    decision: &crate::DecisionSnapshotV1,
    expected_kind: DecisionKindV1,
) -> CommandResult<()> {
    validate_response_header(schema_version, response_request_id, expected_request_id)?;
    if expected_revision.checked_add(1) != Some(new_revision)
        || decision.kind != expected_kind
        || decision.validate().is_err()
    {
        return Err(internal_data_error());
    }
    Ok(())
}

impl<D, B, C, R, I, S, G, P> ApplicationService<D, B, C, R, I, S, G, P>
where
    D: DatabasePort,
    B: BlobPort,
    C: CredentialPort,
{
    pub fn get_foundation_snapshot_v1(
        &self,
        request: GetFoundationSnapshotV1Request,
    ) -> CommandResult<GetFoundationSnapshotV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let state = self
            .database
            .load_foundation_state(MAX_RECENT_JOBS)
            .map_err(map_storage_error)?;
        let snapshot = FoundationSnapshotV1 {
            schema_version: SCHEMA_VERSION_V1,
            versions: state.versions,
            local_settings: state.local_settings,
            credential_references: state.credential_references,
            recent_jobs: state.recent_jobs,
            catalog: CatalogSnapshotV1 { items: Vec::new() },
        };
        snapshot.validate().map_err(|_| internal_data_error())?;

        Ok(GetFoundationSnapshotV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            snapshot,
        })
    }

    pub fn run_storage_check_v1(
        &self,
        request: RunStorageCheckV1Request,
    ) -> CommandResult<RunStorageCheckV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;

        let expected_digest =
            Sha256Digest::parse(format!("{:x}", Sha256::digest(STORAGE_CHECK_BYTES)))
                .map_err(|_| internal_data_error())?;
        let blob = self
            .blobs
            .put_verified(
                &expected_digest,
                STORAGE_CHECK_BYTES,
                STORAGE_CHECK_BYTES.len() as u64,
            )
            .map_err(map_storage_error)?;
        if blob.digest != expected_digest || blob.byte_length != STORAGE_CHECK_BYTES.len() as u64 {
            return Err(internal_data_error());
        }

        let record = self
            .database
            .record_storage_check_and_enqueue(request.request_id, &blob)
            .map_err(map_storage_error)?;

        Ok(RunStorageCheckV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            check_id: record.check_id,
            job_id: record.job_id,
            replay_status: record.replay_status,
        })
    }

    pub fn save_credential_v1(
        &self,
        request: SaveCredentialV1Request,
    ) -> CommandResult<SaveCredentialV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let plan = self
            .database
            .reserve_credential_save(request.request_id, request.provider, &request.display_label)
            .map_err(map_credential_database_error)?;

        let (credential, replay_status) = match plan {
            SaveCredentialPlanV1::Replay { reference } => (reference, ReplayStatusV1::Replayed),
            SaveCredentialPlanV1::WriteSecret {
                locator,
                pending_reference,
            } => {
                self.credentials
                    .put(&locator, &request.secret)
                    .map_err(map_credential_error)?;
                let reference = self
                    .database
                    .activate_credential(request.request_id, pending_reference.credential_id)
                    .map_err(map_credential_database_error)?;
                (reference, ReplayStatusV1::Created)
            }
        };
        credential.validate().map_err(|_| internal_data_error())?;
        if credential.status != CredentialStatusV1::Active {
            return Err(internal_data_error());
        }

        Ok(SaveCredentialV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            credential,
            replay_status,
        })
    }

    pub fn delete_credential_v1(
        &self,
        request: DeleteCredentialV1Request,
    ) -> CommandResult<DeleteCredentialV1Response> {
        request.validate().map_err(CommandErrorV1::from)?;
        let plan = self
            .database
            .prepare_credential_delete(request.request_id, request.credential_id)
            .map_err(map_credential_database_error)?;

        let (credential_id, deleted, replay_status) = match plan {
            DeleteCredentialPlanV1::Replay {
                credential_id,
                deleted,
            } => (credential_id, deleted, ReplayStatusV1::Replayed),
            DeleteCredentialPlanV1::DeleteSecret {
                locator,
                credential_id,
            } => {
                self.credentials
                    .delete(&locator)
                    .map_err(map_credential_error)?;
                self.database
                    .finish_credential_delete(request.request_id, credential_id)
                    .map_err(map_credential_database_error)?;
                (credential_id, true, ReplayStatusV1::Created)
            }
        };

        Ok(DeleteCredentialV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            credential_id,
            deleted,
            replay_status,
        })
    }
}

fn map_storage_error(error: PortError) -> CommandErrorV1 {
    map_port_error(error, false)
}

fn map_credential_database_error(error: PortError) -> CommandErrorV1 {
    map_port_error(error, true)
}

fn map_credential_error(error: PortError) -> CommandErrorV1 {
    let (code, retryable, user_action) = match error.kind {
        PortErrorKind::Unavailable => (
            ErrorCodeV1::CredentialUnavailable,
            true,
            UserActionKeyV1::Retry,
        ),
        PortErrorKind::PermissionDenied => (
            ErrorCodeV1::PermissionDenied,
            true,
            UserActionKeyV1::UnlockKeychain,
        ),
        PortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            false,
            UserActionKeyV1::StartNewRequest,
        ),
        PortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::RestartApplication,
        ),
        PortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
        ),
        PortErrorKind::Internal => (ErrorCodeV1::Internal, true, UserActionKeyV1::Retry),
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field: None,
    }
}

fn map_gmail_connector_error(error: GmailConnectorPortError) -> CommandErrorV1 {
    let (code, retryable, user_action, field) = match error.kind {
        GmailConnectorPortErrorKind::Unavailable => (
            ErrorCodeV1::ProviderUnavailable,
            true,
            UserActionKeyV1::Retry,
            None,
        ),
        GmailConnectorPortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            false,
            UserActionKeyV1::StartNewRequest,
            None,
        ),
        GmailConnectorPortErrorKind::Busy => (
            ErrorCodeV1::InvalidState,
            true,
            UserActionKeyV1::Retry,
            None,
        ),
        GmailConnectorPortErrorKind::InvalidState => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::ConnectGmail,
            None,
        ),
        GmailConnectorPortErrorKind::PermissionDenied => (
            ErrorCodeV1::PermissionDenied,
            false,
            UserActionKeyV1::ConnectGmail,
            None,
        ),
        GmailConnectorPortErrorKind::CredentialUnavailable => (
            ErrorCodeV1::CredentialUnavailable,
            true,
            UserActionKeyV1::UnlockKeychain,
            None,
        ),
        GmailConnectorPortErrorKind::ScopeTooLarge => (
            ErrorCodeV1::InvalidRequest,
            false,
            UserActionKeyV1::ConfigureGmail,
            Some(crate::SafeFieldV1::GmailLimits),
        ),
        GmailConnectorPortErrorKind::MalformedProviderOutput => (
            ErrorCodeV1::MalformedProviderOutput,
            false,
            UserActionKeyV1::Retry,
            None,
        ),
        GmailConnectorPortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::RestartApplication,
            None,
        ),
        GmailConnectorPortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
            None,
        ),
        GmailConnectorPortErrorKind::Internal => {
            (ErrorCodeV1::Internal, true, UserActionKeyV1::Retry, None)
        }
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field,
    }
}

fn map_photokit_connector_error(error: PhotoKitConnectorPortError) -> CommandErrorV1 {
    let (code, retryable, user_action, field) = match error.kind {
        PhotoKitConnectorPortErrorKind::Unavailable => (
            ErrorCodeV1::ProviderUnavailable,
            true,
            UserActionKeyV1::Retry,
            None,
        ),
        PhotoKitConnectorPortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            false,
            UserActionKeyV1::StartNewRequest,
            None,
        ),
        PhotoKitConnectorPortErrorKind::Busy => (
            ErrorCodeV1::InvalidState,
            true,
            UserActionKeyV1::Retry,
            None,
        ),
        PhotoKitConnectorPortErrorKind::InvalidState => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::ConfigurePhotoKit,
            None,
        ),
        PhotoKitConnectorPortErrorKind::PermissionDenied => (
            ErrorCodeV1::PermissionDenied,
            false,
            UserActionKeyV1::ReviewPhotoLibraryAccess,
            None,
        ),
        PhotoKitConnectorPortErrorKind::CredentialUnavailable => (
            ErrorCodeV1::CredentialUnavailable,
            true,
            UserActionKeyV1::UnlockKeychain,
            None,
        ),
        PhotoKitConnectorPortErrorKind::ScopeTooLarge => (
            ErrorCodeV1::InvalidRequest,
            false,
            UserActionKeyV1::ConfigurePhotoKit,
            Some(crate::SafeFieldV1::PhotoKitCounts),
        ),
        PhotoKitConnectorPortErrorKind::SessionExpired => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::BeginPhotoKitSetup,
            Some(crate::SafeFieldV1::PhotoKitSetupSession),
        ),
        PhotoKitConnectorPortErrorKind::SelectionTokenConsumed => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::BeginPhotoKitSetup,
            Some(crate::SafeFieldV1::PhotoKitSelectionToken),
        ),
        PhotoKitConnectorPortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::RestartApplication,
            None,
        ),
        PhotoKitConnectorPortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::ConfigurePhotoKit,
            None,
        ),
        PhotoKitConnectorPortErrorKind::Internal => {
            (ErrorCodeV1::Internal, true, UserActionKeyV1::Retry, None)
        }
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field,
    }
}

fn map_port_error(error: PortError, credential_context: bool) -> CommandErrorV1 {
    let (code, retryable, user_action) = match error.kind {
        PortErrorKind::Unavailable => (
            if credential_context {
                ErrorCodeV1::CredentialUnavailable
            } else {
                ErrorCodeV1::StorageUnavailable
            },
            true,
            UserActionKeyV1::Retry,
        ),
        PortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            false,
            UserActionKeyV1::StartNewRequest,
        ),
        PortErrorKind::PermissionDenied => (
            ErrorCodeV1::PermissionDenied,
            false,
            if credential_context {
                UserActionKeyV1::UnlockKeychain
            } else {
                UserActionKeyV1::ReviewStorage
            },
        ),
        PortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        PortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
        ),
        PortErrorKind::Internal => (
            ErrorCodeV1::Internal,
            true,
            UserActionKeyV1::RestartApplication,
        ),
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field: None,
    }
}

fn map_catalog_error(error: CatalogPortError) -> CommandErrorV1 {
    let (code, retryable, user_action) = match error.kind {
        CatalogPortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            true,
            UserActionKeyV1::RefreshCatalog,
        ),
        CatalogPortErrorKind::SnapshotExpired => (
            ErrorCodeV1::SnapshotExpired,
            true,
            UserActionKeyV1::RestartPaging,
        ),
        CatalogPortErrorKind::InvalidState => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::ReviewInbox,
        ),
        CatalogPortErrorKind::Unavailable => (
            ErrorCodeV1::StorageUnavailable,
            true,
            UserActionKeyV1::Retry,
        ),
        CatalogPortErrorKind::PermissionDenied => (
            ErrorCodeV1::PermissionDenied,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        CatalogPortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        CatalogPortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
        ),
        CatalogPortErrorKind::Internal => (
            ErrorCodeV1::Internal,
            true,
            UserActionKeyV1::RestartApplication,
        ),
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field: None,
    }
}

fn map_receipt_error(error: ReceiptPortError) -> CommandErrorV1 {
    let (code, retryable, user_action) = match error.kind {
        ReceiptPortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            true,
            UserActionKeyV1::RefreshReceipts,
        ),
        ReceiptPortErrorKind::SnapshotExpired => (
            ErrorCodeV1::SnapshotExpired,
            true,
            UserActionKeyV1::RestartPaging,
        ),
        ReceiptPortErrorKind::InvalidState => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::ReviewReceipt,
        ),
        ReceiptPortErrorKind::Unavailable => (
            ErrorCodeV1::StorageUnavailable,
            true,
            UserActionKeyV1::Retry,
        ),
        ReceiptPortErrorKind::PermissionDenied => (
            ErrorCodeV1::PermissionDenied,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        ReceiptPortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        ReceiptPortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
        ),
        ReceiptPortErrorKind::Internal => (
            ErrorCodeV1::Internal,
            true,
            UserActionKeyV1::RestartApplication,
        ),
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field: None,
    }
}

fn map_outfit_error(error: OutfitPortError) -> CommandErrorV1 {
    let (code, retryable, user_action) = match error.kind {
        OutfitPortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            true,
            UserActionKeyV1::RefreshCatalog,
        ),
        OutfitPortErrorKind::SnapshotExpired => (
            ErrorCodeV1::SnapshotExpired,
            true,
            UserActionKeyV1::RestartPaging,
        ),
        OutfitPortErrorKind::InvalidState => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::RefreshCatalog,
        ),
        OutfitPortErrorKind::Unavailable => (
            ErrorCodeV1::StorageUnavailable,
            true,
            UserActionKeyV1::Retry,
        ),
        OutfitPortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        OutfitPortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
        ),
        OutfitPortErrorKind::Internal => (
            ErrorCodeV1::Internal,
            true,
            UserActionKeyV1::RestartApplication,
        ),
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field: None,
    }
}

fn map_photo_analysis_error(error: PhotoAnalysisPortError) -> CommandErrorV1 {
    let (code, retryable, user_action) = match error.kind {
        PhotoAnalysisPortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            true,
            UserActionKeyV1::RefreshCatalog,
        ),
        PhotoAnalysisPortErrorKind::SnapshotExpired => (
            ErrorCodeV1::SnapshotExpired,
            true,
            UserActionKeyV1::RestartPaging,
        ),
        PhotoAnalysisPortErrorKind::InvalidState => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::ReviewInbox,
        ),
        PhotoAnalysisPortErrorKind::Unavailable => (
            ErrorCodeV1::StorageUnavailable,
            true,
            UserActionKeyV1::Retry,
        ),
        PhotoAnalysisPortErrorKind::PermissionDenied => (
            ErrorCodeV1::PermissionDenied,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        PhotoAnalysisPortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        PhotoAnalysisPortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
        ),
        PhotoAnalysisPortErrorKind::Internal => (
            ErrorCodeV1::Internal,
            true,
            UserActionKeyV1::RestartApplication,
        ),
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field: None,
    }
}

fn map_reconciliation_error(error: ReconciliationPortError) -> CommandErrorV1 {
    let (code, retryable, user_action) = match error.kind {
        ReconciliationPortErrorKind::Conflict => (
            ErrorCodeV1::RequestConflict,
            true,
            UserActionKeyV1::RefreshCatalog,
        ),
        ReconciliationPortErrorKind::SnapshotExpired => (
            ErrorCodeV1::SnapshotExpired,
            true,
            UserActionKeyV1::RestartPaging,
        ),
        ReconciliationPortErrorKind::InvalidState => (
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::ReviewInbox,
        ),
        ReconciliationPortErrorKind::Unavailable => (
            ErrorCodeV1::StorageUnavailable,
            true,
            UserActionKeyV1::Retry,
        ),
        ReconciliationPortErrorKind::PermissionDenied => (
            ErrorCodeV1::PermissionDenied,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        ReconciliationPortErrorKind::DataIntegrity => (
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::ReviewStorage,
        ),
        ReconciliationPortErrorKind::NotFound => (
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
        ),
        ReconciliationPortErrorKind::Internal => (
            ErrorCodeV1::Internal,
            true,
            UserActionKeyV1::RestartApplication,
        ),
    };
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code,
        retryable,
        user_action,
        field: None,
    }
}

fn map_segmentation_boundary_error(error: crate::SegmentationProviderError) -> CommandErrorV1 {
    match error.kind {
        SegmentationProviderErrorKind::InvalidRequest
        | SegmentationProviderErrorKind::MalformedOutput => CommandErrorV1 {
            schema_version: SCHEMA_VERSION_V1,
            code: ErrorCodeV1::MalformedProviderOutput,
            retryable: false,
            user_action: UserActionKeyV1::ReviewInbox,
            field: None,
        },
        SegmentationProviderErrorKind::Internal => CommandErrorV1 {
            schema_version: SCHEMA_VERSION_V1,
            code: ErrorCodeV1::Internal,
            retryable: true,
            user_action: UserActionKeyV1::Retry,
            field: None,
        },
    }
}

fn map_person_detection_boundary_error(
    error: crate::PersonDetectionProviderError,
) -> CommandErrorV1 {
    match error.kind {
        crate::PersonDetectionProviderErrorKind::InvalidRequest
        | crate::PersonDetectionProviderErrorKind::MalformedOutput => CommandErrorV1 {
            schema_version: SCHEMA_VERSION_V1,
            code: ErrorCodeV1::MalformedProviderOutput,
            retryable: false,
            user_action: UserActionKeyV1::ReviewInbox,
            field: None,
        },
        crate::PersonDetectionProviderErrorKind::Internal => CommandErrorV1 {
            schema_version: SCHEMA_VERSION_V1,
            code: ErrorCodeV1::Internal,
            retryable: true,
            user_action: UserActionKeyV1::Retry,
            field: None,
        },
    }
}

fn classify_receipt_provider_failure(error: ReceiptProviderError) -> ReceiptAnalysisFailureV1 {
    match error.kind {
        ReceiptProviderErrorKind::Unavailable => ReceiptAnalysisFailureV1::ProviderUnavailable,
        ReceiptProviderErrorKind::MalformedOutput => {
            ReceiptAnalysisFailureV1::ProviderMalformedOutput
        }
        ReceiptProviderErrorKind::Internal => ReceiptAnalysisFailureV1::ProviderInternal,
    }
}

fn map_receipt_analysis_failure(failure: ReceiptAnalysisFailureV1) -> CommandErrorV1 {
    match failure {
        ReceiptAnalysisFailureV1::ProviderUnavailable => CommandErrorV1 {
            schema_version: SCHEMA_VERSION_V1,
            code: ErrorCodeV1::ProviderUnavailable,
            retryable: true,
            user_action: UserActionKeyV1::Retry,
            field: None,
        },
        ReceiptAnalysisFailureV1::ProviderMalformedOutput
        | ReceiptAnalysisFailureV1::OutputValidationFailed => malformed_provider_error(),
        ReceiptAnalysisFailureV1::ProviderInternal => CommandErrorV1 {
            schema_version: SCHEMA_VERSION_V1,
            code: ErrorCodeV1::Internal,
            retryable: true,
            user_action: UserActionKeyV1::Retry,
            field: None,
        },
    }
}

fn malformed_provider_error() -> CommandErrorV1 {
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code: ErrorCodeV1::MalformedProviderOutput,
        retryable: false,
        user_action: UserActionKeyV1::ReviewReceipt,
        field: None,
    }
}

fn internal_data_error() -> CommandErrorV1 {
    CommandErrorV1 {
        schema_version: SCHEMA_VERSION_V1,
        code: ErrorCodeV1::DataIntegrity,
        retryable: false,
        user_action: UserActionKeyV1::ReviewStorage,
        field: None,
    }
}
