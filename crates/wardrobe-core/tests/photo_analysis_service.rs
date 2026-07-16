use std::cell::Cell;

use wardrobe_core::*;

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn artifact(
    scope_id: PhotoScopeId,
    source_revision_id: PhotoSourceRevisionId,
    mode: SegmentationRequestModeKindV1,
    rectangle: RectV1,
) -> PhotoArtifactV1 {
    PhotoArtifactV1 {
        artifact_id: PhotoArtifactId::new_v4(),
        kind: PhotoArtifactKindV1::RectangleSourceCrop,
        artifact_schema_revision: PHOTO_ARTIFACT_SCHEMA_REVISION_V1.to_owned(),
        artifact_revision: RECTANGLE_SOURCE_CROP_REVISION_V1.to_owned(),
        scope_id,
        source_revision_id,
        source_revision_sha256: digest(b"source-revision"),
        input_blob_sha256: digest(b"blob"),
        media_type: PhotoMediaTypeV1::ImagePng,
        source_width: 2,
        source_height: 2,
        rectangle: Some(rectangle),
        preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
        provider_contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
        provider_id: UNAVAILABLE_SEGMENTATION_PROVIDER_ID_V1.to_owned(),
        provider_revision: UNAVAILABLE_SEGMENTATION_PROVIDER_REVISION_V1.to_owned(),
        model_revision: None,
        request_mode: mode,
        prompt_parameters_sha256: digest(b"prompt"),
        quality_gate_revision: PHOTO_QUALITY_GATE_REVISION_V1.to_owned(),
        quality_approved: false,
        segmentation_outcome: PhotoSegmentationOutcomeCodeV1::Unavailable,
        unavailable_reason: Some(SegmentationUnavailableReasonV1::ReviewedModelPackAbsent),
        failure_code: None,
        parent_artifact_ids: vec![],
        provenance_sha256: digest(b"provenance"),
        artifact_sha256: digest(b"artifact"),
    }
}

struct PhotoRepository {
    calls: [Cell<u32>; 7],
    corrupt_read_hash: bool,
    corrupt_read_header: bool,
}

impl PhotoRepository {
    fn new() -> Self {
        Self {
            calls: std::array::from_fn(|_| Cell::new(0)),
            corrupt_read_hash: false,
            corrupt_read_header: false,
        }
    }

    fn called(&self, index: usize) {
        self.calls[index].set(self.calls[index].get() + 1);
    }
}

impl PhotoAnalysisPort for PhotoRepository {
    fn list_imported_photo_roots(
        &self,
        request: &ListImportedPhotoRootsV1Request,
    ) -> PhotoAnalysisPortResult<ListImportedPhotoRootsV1Response> {
        self.called(0);
        Ok(ListImportedPhotoRootsV1Response {
            schema_version: 1,
            request_id: request.request_id,
            roots: vec![ImportedPhotoRootV1 {
                import_root_id: ImportRootId::new_v4(),
                completed_scan_id: PhotoImportScanId::new_v4(),
                manifest_generation: 4,
                member_count: 1,
                eligible_count: 1,
                quarantined_count: 0,
            }],
            total_count: 1,
            evidence_generation: 3,
            next_cursor: None,
        })
    }

    fn create_photo_scope(
        &self,
        request: &CreatePhotoScopeV1Request,
    ) -> PhotoAnalysisPortResult<CreatePhotoScopeV1Response> {
        self.called(1);
        Ok(CreatePhotoScopeV1Response {
            schema_version: 1,
            request_id: request.request_id,
            scope: PhotoScopeV1 {
                scope_id: PhotoScopeId::new_v4(),
                import_root_id: request.import_root_id,
                completed_scan_id: PhotoImportScanId::new_v4(),
                manifest_generation: request.expected_manifest_generation,
                member_count: 1,
                eligible_count: 1,
                quarantined_count: 0,
                membership_sha256: digest(b"members"),
            },
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn analyze_photo_scope(
        &self,
        request: &AnalyzePhotoScopeV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PhotoAnalysisPortResult<AnalyzePhotoScopeV1Response> {
        self.called(2);
        let segmentation_request = SegmentationRequestV1 {
            contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
            request_handle: SegmentationRequestHandle::new_v4(),
            source_revision_sha256: digest(b"source-revision"),
            input_blob_sha256: digest(b"blob"),
            pixels: CanonicalSrgbPixelBufferV1::new(vec![0; 12], 2, 2).unwrap(),
            width: 2,
            height: 2,
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            mode: SegmentationRequestModeV1::Automatic,
        };
        assert!(matches!(
            provider.segment(&segmentation_request).unwrap().result,
            SegmentationResultV1::Unavailable {
                reason: SegmentationUnavailableReasonV1::ReviewedModelPackAbsent
            }
        ));
        Ok(AnalyzePhotoScopeV1Response {
            schema_version: 1,
            request_id: request.request_id,
            scope_id: request.scope_id,
            run_id: PhotoAnalysisRunId::new_v4(),
            state: PhotoAnalysisRunStateV1::Completed,
            member_count: 1,
            completed_count: 1,
            needs_review_count: 1,
            skipped_count: 0,
            failed_count: 0,
            photo_revision: 1,
            evidence_generation: 4,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn list_photo_observations(
        &self,
        request: &ListPhotoObservationsV1Request,
    ) -> PhotoAnalysisPortResult<ListPhotoObservationsV1Response> {
        self.called(3);
        let source_revision_id = PhotoSourceRevisionId::new_v4();
        Ok(ListPhotoObservationsV1Response {
            schema_version: 1,
            request_id: request.request_id,
            scope_id: request.scope_id,
            state: request.state,
            observations: vec![PhotoObservationV1 {
                observation_id: PhotoObservationId::new_v4(),
                scope_id: request.scope_id,
                source_revision_id,
                state: PhotoObservationStateV1::NeedsReview,
                artifact: artifact(
                    request.scope_id,
                    source_revision_id,
                    SegmentationRequestModeKindV1::Automatic,
                    RectV1 {
                        x: 0,
                        y: 0,
                        width: 2,
                        height: 2,
                    },
                ),
                review_head: None,
            }],
            total_count: 1,
            photo_revision: 1,
            evidence_generation: 4,
            next_cursor: None,
        })
    }

    fn read_photo_artifact(
        &self,
        request: &ReadPhotoArtifactV1Request,
    ) -> PhotoAnalysisPortResult<ReadPhotoArtifactV1Response> {
        self.called(4);
        let bytes = BoundedPhotoArtifactBytesV1::new(vec![1, 2, 3]).unwrap();
        Ok(ReadPhotoArtifactV1Response {
            schema_version: 1,
            request_id: if self.corrupt_read_header {
                RequestId::new_v4()
            } else {
                request.request_id
            },
            artifact_id: request.artifact_id,
            media_type: PhotoMediaTypeV1::ImagePng,
            width: 1,
            height: 1,
            bytes_sha256: if self.corrupt_read_hash {
                digest(b"wrong")
            } else {
                Sha256Digest::from_bytes(bytes.as_slice())
            },
            bytes,
        })
    }

    fn prompt_photo_observation(
        &self,
        request: &PromptPhotoObservationV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PhotoAnalysisPortResult<PromptPhotoObservationV1Response> {
        self.called(5);
        let segmentation_request = SegmentationRequestV1 {
            contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
            request_handle: SegmentationRequestHandle::new_v4(),
            source_revision_sha256: digest(b"source-revision"),
            input_blob_sha256: digest(b"blob"),
            pixels: CanonicalSrgbPixelBufferV1::new(vec![0; 12], 2, 2).unwrap(),
            width: 2,
            height: 2,
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            mode: SegmentationRequestModeV1::Interactive {
                box_rectangle: request.box_rectangle,
                positive_points: request.positive_points.clone(),
                negative_points: request.negative_points.clone(),
            },
        };
        provider.segment(&segmentation_request).unwrap();
        let scope_id = PhotoScopeId::new_v4();
        let source_revision_id = PhotoSourceRevisionId::new_v4();
        Ok(PromptPhotoObservationV1Response {
            schema_version: 1,
            request_id: request.request_id,
            observation: PhotoObservationV1 {
                observation_id: request.observation_id,
                scope_id,
                source_revision_id,
                state: PhotoObservationStateV1::NeedsReview,
                artifact: artifact(
                    scope_id,
                    source_revision_id,
                    SegmentationRequestModeKindV1::Interactive,
                    request.box_rectangle,
                ),
                review_head: None,
            },
            photo_revision: 2,
            evidence_generation: 5,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn review_photo_observation(
        &self,
        request: &ReviewPhotoObservationV1Request,
    ) -> PhotoAnalysisPortResult<ReviewPhotoObservationV1Response> {
        self.called(6);
        let scope_id = PhotoScopeId::new_v4();
        let source_revision_id = PhotoSourceRevisionId::new_v4();
        let rectangle = request.replacement_rectangle.unwrap_or(RectV1 {
            x: 0,
            y: 0,
            width: 2,
            height: 2,
        });
        let artifact = artifact(
            scope_id,
            source_revision_id,
            SegmentationRequestModeKindV1::Interactive,
            rectangle,
        );
        let decision = PhotoReviewDecisionV1 {
            decision_id: PhotoReviewDecisionId::new_v4(),
            observation_id: request.observation_id,
            action: request.action,
            selected_artifact_id: matches!(
                request.action,
                PhotoReviewActionV1::ConfirmCrop | PhotoReviewActionV1::ReplaceCrop
            )
            .then_some(artifact.artifact_id),
            photo_revision: request.expected_photo_revision + 1,
        };
        Ok(ReviewPhotoObservationV1Response {
            schema_version: 1,
            request_id: request.request_id,
            observation: PhotoObservationV1 {
                observation_id: request.observation_id,
                scope_id,
                source_revision_id,
                state: request.action.resulting_state(),
                artifact,
                review_head: Some(PhotoReviewHeadV1 {
                    state: request.action.resulting_state(),
                    decision: decision.clone(),
                }),
            },
            decision,
            new_photo_revision: request.expected_photo_revision + 1,
            replay_status: ReplayStatusV1::Created,
        })
    }
}

#[test]
fn service_forwards_all_photo_commands_and_the_checked_provider() {
    let service = ApplicationService::new(PhotoRepository::new(), (), ())
        .with_garment_segmentation_provider(UnavailableGarmentSegmentationProviderV1);
    let root_id = ImportRootId::new_v4();
    let scope_id = PhotoScopeId::new_v4();
    let observation_id = PhotoObservationId::new_v4();
    let artifact_id = PhotoArtifactId::new_v4();

    service
        .list_imported_photo_roots_v1(ListImportedPhotoRootsV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            cursor: None,
            limit: 10,
        })
        .unwrap();
    service
        .create_photo_scope_v1(CreatePhotoScopeV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            import_root_id: root_id,
            expected_manifest_generation: 4,
        })
        .unwrap();
    service
        .analyze_photo_scope_v1(AnalyzePhotoScopeV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            scope_id,
        })
        .unwrap();
    service
        .list_photo_observations_v1(ListPhotoObservationsV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            scope_id,
            state: PhotoObservationStateV1::NeedsReview,
            cursor: None,
            limit: 10,
        })
        .unwrap();
    service
        .read_photo_artifact_v1(ReadPhotoArtifactV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            artifact_id,
        })
        .unwrap();
    service
        .prompt_photo_observation_v1(PromptPhotoObservationV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            observation_id,
            box_rectangle: RectV1 {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            positive_points: vec![],
            negative_points: vec![],
        })
        .unwrap();
    service
        .review_photo_observation_v1(ReviewPhotoObservationV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            observation_id,
            action: PhotoReviewActionV1::ConfirmCrop,
            replacement_rectangle: None,
            expected_photo_revision: 2,
        })
        .unwrap();

    assert_eq!(
        service.database().calls.each_ref().map(|calls| calls.get()),
        [1; 7]
    );
}

#[test]
fn service_rejects_bad_artifact_hashes_and_replay_headers() {
    for repository in [
        PhotoRepository {
            corrupt_read_hash: true,
            ..PhotoRepository::new()
        },
        PhotoRepository {
            corrupt_read_header: true,
            ..PhotoRepository::new()
        },
    ] {
        let service = ApplicationService::new(repository, (), ());
        let error = service
            .read_photo_artifact_v1(ReadPhotoArtifactV1Request {
                schema_version: 1,
                request_id: RequestId::new_v4(),
                artifact_id: PhotoArtifactId::new_v4(),
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCodeV1::DataIntegrity);
    }
}

struct OwnerRepository {
    base: PhotoRepository,
    detection_calls: Cell<u32>,
    owner_calls: [Cell<u32>; 6],
}

impl OwnerRepository {
    fn new() -> Self {
        Self {
            base: PhotoRepository::new(),
            detection_calls: Cell::new(0),
            owner_calls: std::array::from_fn(|_| Cell::new(0)),
        }
    }

    fn review(
        &self,
        owner_review_id: PhotoOwnerReviewId,
        state: PhotoOwnerReviewStateV1,
        detection_revision: u64,
        owner_revision: u64,
        photo_revision: u64,
        selected_person_instance_id: Option<PhotoPersonInstanceId>,
    ) -> PhotoOwnerReviewV1 {
        let source_revision_id = PhotoSourceRevisionId::new_v4();
        let source_revision_sha256 = digest(b"owner source revision");
        let terminal_detection_state = match state {
            PhotoOwnerReviewStateV1::RetryableFailure => {
                PersonDetectionTerminalStateV1::RetryableFailure
            }
            PhotoOwnerReviewStateV1::PermanentUnavailable => {
                PersonDetectionTerminalStateV1::PermanentUnavailable
            }
            PhotoOwnerReviewStateV1::Overflow => PersonDetectionTerminalStateV1::Overflow,
            _ if selected_person_instance_id.is_some() => {
                PersonDetectionTerminalStateV1::SucceededInstances
            }
            _ => PersonDetectionTerminalStateV1::SucceededZero,
        };
        let instances = selected_person_instance_id
            .map(|person_instance_id| {
                vec![PhotoPersonInstanceV1 {
                    person_instance_id,
                    owner_review_id,
                    source_revision_id,
                    source_revision_sha256: source_revision_sha256.clone(),
                    source_kind: PersonEvidenceKindV1::AppleVision,
                    rectangle: RectV1 {
                        x: 0,
                        y: 0,
                        width: 2,
                        height: 2,
                    },
                    confidence_basis_points: Some(9_000),
                    provider_revision: Some(
                        APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
                    ),
                }]
            })
            .unwrap_or_default();
        PhotoOwnerReviewV1 {
            owner_review_id,
            source_revision_id,
            source_revision_sha256,
            preview_id: PhotoOwnerPreviewId::new_v4(),
            terminal_attempt_id: PhotoPersonDetectionAttemptId::new_v4(),
            terminal_detection_state,
            state,
            instances,
            provider_contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
            provider_revision: APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            vision_request_revision: 2,
            safe_reason_code: None,
            detection_revision,
            owner_head_revision: owner_revision,
            photo_revision,
        }
    }
}

impl PhotoAnalysisPort for OwnerRepository {
    fn list_imported_photo_roots(
        &self,
        request: &ListImportedPhotoRootsV1Request,
    ) -> PhotoAnalysisPortResult<ListImportedPhotoRootsV1Response> {
        self.base.list_imported_photo_roots(request)
    }

    fn create_photo_scope(
        &self,
        request: &CreatePhotoScopeV1Request,
    ) -> PhotoAnalysisPortResult<CreatePhotoScopeV1Response> {
        self.base.create_photo_scope(request)
    }

    fn analyze_photo_scope(
        &self,
        request: &AnalyzePhotoScopeV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PhotoAnalysisPortResult<AnalyzePhotoScopeV1Response> {
        self.base.analyze_photo_scope(request, provider)
    }

    fn detect_photo_scope_people(
        &self,
        request: &DetectPhotoScopePeopleV1Request,
        provider: &dyn LocalPersonDetectionProviderV1,
    ) -> PhotoAnalysisPortResult<DetectPhotoScopePeopleV1Response> {
        self.detection_calls.set(self.detection_calls.get() + 1);
        let detection_request = PersonDetectionRequestV1 {
            contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
            request_handle: PersonDetectionRequestHandle::new_v4(),
            source_revision_sha256: digest(b"owner source revision"),
            input_blob_sha256: digest(b"owner source blob"),
            width: 2,
            height: 2,
            rgb_row_stride: 6,
            pixels: CanonicalSrgbPixelBufferV1::new(vec![0; 12], 2, 2).unwrap(),
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
        };
        assert_eq!(
            provider
                .detect(&detection_request)
                .unwrap()
                .terminal_state(),
            PersonDetectionTerminalStateV1::SucceededZero
        );
        Ok(DetectPhotoScopePeopleV1Response {
            schema_version: 1,
            request_id: request.request_id,
            scope_id: request.scope_id,
            run_id: PhotoAnalysisRunId::new_v4(),
            state: PhotoAnalysisRunStateV1::Completed,
            member_count: 1,
            completed_count: 1,
            terminal_review_count: 1,
            instances_available_count: 0,
            no_person_detected_count: 1,
            overflow_count: 0,
            retryable_failure_count: 0,
            permanent_unavailable_count: 0,
            skipped_count: 0,
            photo_revision: 1,
            owner_revision: 0,
            evidence_generation: 1,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn list_photo_observations(
        &self,
        request: &ListPhotoObservationsV1Request,
    ) -> PhotoAnalysisPortResult<ListPhotoObservationsV1Response> {
        self.base.list_photo_observations(request)
    }

    fn read_photo_artifact(
        &self,
        request: &ReadPhotoArtifactV1Request,
    ) -> PhotoAnalysisPortResult<ReadPhotoArtifactV1Response> {
        self.base.read_photo_artifact(request)
    }

    fn prompt_photo_observation(
        &self,
        request: &PromptPhotoObservationV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PhotoAnalysisPortResult<PromptPhotoObservationV1Response> {
        self.base.prompt_photo_observation(request, provider)
    }

    fn review_photo_observation(
        &self,
        request: &ReviewPhotoObservationV1Request,
    ) -> PhotoAnalysisPortResult<ReviewPhotoObservationV1Response> {
        self.base.review_photo_observation(request)
    }

    fn list_photo_owner_reviews(
        &self,
        request: &ListPhotoOwnerReviewsV1Request,
    ) -> PhotoAnalysisPortResult<ListPhotoOwnerReviewsV1Response> {
        self.owner_calls[0].set(self.owner_calls[0].get() + 1);
        Ok(ListPhotoOwnerReviewsV1Response {
            schema_version: 1,
            request_id: request.request_id,
            state: request.state,
            reviews: vec![self.review(PhotoOwnerReviewId::new_v4(), request.state, 1, 0, 1, None)],
            next_cursor: None,
            photo_revision: 1,
            owner_revision: 0,
        })
    }

    fn read_photo_owner_preview(
        &self,
        request: &ReadPhotoOwnerPreviewV1Request,
    ) -> PhotoAnalysisPortResult<ReadPhotoOwnerPreviewV1Response> {
        self.owner_calls[1].set(self.owner_calls[1].get() + 1);
        let bytes = BoundedPhotoArtifactBytesV1::new(vec![1, 2, 3]).unwrap();
        Ok(ReadPhotoOwnerPreviewV1Response {
            schema_version: 1,
            request_id: request.request_id,
            owner_review_id: request.owner_review_id,
            preview_id: request.preview_id,
            media_type: PhotoMediaTypeV1::ImagePng,
            width: 1,
            height: 1,
            byte_length: 3,
            bytes_sha256: Sha256Digest::from_bytes(bytes.as_slice()),
            bytes,
        })
    }

    fn decide_photo_owner(
        &self,
        request: &DecidePhotoOwnerV1Request,
    ) -> PhotoAnalysisPortResult<DecidePhotoOwnerV1Response> {
        self.owner_calls[2].set(self.owner_calls[2].get() + 1);
        let state = if request.selected_person_instance_id.is_some() {
            PhotoOwnerReviewStateV1::InstancesAvailable
        } else {
            PhotoOwnerReviewStateV1::NoPersonDetected
        };
        let decision = PhotoOwnerDecisionV1 {
            owner_decision_id: PhotoOwnerDecisionId::new_v4(),
            owner_review_id: request.owner_review_id,
            action: request.action,
            selected_person_instance_id: request.selected_person_instance_id,
            supersedes_owner_decision_id: None,
            detection_revision: request.expected_detection_revision,
            owner_revision: request.expected_owner_head_revision + 1,
            photo_revision: request.expected_photo_revision + 1,
        };
        Ok(DecidePhotoOwnerV1Response {
            schema_version: 1,
            request_id: request.request_id,
            review: self.review(
                request.owner_review_id,
                state,
                request.expected_detection_revision,
                decision.owner_revision,
                decision.photo_revision,
                request.selected_person_instance_id,
            ),
            decision,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn correct_photo_owner(
        &self,
        request: &CorrectPhotoOwnerV1Request,
    ) -> PhotoAnalysisPortResult<CorrectPhotoOwnerV1Response> {
        self.owner_calls[3].set(self.owner_calls[3].get() + 1);
        let state = if request.selected_person_instance_id.is_some() {
            PhotoOwnerReviewStateV1::InstancesAvailable
        } else {
            PhotoOwnerReviewStateV1::NoPersonDetected
        };
        let decision = PhotoOwnerDecisionV1 {
            owner_decision_id: PhotoOwnerDecisionId::new_v4(),
            owner_review_id: request.owner_review_id,
            action: request.action,
            selected_person_instance_id: request.selected_person_instance_id,
            supersedes_owner_decision_id: Some(request.superseded_owner_decision_id),
            detection_revision: request.expected_detection_revision,
            owner_revision: request.expected_owner_head_revision + 1,
            photo_revision: request.expected_photo_revision + 1,
        };
        Ok(CorrectPhotoOwnerV1Response {
            schema_version: 1,
            request_id: request.request_id,
            review: self.review(
                request.owner_review_id,
                state,
                request.expected_detection_revision,
                decision.owner_revision,
                decision.photo_revision,
                request.selected_person_instance_id,
            ),
            decision,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn correct_photo_person_detection(
        &self,
        request: &CorrectPhotoPersonDetectionV1Request,
    ) -> PhotoAnalysisPortResult<CorrectPhotoPersonDetectionV1Response> {
        self.owner_calls[4].set(self.owner_calls[4].get() + 1);
        let mut review = self.review(
            request.owner_review_id,
            PhotoOwnerReviewStateV1::InstancesAvailable,
            request.expected_detection_revision + 1,
            request.expected_owner_head_revision,
            request.expected_photo_revision + 1,
            None,
        );
        review.terminal_attempt_id = request.expected_terminal_attempt_id;
        let instance = PhotoPersonInstanceV1 {
            person_instance_id: PhotoPersonInstanceId::new_v4(),
            owner_review_id: request.owner_review_id,
            source_revision_id: review.source_revision_id,
            source_revision_sha256: review.source_revision_sha256.clone(),
            source_kind: PersonEvidenceKindV1::ManualUserRectangle,
            rectangle: request.manual_rectangle,
            confidence_basis_points: None,
            provider_revision: None,
        };
        review.instances.push(instance.clone());
        Ok(CorrectPhotoPersonDetectionV1Response {
            schema_version: 1,
            request_id: request.request_id,
            review,
            instance,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn retry_photo_person_detection(
        &self,
        request: &RetryPhotoPersonDetectionV1Request,
    ) -> PhotoAnalysisPortResult<RetryPhotoPersonDetectionV1Response> {
        self.owner_calls[5].set(self.owner_calls[5].get() + 1);
        Ok(RetryPhotoPersonDetectionV1Response {
            schema_version: 1,
            request_id: request.request_id,
            owner_review_id: request.owner_review_id,
            detection_revision: request.expected_detection_revision + 1,
            owner_revision: request.expected_owner_head_revision,
            photo_revision: request.expected_photo_revision + 1,
            replay_status: ReplayStatusV1::Created,
        })
    }
}

struct ZeroPersonProvider;

impl LocalPersonDetectionProviderV1 for ZeroPersonProvider {
    fn describe(&self) -> PersonDetectionProviderDescriptorV1 {
        PersonDetectionProviderDescriptorV1 {
            contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
            provider_revision: APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            vision_request_revision: 2,
            os_build: "25A123".to_owned(),
            vision_framework_build: "1.0.0".to_owned(),
        }
    }

    fn detect(
        &self,
        request: &PersonDetectionRequestV1,
    ) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
        Ok(PersonDetectionOutcomeV1 {
            contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
            request_handle: request.request_handle,
            source_revision_sha256: request.source_revision_sha256.clone(),
            input_blob_sha256: request.input_blob_sha256.clone(),
            result: PersonDetectionResultV1::SucceededZero,
        })
    }
}

#[test]
fn service_forwards_and_checks_all_owner_authority_apis() {
    let service = ApplicationService::new(OwnerRepository::new(), (), ());
    service
        .detect_photo_scope_people_v1(
            DetectPhotoScopePeopleV1Request {
                schema_version: 1,
                request_id: RequestId::new_v4(),
                scope_id: PhotoScopeId::new_v4(),
            },
            &ZeroPersonProvider,
        )
        .unwrap();
    let owner_review_id = PhotoOwnerReviewId::new_v4();
    let preview_id = PhotoOwnerPreviewId::new_v4();
    let person_instance_id = PhotoPersonInstanceId::new_v4();

    service
        .list_photo_owner_reviews_v1(ListPhotoOwnerReviewsV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            state: PhotoOwnerReviewStateV1::RetryableFailure,
            cursor: None,
            limit: 10,
        })
        .unwrap();
    service
        .read_photo_owner_preview_v1(ReadPhotoOwnerPreviewV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            owner_review_id,
            preview_id,
        })
        .unwrap();
    service
        .decide_photo_owner_v1(DecidePhotoOwnerV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            owner_review_id,
            action: PhotoOwnerActionV1::SelectPerson,
            selected_person_instance_id: Some(person_instance_id),
            expected_detection_revision: 1,
            expected_owner_head_revision: 0,
            expected_photo_revision: 1,
        })
        .unwrap();
    service
        .correct_photo_owner_v1(CorrectPhotoOwnerV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            owner_review_id,
            superseded_owner_decision_id: PhotoOwnerDecisionId::new_v4(),
            action: PhotoOwnerActionV1::OwnerAbsent,
            selected_person_instance_id: None,
            expected_detection_revision: 1,
            expected_owner_head_revision: 1,
            expected_photo_revision: 2,
        })
        .unwrap();
    let terminal_attempt_id = PhotoPersonDetectionAttemptId::new_v4();
    service
        .correct_photo_person_detection_v1(CorrectPhotoPersonDetectionV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            owner_review_id,
            manual_rectangle: RectV1 {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            expected_terminal_attempt_id: terminal_attempt_id,
            expected_detection_revision: 2,
            expected_owner_head_revision: 2,
            expected_photo_revision: 3,
        })
        .unwrap();
    service
        .retry_photo_person_detection_v1(RetryPhotoPersonDetectionV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            owner_review_id,
            expected_terminal_attempt_id: terminal_attempt_id,
            expected_detection_revision: 3,
            expected_owner_head_revision: 2,
            expected_photo_revision: 4,
        })
        .unwrap();

    assert_eq!(
        service
            .database()
            .owner_calls
            .each_ref()
            .map(|calls| calls.get()),
        [1; 6]
    );
    assert_eq!(service.database().detection_calls.get(), 1);
}
