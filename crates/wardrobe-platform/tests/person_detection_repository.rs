use image::{ColorType, ImageFormat};
use rusqlite::Connection;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use wardrobe_core::{
    CatalogPort, CorrectPhotoPersonDetectionV1Request, CreatePhotoScopeV1Request,
    DecidePhotoOwnerV1Request, DetectPhotoScopePeopleV1Request, ImportLocalSourcesV1Request,
    ListImportedPhotoRootsV1Request, ListPhotoObservationsV1Request,
    ListPhotoOwnerReviewsV1Request, LocalPersonDetectionProviderV1, PersonDetectionOutcomeV1,
    PersonDetectionProviderDescriptorV1, PersonDetectionProviderResult, PersonDetectionRequestV1,
    PersonDetectionResultV1, PersonDetectionUnavailableReasonV1, PhotoAnalysisPort,
    PhotoObservationStateV1, PhotoOwnerActionV1, PhotoOwnerReviewStateV1, RectV1, RequestId,
    APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1, LOCAL_PERSON_DETECTION_CONTRACT_V1,
    PHOTO_PREPROCESSING_REVISION_V1, SCHEMA_VERSION_V1,
};
use wardrobe_platform::{Database, PrivateAppPaths};

struct ProcessUnavailableProvider<'a> {
    calls: &'a AtomicUsize,
}

impl LocalPersonDetectionProviderV1 for ProcessUnavailableProvider<'_> {
    fn describe(&self) -> PersonDetectionProviderDescriptorV1 {
        PersonDetectionProviderDescriptorV1 {
            contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
            provider_revision: APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            vision_request_revision: 2,
            os_build: "process-unavailable-test-os".to_owned(),
            vision_framework_build: "process-unavailable-test-vision".to_owned(),
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
            result: PersonDetectionResultV1::PermanentUnavailable {
                reason: PersonDetectionUnavailableReasonV1::VisionProcessUnavailable,
            },
        })
    }
}

fn request_id() -> RequestId {
    RequestId::new_v4()
}

#[test]
fn process_unavailable_persists_once_and_remains_manually_recoverable_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let folder = temporary.path().join("photos");
    fs::create_dir(&folder).unwrap();
    image::save_buffer_with_format(
        folder.join("shirt.png"),
        &[80; 8 * 6 * 3],
        8,
        6,
        ColorType::Rgb8,
        ImageFormat::Png,
    )
    .unwrap();

    let database = Database::open(&paths, 1).unwrap();
    database
        .import_local_sources(&ImportLocalSourcesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            paths: vec![folder.to_string_lossy().into_owned()],
        })
        .unwrap();
    let root = database
        .list_imported_photo_roots(&ListImportedPhotoRootsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            cursor: None,
            limit: 20,
        })
        .unwrap()
        .roots
        .remove(0);
    let scope = database
        .create_photo_scope(&CreatePhotoScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_id: root.import_root_id,
            expected_manifest_generation: root.manifest_generation,
        })
        .unwrap()
        .scope;
    let calls = AtomicUsize::new(0);
    let detected = database
        .detect_photo_scope_people(
            &DetectPhotoScopePeopleV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                scope_id: scope.scope_id,
            },
            &ProcessUnavailableProvider { calls: &calls },
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(detected.permanent_unavailable_count, 1);
    assert_eq!(detected.retryable_failure_count, 0);

    let connection = Connection::open(&paths.database).unwrap();
    let stored: (String, String, i64) = connection
        .query_row(
            "SELECT state, terminal_reason, attempt_count
             FROM photo_person_detection_attempts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        stored,
        (
            "permanent_unavailable".to_owned(),
            "vision_unavailable".to_owned(),
            1
        )
    );
    drop(connection);
    drop(database);

    let restarted = Database::open(&paths, 1).unwrap();
    let review = restarted
        .list_photo_owner_reviews(&ListPhotoOwnerReviewsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            state: PhotoOwnerReviewStateV1::PermanentUnavailable,
            cursor: None,
            limit: 20,
        })
        .unwrap()
        .reviews
        .remove(0);
    let correction = restarted
        .correct_photo_person_detection(&CorrectPhotoPersonDetectionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            owner_review_id: review.owner_review_id,
            manual_rectangle: RectV1 {
                x: 0,
                y: 0,
                width: 8,
                height: 6,
            },
            expected_terminal_attempt_id: review.terminal_attempt_id,
            expected_detection_revision: review.detection_revision,
            expected_owner_head_revision: review.owner_head_revision,
            expected_photo_revision: review.photo_revision,
        })
        .unwrap();
    restarted
        .decide_photo_owner(&DecidePhotoOwnerV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            owner_review_id: correction.review.owner_review_id,
            action: PhotoOwnerActionV1::SelectPerson,
            selected_person_instance_id: Some(correction.instance.person_instance_id),
            expected_detection_revision: correction.review.detection_revision,
            expected_owner_head_revision: correction.review.owner_head_revision,
            expected_photo_revision: correction.review.photo_revision,
        })
        .unwrap();
    let observations = restarted
        .list_photo_observations(&ListPhotoObservationsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            scope_id: scope.scope_id,
            state: PhotoObservationStateV1::NeedsReview,
            cursor: None,
            limit: 20,
        })
        .unwrap();
    assert_eq!(observations.observations.len(), 1);
}
