use wardrobe_core::*;

fn request(mode: SegmentationRequestModeV1) -> SegmentationRequestV1 {
    SegmentationRequestV1 {
        contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
        request_handle: SegmentationRequestHandle::new_v4(),
        source_revision_sha256: Sha256Digest::from_bytes(b"source revision"),
        input_blob_sha256: Sha256Digest::from_bytes(b"source blob"),
        pixels: CanonicalSrgbPixelBufferV1::new(vec![32; 12], 2, 2).unwrap(),
        width: 2,
        height: 2,
        preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
        mode,
    }
}

fn descriptor() -> SegmentationProviderDescriptorV1 {
    SegmentationProviderDescriptorV1 {
        contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
        provider_id: "scripted-test-provider".to_owned(),
        provider_revision: "scripted-v1".to_owned(),
        model_revision: Some("model-v1".to_owned()),
        preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
        automatic_capability: SegmentationCapabilityV1::Available,
        interactive_capability: SegmentationCapabilityV1::Available,
        maximum_masks: MAX_SEGMENTATION_MASKS as u8,
    }
}

fn outcome(request: &SegmentationRequestV1, result: SegmentationResultV1) -> SegmentationOutcomeV1 {
    SegmentationOutcomeV1 {
        contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
        request_handle: request.request_handle,
        source_revision_sha256: request.source_revision_sha256.clone(),
        input_blob_sha256: request.input_blob_sha256.clone(),
        result,
    }
}

struct ScriptedProvider {
    descriptor: SegmentationProviderDescriptorV1,
    outcome: SegmentationOutcomeV1,
}

impl GarmentSegmentationProvider for ScriptedProvider {
    fn describe(&self) -> SegmentationProviderDescriptorV1 {
        self.descriptor.clone()
    }

    fn segment(
        &self,
        _request: &SegmentationRequestV1,
    ) -> SegmentationProviderResult<SegmentationOutcomeV1> {
        Ok(self.outcome.clone())
    }
}

#[test]
fn unavailable_provider_is_honest_for_automatic_and_interactive_modes() {
    let provider = UnavailableGarmentSegmentationProviderV1;
    let descriptor = provider.describe();
    assert_eq!(
        descriptor.automatic_capability,
        SegmentationCapabilityV1::Unavailable
    );
    assert_eq!(descriptor.model_revision, None);

    for mode in [
        SegmentationRequestModeV1::Automatic,
        SegmentationRequestModeV1::Interactive {
            box_rectangle: RectV1 {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            positive_points: vec![PointV1 { x: 0, y: 0 }],
            negative_points: vec![PointV1 { x: 1, y: 1 }],
        },
    ] {
        let request = request(mode);
        let outcome = provider.segment(&request).unwrap();
        assert_eq!(
            outcome.result,
            SegmentationResultV1::Unavailable {
                reason: SegmentationUnavailableReasonV1::ReviewedModelPackAbsent
            }
        );
        assert!(outcome.validate_against(&descriptor, &request).is_ok());
    }
}

#[test]
fn conformance_rejects_mode_mismatch_changed_hashes_and_duplicate_masks() {
    let automatic = request(SegmentationRequestModeV1::Automatic);
    let mask = MaskV1 {
        width: 2,
        height: 2,
        packed_bits: vec![0b1000_0000],
        confidence: 0.9,
    };
    let mismatch = outcome(
        &automatic,
        SegmentationResultV1::InteractiveMasks {
            masks: vec![mask.clone()],
        },
    );
    assert!(mismatch
        .validate_against(&descriptor(), &automatic)
        .is_err());

    let mut changed_hash = outcome(
        &automatic,
        SegmentationResultV1::AutomaticMasks {
            masks: vec![mask.clone()],
        },
    );
    changed_hash.input_blob_sha256 = Sha256Digest::from_bytes(b"changed");
    assert!(changed_hash
        .validate_against(&descriptor(), &automatic)
        .is_err());

    let duplicates = outcome(
        &automatic,
        SegmentationResultV1::AutomaticMasks {
            masks: vec![mask.clone(), mask],
        },
    );
    assert!(duplicates
        .validate_against(&descriptor(), &automatic)
        .is_err());
}

#[test]
fn conforming_wrapper_rejects_malformed_provider_output() {
    let request = request(SegmentationRequestModeV1::Automatic);
    let provider = ScriptedProvider {
        descriptor: descriptor(),
        outcome: outcome(
            &request,
            SegmentationResultV1::InteractiveMasks {
                masks: vec![MaskV1 {
                    width: 2,
                    height: 2,
                    packed_bits: vec![0b1000_0000],
                    confidence: 0.8,
                }],
            },
        ),
    };
    let checked = ConformingGarmentSegmentationProviderV1::new(&provider).unwrap();
    assert_eq!(
        checked.segment(&request).unwrap_err().kind,
        SegmentationProviderErrorKind::MalformedOutput
    );
}

fn person_request() -> PersonDetectionRequestV1 {
    PersonDetectionRequestV1 {
        contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
        request_handle: PersonDetectionRequestHandle::new_v4(),
        source_revision_sha256: Sha256Digest::from_bytes(b"person source revision"),
        input_blob_sha256: Sha256Digest::from_bytes(b"person source blob"),
        width: 2,
        height: 2,
        rgb_row_stride: 6,
        pixels: CanonicalSrgbPixelBufferV1::new(vec![0; 12], 2, 2).unwrap(),
        preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
    }
}

fn person_descriptor() -> PersonDetectionProviderDescriptorV1 {
    PersonDetectionProviderDescriptorV1 {
        contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
        provider_revision: APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
        preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
        vision_request_revision: 2,
        os_build: "25A123".to_owned(),
        vision_framework_build: "1.0.0".to_owned(),
    }
}

fn person_outcome(
    request: &PersonDetectionRequestV1,
    result: PersonDetectionResultV1,
) -> PersonDetectionOutcomeV1 {
    PersonDetectionOutcomeV1 {
        contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
        request_handle: request.request_handle,
        source_revision_sha256: request.source_revision_sha256.clone(),
        input_blob_sha256: request.input_blob_sha256.clone(),
        result,
    }
}

struct ScriptedPersonProvider {
    outcome: PersonDetectionOutcomeV1,
}

impl LocalPersonDetectionProviderV1 for ScriptedPersonProvider {
    fn describe(&self) -> PersonDetectionProviderDescriptorV1 {
        person_descriptor()
    }

    fn detect(
        &self,
        _request: &PersonDetectionRequestV1,
    ) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
        Ok(self.outcome.clone())
    }
}

#[test]
fn person_detection_terminal_classes_enforce_cardinality_and_geometry() {
    let request = person_request();
    let descriptor = person_descriptor();
    let one = DetectedPersonRectangleV1 {
        rectangle: RectV1 {
            x: 0,
            y: 0,
            width: 1,
            height: 2,
        },
        confidence_basis_points: 9_500,
    };
    assert!(person_outcome(
        &request,
        PersonDetectionResultV1::SucceededInstances {
            instances: vec![one.clone()]
        }
    )
    .validate_against(&descriptor, &request)
    .is_ok());
    assert!(person_outcome(
        &request,
        PersonDetectionResultV1::SucceededInstances { instances: vec![] }
    )
    .validate_against(&descriptor, &request)
    .is_err());
    assert!(person_outcome(
        &request,
        PersonDetectionResultV1::Overflow {
            detected_count: MAX_PERSON_INSTANCES_V1 as u32
        }
    )
    .validate_against(&descriptor, &request)
    .is_err());

    let mut outside = one;
    outside.rectangle.x = 2;
    assert!(person_outcome(
        &request,
        PersonDetectionResultV1::SucceededInstances {
            instances: vec![outside]
        }
    )
    .validate_against(&descriptor, &request)
    .is_err());
}

#[test]
fn person_detection_wrapper_rejects_changed_evidence_and_bad_row_stride() {
    let request = person_request();
    let mut changed = person_outcome(&request, PersonDetectionResultV1::SucceededZero);
    changed.input_blob_sha256 = Sha256Digest::from_bytes(b"changed");
    let provider = ScriptedPersonProvider { outcome: changed };
    let checked = ConformingLocalPersonDetectionProviderV1::new(&provider).unwrap();
    assert_eq!(
        checked.detect_people(&request).unwrap_err().kind,
        PersonDetectionProviderErrorKind::MalformedOutput
    );

    let mut bad_stride = person_request();
    bad_stride.rgb_row_stride = 7;
    assert_eq!(
        checked.detect_people(&bad_stride).unwrap_err().kind,
        PersonDetectionProviderErrorKind::InvalidRequest
    );
}
