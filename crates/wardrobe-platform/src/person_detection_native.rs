#![cfg_attr(
    not(any(test, all(target_os = "macos", feature = "photokit-native"))),
    allow(dead_code)
)]

use std::collections::BTreeSet;
use std::mem::{offset_of, size_of};

use wardrobe_core::{
    DetectedPersonRectangleV1, LocalPersonDetectionProviderV1, PersonDetectionFailureReasonV1,
    PersonDetectionOutcomeV1, PersonDetectionProviderDescriptorV1, PersonDetectionProviderError,
    PersonDetectionProviderErrorKind, PersonDetectionProviderResult, PersonDetectionRequestV1,
    PersonDetectionResultV1, PersonDetectionUnavailableReasonV1, RectV1, Validate,
    APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1, LOCAL_PERSON_DETECTION_CONTRACT_V1,
    PHOTO_PREPROCESSING_REVISION_V1,
};

const ABI_VERSION: u32 = 1;
const REQUEST_REVISION: u32 = 2;
const MAX_RECTANGLES: usize = 32;
const OVERFLOW_COUNT: u32 = 33;

const STATUS_OK: i32 = 0;
const STATUS_INVALID_INPUT: i32 = 1;
const STATUS_UNSUPPORTED_REVISION: i32 = 2;
const STATUS_RETRYABLE_FAILURE: i32 = 3;
const STATUS_PERMANENT_UNAVAILABLE: i32 = 4;
const STATUS_OUTPUT_OVERFLOW: i32 = 5;
const STATUS_INTERNAL_FAILURE: i32 = 6;
const STATUS_PROCESS_UNAVAILABLE: i32 = 7;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativePersonDetectionRequestV1 {
    abi_version: u32,
    struct_size: u32,
    width: u32,
    height: u32,
    bytes_per_row: u64,
    rgb_length: u64,
    reserved_0: u32,
    reserved_1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NativePersonRectV1 {
    abi_version: u32,
    struct_size: u32,
    left: u32,
    top: u32,
    width: u32,
    height: u32,
    confidence_basis_points: u32,
    result_ordinal: u32,
    reserved_0: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NativePersonDetectionMetadataV1 {
    abi_version: u32,
    struct_size: u32,
    request_revision: u32,
    result_count: u32,
    os_major: u32,
    os_minor: u32,
    os_patch: u32,
    reserved_0: u32,
    os_build: [u8; 32],
    vision_framework_build: [u8; 32],
}

impl Default for NativePersonDetectionMetadataV1 {
    fn default() -> Self {
        Self {
            abi_version: 0,
            struct_size: 0,
            request_revision: 0,
            result_count: 0,
            os_major: 0,
            os_minor: 0,
            os_patch: 0,
            reserved_0: 0,
            os_build: [0; 32],
            vision_framework_build: [0; 32],
        }
    }
}

const _: [(); 40] = [(); size_of::<NativePersonDetectionRequestV1>()];
const _: [(); 36] = [(); size_of::<NativePersonRectV1>()];
const _: [(); 96] = [(); size_of::<NativePersonDetectionMetadataV1>()];
const _: [(); 16] = [(); offset_of!(NativePersonDetectionRequestV1, bytes_per_row)];
const _: [(); 36] = [(); offset_of!(NativePersonDetectionRequestV1, reserved_1)];
const _: [(); 24] = [(); offset_of!(NativePersonRectV1, confidence_basis_points)];
const _: [(); 32] = [(); offset_of!(NativePersonRectV1, reserved_0)];
const _: [(); 32] = [(); offset_of!(NativePersonDetectionMetadataV1, os_build)];
const _: [(); 64] = [(); offset_of!(NativePersonDetectionMetadataV1, vision_framework_build)];

#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsVisionPersonDetectionProviderV1;

impl LocalPersonDetectionProviderV1 for MacOsVisionPersonDetectionProviderV1 {
    fn describe(&self) -> PersonDetectionProviderDescriptorV1 {
        runtime_descriptor()
    }

    fn detect(
        &self,
        request: &PersonDetectionRequestV1,
    ) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
        request.validate().map_err(|_| {
            PersonDetectionProviderError::new(PersonDetectionProviderErrorKind::InvalidRequest)
        })?;
        if request.contract_revision != LOCAL_PERSON_DETECTION_CONTRACT_V1
            || request.preprocessing_revision != PHOTO_PREPROCESSING_REVISION_V1
        {
            return Err(PersonDetectionProviderError::new(
                PersonDetectionProviderErrorKind::InvalidRequest,
            ));
        }
        detect_platform(request)
    }
}

#[cfg(all(target_os = "macos", feature = "photokit-native"))]
fn detect_platform(
    request: &PersonDetectionRequestV1,
) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
    let native_request = native_request(request)?;
    let mut rectangles = [NativePersonRectV1::default(); MAX_RECTANGLES];
    let mut count = 0_u32;
    let mut metadata = NativePersonDetectionMetadataV1::default();
    let status = unsafe {
        wk_detect_people_rgb_v1(
            &native_request,
            request.pixels.as_bytes().as_ptr(),
            rectangles.as_mut_ptr(),
            MAX_RECTANGLES as u32,
            &mut count,
            &mut metadata,
        )
    };
    map_native_response(request, status, count, &metadata, &rectangles)
}

#[cfg(not(all(target_os = "macos", feature = "photokit-native")))]
fn detect_platform(
    request: &PersonDetectionRequestV1,
) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
    Ok(outcome(
        request,
        PersonDetectionResultV1::PermanentUnavailable {
            reason: if cfg!(target_os = "macos") {
                PersonDetectionUnavailableReasonV1::VisionFrameworkAbsent
            } else {
                PersonDetectionUnavailableReasonV1::UnsupportedOperatingSystem
            },
        },
    ))
}

#[cfg(all(target_os = "macos", feature = "photokit-native"))]
extern "C" {
    fn wk_detect_people_rgb_v1(
        request: *const NativePersonDetectionRequestV1,
        rgb: *const u8,
        out_rectangles: *mut NativePersonRectV1,
        output_capacity: u32,
        out_count: *mut u32,
        out_metadata: *mut NativePersonDetectionMetadataV1,
    ) -> i32;
}

#[cfg(all(target_os = "macos", feature = "photokit-native"))]
fn native_request(
    request: &PersonDetectionRequestV1,
) -> PersonDetectionProviderResult<NativePersonDetectionRequestV1> {
    Ok(NativePersonDetectionRequestV1 {
        abi_version: ABI_VERSION,
        struct_size: size_of::<NativePersonDetectionRequestV1>() as u32,
        width: request.width,
        height: request.height,
        bytes_per_row: u64::from(request.rgb_row_stride),
        rgb_length: u64::try_from(request.pixels.as_bytes().len()).map_err(|_| {
            PersonDetectionProviderError::new(PersonDetectionProviderErrorKind::InvalidRequest)
        })?,
        reserved_0: 0,
        reserved_1: 0,
    })
}

fn map_native_response(
    request: &PersonDetectionRequestV1,
    status: i32,
    count: u32,
    metadata: &NativePersonDetectionMetadataV1,
    rectangles: &[NativePersonRectV1; MAX_RECTANGLES],
) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
    match status {
        STATUS_INVALID_INPUT => {
            return Err(PersonDetectionProviderError::new(
                PersonDetectionProviderErrorKind::InvalidRequest,
            ));
        }
        STATUS_UNSUPPORTED_REVISION => {
            require_zeroed_outputs(count, metadata)?;
            return Ok(outcome(
                request,
                PersonDetectionResultV1::PermanentUnavailable {
                    reason: PersonDetectionUnavailableReasonV1::UnsupportedRequestRevision,
                },
            ));
        }
        STATUS_INTERNAL_FAILURE => {
            require_runtime_metadata(count, metadata)?;
            return Err(PersonDetectionProviderError::new(
                PersonDetectionProviderErrorKind::Internal,
            ));
        }
        STATUS_OK
        | STATUS_RETRYABLE_FAILURE
        | STATUS_PERMANENT_UNAVAILABLE
        | STATUS_OUTPUT_OVERFLOW
        | STATUS_PROCESS_UNAVAILABLE => {}
        _ => {
            return Err(PersonDetectionProviderError::new(
                PersonDetectionProviderErrorKind::MalformedOutput,
            ));
        }
    }

    if status == STATUS_PERMANENT_UNAVAILABLE && metadata.abi_version == 0 {
        require_zeroed_outputs(count, metadata)?;
        return Ok(outcome(
            request,
            PersonDetectionResultV1::PermanentUnavailable {
                reason: PersonDetectionUnavailableReasonV1::VisionFrameworkAbsent,
            },
        ));
    }
    require_runtime_metadata(count, metadata)?;

    let result = match status {
        STATUS_OK => {
            if count > MAX_RECTANGLES as u32 {
                return malformed();
            }
            let mut seen_ordinals = BTreeSet::new();
            let mut instances = rectangles[..count as usize]
                .iter()
                .map(|rectangle| validate_rectangle(request, rectangle, &mut seen_ordinals))
                .collect::<PersonDetectionProviderResult<Vec<_>>>()?;
            instances.sort_by_key(|instance| {
                (
                    instance.0.rectangle.y,
                    instance.0.rectangle.x,
                    instance.0.rectangle.height,
                    instance.0.rectangle.width,
                    instance.0.confidence_basis_points,
                    instance.1,
                )
            });
            let instances = instances
                .into_iter()
                .map(|(instance, _)| instance)
                .collect::<Vec<_>>();
            if instances.is_empty() {
                PersonDetectionResultV1::SucceededZero
            } else {
                PersonDetectionResultV1::SucceededInstances { instances }
            }
        }
        STATUS_RETRYABLE_FAILURE => {
            if count != 0 {
                return malformed();
            }
            PersonDetectionResultV1::RetryableFailure {
                reason: PersonDetectionFailureReasonV1::VisionRequestFailed,
            }
        }
        STATUS_PERMANENT_UNAVAILABLE => {
            if count != 0 {
                return malformed();
            }
            PersonDetectionResultV1::PermanentUnavailable {
                reason: PersonDetectionUnavailableReasonV1::InvalidProviderOutput,
            }
        }
        STATUS_PROCESS_UNAVAILABLE => {
            if count != 0 {
                return malformed();
            }
            PersonDetectionResultV1::PermanentUnavailable {
                reason: PersonDetectionUnavailableReasonV1::VisionProcessUnavailable,
            }
        }
        STATUS_OUTPUT_OVERFLOW => {
            if count < OVERFLOW_COUNT {
                return malformed();
            }
            if rectangles
                .iter()
                .any(|rectangle| *rectangle != NativePersonRectV1::default())
            {
                return malformed();
            }
            PersonDetectionResultV1::Overflow {
                detected_count: count,
            }
        }
        _ => unreachable!("statuses were filtered above"),
    };
    Ok(outcome(request, result))
}

fn validate_rectangle(
    request: &PersonDetectionRequestV1,
    rectangle: &NativePersonRectV1,
    seen_ordinals: &mut BTreeSet<u32>,
) -> PersonDetectionProviderResult<(DetectedPersonRectangleV1, u32)> {
    if rectangle.abi_version != ABI_VERSION
        || rectangle.struct_size != size_of::<NativePersonRectV1>() as u32
        || rectangle.reserved_0 != 0
        || rectangle.confidence_basis_points > 10_000
        || !seen_ordinals.insert(rectangle.result_ordinal)
    {
        return malformed();
    }
    let right = rectangle.left.checked_add(rectangle.width);
    let bottom = rectangle.top.checked_add(rectangle.height);
    if rectangle.width == 0
        || rectangle.height == 0
        || right.is_none_or(|right| right > request.width)
        || bottom.is_none_or(|bottom| bottom > request.height)
    {
        return malformed();
    }
    Ok((
        DetectedPersonRectangleV1 {
            rectangle: RectV1 {
                x: rectangle.left,
                y: rectangle.top,
                width: rectangle.width,
                height: rectangle.height,
            },
            confidence_basis_points: rectangle.confidence_basis_points as u16,
        },
        rectangle.result_ordinal,
    ))
}

fn require_runtime_metadata(
    count: u32,
    metadata: &NativePersonDetectionMetadataV1,
) -> PersonDetectionProviderResult<()> {
    if metadata.abi_version != ABI_VERSION
        || metadata.struct_size != size_of::<NativePersonDetectionMetadataV1>() as u32
        || metadata.request_revision != REQUEST_REVISION
        || metadata.result_count != count
        || metadata.reserved_0 != 0
        || fixed_ascii(&metadata.os_build).is_err()
        || fixed_ascii(&metadata.vision_framework_build).is_err()
    {
        malformed()
    } else {
        Ok(())
    }
}

fn require_zeroed_outputs(
    count: u32,
    metadata: &NativePersonDetectionMetadataV1,
) -> PersonDetectionProviderResult<()> {
    if count == 0 && metadata_bytes(metadata).iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        malformed()
    }
}

fn fixed_ascii(value: &[u8; 32]) -> Result<String, ()> {
    let end = value.iter().position(|byte| *byte == 0).ok_or(())?;
    if end == 0
        || value[end..].iter().any(|byte| *byte != 0)
        || !value[..end].is_ascii()
        || value[..end].iter().any(|byte| byte.is_ascii_control())
    {
        return Err(());
    }
    let text = std::str::from_utf8(&value[..end]).map_err(|_| ())?;
    if text.trim() != text {
        return Err(());
    }
    Ok(text.to_owned())
}

fn metadata_bytes(metadata: &NativePersonDetectionMetadataV1) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            metadata as *const NativePersonDetectionMetadataV1 as *const u8,
            size_of::<NativePersonDetectionMetadataV1>(),
        )
    }
}

fn outcome(
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

fn malformed<T>() -> PersonDetectionProviderResult<T> {
    Err(PersonDetectionProviderError::new(
        PersonDetectionProviderErrorKind::MalformedOutput,
    ))
}

#[cfg(all(target_os = "macos", feature = "photokit-native"))]
fn runtime_descriptor() -> PersonDetectionProviderDescriptorV1 {
    let probe_pixels = [0_u8; 3];
    let request = NativePersonDetectionRequestV1 {
        abi_version: ABI_VERSION,
        struct_size: size_of::<NativePersonDetectionRequestV1>() as u32,
        width: 1,
        height: 1,
        bytes_per_row: 3,
        rgb_length: 3,
        reserved_0: 0,
        reserved_1: 0,
    };
    let mut rectangles = [NativePersonRectV1::default(); MAX_RECTANGLES];
    let mut count = 0;
    let mut metadata = NativePersonDetectionMetadataV1::default();
    unsafe {
        wk_detect_people_rgb_v1(
            &request,
            probe_pixels.as_ptr(),
            rectangles.as_mut_ptr(),
            MAX_RECTANGLES as u32,
            &mut count,
            &mut metadata,
        );
    }
    descriptor_from_metadata(&metadata).unwrap_or_else(unavailable_descriptor)
}

#[cfg(not(all(target_os = "macos", feature = "photokit-native")))]
fn runtime_descriptor() -> PersonDetectionProviderDescriptorV1 {
    unavailable_descriptor()
}

#[cfg(all(target_os = "macos", feature = "photokit-native"))]
fn descriptor_from_metadata(
    metadata: &NativePersonDetectionMetadataV1,
) -> Option<PersonDetectionProviderDescriptorV1> {
    require_runtime_metadata(metadata.result_count, metadata).ok()?;
    Some(PersonDetectionProviderDescriptorV1 {
        contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
        provider_revision: APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
        preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
        vision_request_revision: metadata.request_revision,
        os_build: fixed_ascii(&metadata.os_build).ok()?,
        vision_framework_build: fixed_ascii(&metadata.vision_framework_build).ok()?,
    })
}

fn unavailable_descriptor() -> PersonDetectionProviderDescriptorV1 {
    PersonDetectionProviderDescriptorV1 {
        contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
        provider_revision: APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
        preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
        vision_request_revision: REQUEST_REVISION,
        os_build: if cfg!(target_os = "macos") {
            "macos-native-feature-disabled".to_owned()
        } else {
            "non-macos".to_owned()
        },
        vision_framework_build: "unavailable".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardrobe_core::{CanonicalSrgbPixelBufferV1, PersonDetectionRequestHandle, Sha256Digest};

    fn request() -> PersonDetectionRequestV1 {
        PersonDetectionRequestV1 {
            contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
            request_handle: PersonDetectionRequestHandle::new_v4(),
            source_revision_sha256: Sha256Digest::from_bytes(b"source"),
            input_blob_sha256: Sha256Digest::from_bytes(b"blob"),
            width: 20,
            height: 10,
            rgb_row_stride: 60,
            pixels: CanonicalSrgbPixelBufferV1::new(vec![0; 600], 20, 10).unwrap(),
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
        }
    }

    fn metadata(count: u32) -> NativePersonDetectionMetadataV1 {
        let mut metadata = NativePersonDetectionMetadataV1 {
            abi_version: ABI_VERSION,
            struct_size: 96,
            request_revision: REQUEST_REVISION,
            result_count: count,
            os_major: 15,
            os_minor: 0,
            os_patch: 0,
            reserved_0: 0,
            ..Default::default()
        };
        metadata.os_build[..5].copy_from_slice(b"24A1\0");
        metadata.vision_framework_build[..4].copy_from_slice(b"1.0\0");
        metadata
    }

    fn rectangle(
        left: u32,
        top: u32,
        width: u32,
        height: u32,
        confidence: u32,
        ordinal: u32,
    ) -> NativePersonRectV1 {
        NativePersonRectV1 {
            abi_version: ABI_VERSION,
            struct_size: 36,
            left,
            top,
            width,
            height,
            confidence_basis_points: confidence,
            result_ordinal: ordinal,
            reserved_0: 0,
        }
    }

    #[test]
    fn native_layout_matches_the_frozen_header() {
        assert_eq!(size_of::<NativePersonDetectionRequestV1>(), 40);
        assert_eq!(offset_of!(NativePersonDetectionRequestV1, rgb_length), 24);
        assert_eq!(size_of::<NativePersonRectV1>(), 36);
        assert_eq!(offset_of!(NativePersonRectV1, result_ordinal), 28);
        assert_eq!(size_of::<NativePersonDetectionMetadataV1>(), 96);
        assert_eq!(
            offset_of!(NativePersonDetectionMetadataV1, vision_framework_build),
            64
        );
    }

    #[test]
    fn successful_rectangles_are_validated_and_stably_sorted() {
        let request = request();
        let mut rectangles = [NativePersonRectV1::default(); MAX_RECTANGLES];
        rectangles[0] = rectangle(5, 4, 3, 2, 9_000, 7);
        rectangles[1] = rectangle(1, 1, 4, 5, 8_000, 2);
        let result =
            map_native_response(&request, STATUS_OK, 2, &metadata(2), &rectangles).unwrap();
        let PersonDetectionResultV1::SucceededInstances { ref instances } = result.result else {
            panic!("expected instances");
        };
        assert_eq!(instances[0].rectangle.x, 1);
        assert_eq!(instances[1].rectangle.x, 5);
        result
            .validate_against(&MacOsVisionPersonDetectionProviderV1.describe(), &request)
            .unwrap();
    }

    #[test]
    fn malformed_metadata_rectangles_and_overflow_fail_closed() {
        let request = request();
        let mut rectangles = [NativePersonRectV1::default(); MAX_RECTANGLES];
        rectangles[0] = rectangle(19, 0, 2, 1, 9_000, 0);
        assert_eq!(
            map_native_response(&request, STATUS_OK, 1, &metadata(1), &rectangles)
                .unwrap_err()
                .kind,
            PersonDetectionProviderErrorKind::MalformedOutput
        );

        let mut bad_metadata = metadata(0);
        bad_metadata.reserved_0 = 1;
        assert_eq!(
            map_native_response(
                &request,
                STATUS_RETRYABLE_FAILURE,
                0,
                &bad_metadata,
                &[NativePersonRectV1::default(); MAX_RECTANGLES],
            )
            .unwrap_err()
            .kind,
            PersonDetectionProviderErrorKind::MalformedOutput
        );

        rectangles = [NativePersonRectV1::default(); MAX_RECTANGLES];
        rectangles[0].left = 1;
        assert_eq!(
            map_native_response(
                &request,
                STATUS_OUTPUT_OVERFLOW,
                OVERFLOW_COUNT,
                &metadata(OVERFLOW_COUNT),
                &rectangles,
            )
            .unwrap_err()
            .kind,
            PersonDetectionProviderErrorKind::MalformedOutput
        );
    }

    #[test]
    fn every_native_status_has_an_explicit_mapping() {
        let request = request();
        let empty = [NativePersonRectV1::default(); MAX_RECTANGLES];
        assert_eq!(
            map_native_response(
                &request,
                STATUS_INVALID_INPUT,
                0,
                &NativePersonDetectionMetadataV1::default(),
                &empty,
            )
            .unwrap_err()
            .kind,
            PersonDetectionProviderErrorKind::InvalidRequest
        );
        assert!(matches!(
            map_native_response(
                &request,
                STATUS_UNSUPPORTED_REVISION,
                0,
                &NativePersonDetectionMetadataV1::default(),
                &empty,
            )
            .unwrap()
            .result,
            PersonDetectionResultV1::PermanentUnavailable {
                reason: PersonDetectionUnavailableReasonV1::UnsupportedRequestRevision
            }
        ));
        assert!(matches!(
            map_native_response(&request, STATUS_RETRYABLE_FAILURE, 0, &metadata(0), &empty,)
                .unwrap()
                .result,
            PersonDetectionResultV1::RetryableFailure { .. }
        ));
        assert!(matches!(
            map_native_response(
                &request,
                STATUS_PERMANENT_UNAVAILABLE,
                0,
                &NativePersonDetectionMetadataV1::default(),
                &empty,
            )
            .unwrap()
            .result,
            PersonDetectionResultV1::PermanentUnavailable {
                reason: PersonDetectionUnavailableReasonV1::VisionFrameworkAbsent
            }
        ));
        assert!(matches!(
            map_native_response(
                &request,
                STATUS_PROCESS_UNAVAILABLE,
                0,
                &metadata(0),
                &empty,
            )
            .unwrap()
            .result,
            PersonDetectionResultV1::PermanentUnavailable {
                reason: PersonDetectionUnavailableReasonV1::VisionProcessUnavailable
            }
        ));
        assert!(matches!(
            map_native_response(
                &request,
                STATUS_OUTPUT_OVERFLOW,
                OVERFLOW_COUNT,
                &metadata(OVERFLOW_COUNT),
                &empty,
            )
            .unwrap()
            .result,
            PersonDetectionResultV1::Overflow {
                detected_count: OVERFLOW_COUNT
            }
        ));
        assert_eq!(
            map_native_response(&request, STATUS_INTERNAL_FAILURE, 0, &metadata(0), &empty,)
                .unwrap_err()
                .kind,
            PersonDetectionProviderErrorKind::Internal
        );
        assert_eq!(
            map_native_response(&request, 99, 0, &metadata(0), &empty)
                .unwrap_err()
                .kind,
            PersonDetectionProviderErrorKind::MalformedOutput
        );
    }

    #[test]
    fn unavailable_descriptor_and_fallback_are_conforming() {
        let provider = MacOsVisionPersonDetectionProviderV1;
        provider.describe().validate().unwrap();
        let request = request();
        let result = provider.detect(&request).unwrap();
        result
            .validate_against(&provider.describe(), &request)
            .unwrap();
        #[cfg(not(all(target_os = "macos", feature = "photokit-native")))]
        assert!(matches!(
            result.result,
            PersonDetectionResultV1::PermanentUnavailable { .. }
        ));
    }
}
