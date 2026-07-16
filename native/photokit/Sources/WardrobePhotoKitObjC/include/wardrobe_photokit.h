#ifndef WARDROBE_PHOTOKIT_H
#define WARDROBE_PHOTOKIT_H

#include <stddef.h>
#include <stdint.h>

#define WK_PHOTOKIT_ABI_V1 1u
#define WK_PHOTOKIT_MAX_CONTROL_V1 65536u
#define WK_PHOTOKIT_MAX_BINARY_V1 1048576u

#define WK_PERSON_DETECTION_ABI_V1 1u
#define WK_PERSON_DETECTION_REQUEST_REVISION_V1 2u
#define WK_PERSON_DETECTION_MAX_DIMENSION_V1 16384u
#define WK_PERSON_DETECTION_MAX_PIXELS_V1 67108864u
#define WK_PERSON_DETECTION_MAX_RECTS_V1 32u
#define WK_PERSON_DETECTION_OVERFLOW_COUNT_V1 33u

#define WK_PERSON_DETECTION_REQUEST_V1_SIZE 40u
#define WK_PERSON_RECT_V1_SIZE 36u
#define WK_PERSON_DETECTION_METADATA_V1_SIZE 96u

#define WK_PERSON_DETECTION_REQUEST_V1_ABI_VERSION_OFFSET 0u
#define WK_PERSON_DETECTION_REQUEST_V1_STRUCT_SIZE_OFFSET 4u
#define WK_PERSON_DETECTION_REQUEST_V1_WIDTH_OFFSET 8u
#define WK_PERSON_DETECTION_REQUEST_V1_HEIGHT_OFFSET 12u
#define WK_PERSON_DETECTION_REQUEST_V1_BYTES_PER_ROW_OFFSET 16u
#define WK_PERSON_DETECTION_REQUEST_V1_RGB_LENGTH_OFFSET 24u
#define WK_PERSON_DETECTION_REQUEST_V1_RESERVED_0_OFFSET 32u
#define WK_PERSON_DETECTION_REQUEST_V1_RESERVED_1_OFFSET 36u

#define WK_PERSON_RECT_V1_ABI_VERSION_OFFSET 0u
#define WK_PERSON_RECT_V1_STRUCT_SIZE_OFFSET 4u
#define WK_PERSON_RECT_V1_LEFT_OFFSET 8u
#define WK_PERSON_RECT_V1_TOP_OFFSET 12u
#define WK_PERSON_RECT_V1_WIDTH_OFFSET 16u
#define WK_PERSON_RECT_V1_HEIGHT_OFFSET 20u
#define WK_PERSON_RECT_V1_CONFIDENCE_BASIS_POINTS_OFFSET 24u
#define WK_PERSON_RECT_V1_RESULT_ORDINAL_OFFSET 28u
#define WK_PERSON_RECT_V1_RESERVED_0_OFFSET 32u

#define WK_PERSON_DETECTION_METADATA_V1_ABI_VERSION_OFFSET 0u
#define WK_PERSON_DETECTION_METADATA_V1_STRUCT_SIZE_OFFSET 4u
#define WK_PERSON_DETECTION_METADATA_V1_REQUEST_REVISION_OFFSET 8u
#define WK_PERSON_DETECTION_METADATA_V1_RESULT_COUNT_OFFSET 12u
#define WK_PERSON_DETECTION_METADATA_V1_OS_MAJOR_OFFSET 16u
#define WK_PERSON_DETECTION_METADATA_V1_OS_MINOR_OFFSET 20u
#define WK_PERSON_DETECTION_METADATA_V1_OS_PATCH_OFFSET 24u
#define WK_PERSON_DETECTION_METADATA_V1_RESERVED_0_OFFSET 28u
#define WK_PERSON_DETECTION_METADATA_V1_OS_BUILD_OFFSET 32u
#define WK_PERSON_DETECTION_METADATA_V1_VISION_BUILD_OFFSET 64u

typedef struct wk_photokit_handle_v1 wk_photokit_handle_v1;

typedef enum {
  WK_PHOTOKIT_OK_V1 = 0,
  WK_PHOTOKIT_TIMEOUT_V1 = 1,
  WK_PHOTOKIT_CLOSED_V1 = 2,
  WK_PHOTOKIT_INVALID_V1 = 3,
  WK_PHOTOKIT_BUSY_V1 = 4,
  WK_PHOTOKIT_INTERNAL_V1 = 5
} wk_photokit_status_v1;

typedef enum {
  WK_PHOTOKIT_CONTROL_V1 = 1,
  WK_PHOTOKIT_BINARY_V1 = 2
} wk_photokit_frame_kind_v1;

typedef enum {
  WK_PERSON_DETECTION_OK_V1 = 0,
  WK_PERSON_DETECTION_INVALID_INPUT_V1 = 1,
  WK_PERSON_DETECTION_UNSUPPORTED_REVISION_V1 = 2,
  WK_PERSON_DETECTION_RETRYABLE_FAILURE_V1 = 3,
  WK_PERSON_DETECTION_PERMANENT_UNAVAILABLE_V1 = 4,
  WK_PERSON_DETECTION_OUTPUT_OVERFLOW_V1 = 5,
  WK_PERSON_DETECTION_INTERNAL_FAILURE_V1 = 6,
  WK_PERSON_DETECTION_PROCESS_UNAVAILABLE_V1 = 7
} wk_person_detection_status_v1;

typedef struct {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t width;
  uint32_t height;
  uint64_t bytes_per_row;
  uint64_t rgb_length;
  uint32_t reserved_0;
  uint32_t reserved_1;
} wk_person_detection_request_v1;

typedef struct {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t left;
  uint32_t top;
  uint32_t width;
  uint32_t height;
  uint32_t confidence_basis_points;
  uint32_t result_ordinal;
  uint32_t reserved_0;
} wk_person_rect_v1;

typedef struct {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t request_revision;
  uint32_t result_count;
  uint32_t os_major;
  uint32_t os_minor;
  uint32_t os_patch;
  uint32_t reserved_0;
  uint8_t os_build[32];
  uint8_t vision_framework_build[32];
} wk_person_detection_metadata_v1;

typedef struct {
  uint32_t abi_version;
  uint32_t kind;
  uint64_t sequence;
  size_t length;
  uint8_t bytes[];
} wk_photokit_frame_v1;

int32_t wk_photokit_create_v1(
  uint32_t requested_abi, wk_photokit_handle_v1 **out_handle);
int32_t wk_photokit_send_v1(
  wk_photokit_handle_v1 *handle, const uint8_t *bytes, size_t length);
int32_t wk_photokit_next_v1(
  wk_photokit_handle_v1 *handle, uint32_t timeout_ms,
  wk_photokit_frame_v1 **out_frame);
void wk_photokit_frame_free_v1(wk_photokit_frame_v1 *frame);
int32_t wk_photokit_quiesce_v1(
  wk_photokit_handle_v1 *handle, uint32_t timeout_ms);
int32_t wk_photokit_destroy_v1(wk_photokit_handle_v1 **handle);
int32_t wk_photokit_validate_image_fd_v1(
  int duplicated_read_only_fd, const uint8_t *uti, size_t uti_length,
  uint32_t *out_width, uint32_t *out_height, uint32_t *out_frame_count);
int32_t wk_detect_people_rgb_v1(
  const wk_person_detection_request_v1 *request, const uint8_t *rgb,
  wk_person_rect_v1 *out_rects, uint32_t output_capacity,
  uint32_t *out_count, wk_person_detection_metadata_v1 *out_metadata);

#if defined(__cplusplus)
#define WK_STATIC_ASSERT_V1(condition, message) static_assert(condition, message)
#else
#define WK_STATIC_ASSERT_V1(condition, message) _Static_assert(condition, message)
#endif

WK_STATIC_ASSERT_V1(sizeof(wk_person_detection_request_v1) ==
                    WK_PERSON_DETECTION_REQUEST_V1_SIZE,
                    "person request size drift");
WK_STATIC_ASSERT_V1(offsetof(wk_person_detection_request_v1, bytes_per_row) ==
                    WK_PERSON_DETECTION_REQUEST_V1_BYTES_PER_ROW_OFFSET,
                    "person request layout drift");
WK_STATIC_ASSERT_V1(offsetof(wk_person_detection_request_v1, reserved_1) ==
                    WK_PERSON_DETECTION_REQUEST_V1_RESERVED_1_OFFSET,
                    "person request layout drift");
WK_STATIC_ASSERT_V1(sizeof(wk_person_rect_v1) == WK_PERSON_RECT_V1_SIZE,
                    "person rect size drift");
WK_STATIC_ASSERT_V1(offsetof(wk_person_rect_v1, confidence_basis_points) ==
                    WK_PERSON_RECT_V1_CONFIDENCE_BASIS_POINTS_OFFSET,
                    "person rect layout drift");
WK_STATIC_ASSERT_V1(offsetof(wk_person_rect_v1, reserved_0) ==
                    WK_PERSON_RECT_V1_RESERVED_0_OFFSET,
                    "person rect layout drift");
WK_STATIC_ASSERT_V1(sizeof(wk_person_detection_metadata_v1) ==
                    WK_PERSON_DETECTION_METADATA_V1_SIZE,
                    "person metadata size drift");
WK_STATIC_ASSERT_V1(offsetof(wk_person_detection_metadata_v1, os_build) ==
                    WK_PERSON_DETECTION_METADATA_V1_OS_BUILD_OFFSET,
                    "person metadata layout drift");
WK_STATIC_ASSERT_V1(
  offsetof(wk_person_detection_metadata_v1, vision_framework_build) ==
    WK_PERSON_DETECTION_METADATA_V1_VISION_BUILD_OFFSET,
  "person metadata layout drift");

#undef WK_STATIC_ASSERT_V1

#endif
