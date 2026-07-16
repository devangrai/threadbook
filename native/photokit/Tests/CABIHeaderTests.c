#include "wardrobe_photokit.h"

#include <stddef.h>

_Static_assert(WK_PHOTOKIT_ABI_V1 == 1u, "ABI version drift");
_Static_assert(WK_PHOTOKIT_MAX_CONTROL_V1 == 65536u, "control bound drift");
_Static_assert(WK_PHOTOKIT_MAX_BINARY_V1 == 1048576u, "binary bound drift");
_Static_assert(WK_PHOTOKIT_OK_V1 == 0, "status drift");
_Static_assert(WK_PHOTOKIT_TIMEOUT_V1 == 1, "status drift");
_Static_assert(WK_PHOTOKIT_CLOSED_V1 == 2, "status drift");
_Static_assert(WK_PHOTOKIT_INVALID_V1 == 3, "status drift");
_Static_assert(WK_PHOTOKIT_BUSY_V1 == 4, "status drift");
_Static_assert(WK_PHOTOKIT_INTERNAL_V1 == 5, "status drift");
_Static_assert(offsetof(wk_photokit_frame_v1, bytes) == 24, "frame layout drift");
_Static_assert(WK_PERSON_DETECTION_ABI_V1 == 1u, "person ABI drift");
_Static_assert(WK_PERSON_DETECTION_REQUEST_REVISION_V1 == 2u,
               "public Vision revision drift");
_Static_assert(WK_PERSON_DETECTION_MAX_DIMENSION_V1 == 16384u,
               "person dimension bound drift");
_Static_assert(WK_PERSON_DETECTION_MAX_PIXELS_V1 == 67108864u,
               "person pixel bound drift");
_Static_assert(WK_PERSON_DETECTION_MAX_RECTS_V1 == 32u,
               "person output bound drift");
_Static_assert(WK_PERSON_DETECTION_OVERFLOW_COUNT_V1 == 33u,
               "person overflow count drift");
_Static_assert(WK_PERSON_DETECTION_OK_V1 == 0, "person status drift");
_Static_assert(WK_PERSON_DETECTION_INVALID_INPUT_V1 == 1,
               "person status drift");
_Static_assert(WK_PERSON_DETECTION_UNSUPPORTED_REVISION_V1 == 2,
               "person status drift");
_Static_assert(WK_PERSON_DETECTION_RETRYABLE_FAILURE_V1 == 3,
               "person status drift");
_Static_assert(WK_PERSON_DETECTION_PERMANENT_UNAVAILABLE_V1 == 4,
               "person status drift");
_Static_assert(WK_PERSON_DETECTION_OUTPUT_OVERFLOW_V1 == 5,
               "person status drift");
_Static_assert(WK_PERSON_DETECTION_INTERNAL_FAILURE_V1 == 6,
               "person status drift");
_Static_assert(WK_PERSON_DETECTION_PROCESS_UNAVAILABLE_V1 == 7,
               "person status drift");

#define ASSERT_OFFSET(type, field, constant) \
  _Static_assert(offsetof(type, field) == constant, #type "." #field " drift")

_Static_assert(sizeof(wk_person_detection_request_v1) ==
                 WK_PERSON_DETECTION_REQUEST_V1_SIZE,
               "person request size drift");
ASSERT_OFFSET(wk_person_detection_request_v1, abi_version,
              WK_PERSON_DETECTION_REQUEST_V1_ABI_VERSION_OFFSET);
ASSERT_OFFSET(wk_person_detection_request_v1, struct_size,
              WK_PERSON_DETECTION_REQUEST_V1_STRUCT_SIZE_OFFSET);
ASSERT_OFFSET(wk_person_detection_request_v1, width,
              WK_PERSON_DETECTION_REQUEST_V1_WIDTH_OFFSET);
ASSERT_OFFSET(wk_person_detection_request_v1, height,
              WK_PERSON_DETECTION_REQUEST_V1_HEIGHT_OFFSET);
ASSERT_OFFSET(wk_person_detection_request_v1, bytes_per_row,
              WK_PERSON_DETECTION_REQUEST_V1_BYTES_PER_ROW_OFFSET);
ASSERT_OFFSET(wk_person_detection_request_v1, rgb_length,
              WK_PERSON_DETECTION_REQUEST_V1_RGB_LENGTH_OFFSET);
ASSERT_OFFSET(wk_person_detection_request_v1, reserved_0,
              WK_PERSON_DETECTION_REQUEST_V1_RESERVED_0_OFFSET);
ASSERT_OFFSET(wk_person_detection_request_v1, reserved_1,
              WK_PERSON_DETECTION_REQUEST_V1_RESERVED_1_OFFSET);

_Static_assert(sizeof(wk_person_rect_v1) == WK_PERSON_RECT_V1_SIZE,
               "person rect size drift");
ASSERT_OFFSET(wk_person_rect_v1, abi_version,
              WK_PERSON_RECT_V1_ABI_VERSION_OFFSET);
ASSERT_OFFSET(wk_person_rect_v1, struct_size,
              WK_PERSON_RECT_V1_STRUCT_SIZE_OFFSET);
ASSERT_OFFSET(wk_person_rect_v1, left, WK_PERSON_RECT_V1_LEFT_OFFSET);
ASSERT_OFFSET(wk_person_rect_v1, top, WK_PERSON_RECT_V1_TOP_OFFSET);
ASSERT_OFFSET(wk_person_rect_v1, width, WK_PERSON_RECT_V1_WIDTH_OFFSET);
ASSERT_OFFSET(wk_person_rect_v1, height, WK_PERSON_RECT_V1_HEIGHT_OFFSET);
ASSERT_OFFSET(wk_person_rect_v1, confidence_basis_points,
              WK_PERSON_RECT_V1_CONFIDENCE_BASIS_POINTS_OFFSET);
ASSERT_OFFSET(wk_person_rect_v1, result_ordinal,
              WK_PERSON_RECT_V1_RESULT_ORDINAL_OFFSET);
ASSERT_OFFSET(wk_person_rect_v1, reserved_0,
              WK_PERSON_RECT_V1_RESERVED_0_OFFSET);

_Static_assert(sizeof(wk_person_detection_metadata_v1) ==
                 WK_PERSON_DETECTION_METADATA_V1_SIZE,
               "person metadata size drift");
ASSERT_OFFSET(wk_person_detection_metadata_v1, abi_version,
              WK_PERSON_DETECTION_METADATA_V1_ABI_VERSION_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, struct_size,
              WK_PERSON_DETECTION_METADATA_V1_STRUCT_SIZE_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, request_revision,
              WK_PERSON_DETECTION_METADATA_V1_REQUEST_REVISION_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, result_count,
              WK_PERSON_DETECTION_METADATA_V1_RESULT_COUNT_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, os_major,
              WK_PERSON_DETECTION_METADATA_V1_OS_MAJOR_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, os_minor,
              WK_PERSON_DETECTION_METADATA_V1_OS_MINOR_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, os_patch,
              WK_PERSON_DETECTION_METADATA_V1_OS_PATCH_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, reserved_0,
              WK_PERSON_DETECTION_METADATA_V1_RESERVED_0_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, os_build,
              WK_PERSON_DETECTION_METADATA_V1_OS_BUILD_OFFSET);
ASSERT_OFFSET(wk_person_detection_metadata_v1, vision_framework_build,
              WK_PERSON_DETECTION_METADATA_V1_VISION_BUILD_OFFSET);

#undef ASSERT_OFFSET

static int32_t (*create_fn)(
    uint32_t, wk_photokit_handle_v1 **) = wk_photokit_create_v1;
static int32_t (*send_fn)(
    wk_photokit_handle_v1 *, const uint8_t *, size_t) = wk_photokit_send_v1;
static int32_t (*next_fn)(
    wk_photokit_handle_v1 *, uint32_t,
    wk_photokit_frame_v1 **) = wk_photokit_next_v1;
static void (*free_fn)(wk_photokit_frame_v1 *) = wk_photokit_frame_free_v1;
static int32_t (*quiesce_fn)(
    wk_photokit_handle_v1 *, uint32_t) = wk_photokit_quiesce_v1;
static int32_t (*destroy_fn)(
    wk_photokit_handle_v1 **) = wk_photokit_destroy_v1;
static int32_t (*validate_fn)(
    int, const uint8_t *, size_t, uint32_t *, uint32_t *,
    uint32_t *) = wk_photokit_validate_image_fd_v1;
static int32_t (*detect_people_fn)(
    const wk_person_detection_request_v1 *, const uint8_t *,
    wk_person_rect_v1 *, uint32_t, uint32_t *,
    wk_person_detection_metadata_v1 *) = wk_detect_people_rgb_v1;

int main(void) {
  return create_fn == 0 || send_fn == 0 || next_fn == 0 || free_fn == 0 ||
                 quiesce_fn == 0 || destroy_fn == 0 || validate_fn == 0 ||
                 detect_people_fn == 0;
}
