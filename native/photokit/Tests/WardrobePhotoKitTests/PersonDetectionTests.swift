import CoreGraphics
import Foundation
import ImageIO
import Vision
import WardrobePhotoKitObjC
import XCTest
@testable import WardrobePhotoKit

final class PersonDetectionTests: XCTestCase {
    func testPersonDetectionLayoutsMatchCABI() {
        XCTAssertEqual(
            MemoryLayout<wk_person_detection_request_v1>.size,
            Int(WK_PERSON_DETECTION_REQUEST_V1_SIZE)
        )
        assertOffset(
            \wk_person_detection_request_v1.abi_version,
            Int(WK_PERSON_DETECTION_REQUEST_V1_ABI_VERSION_OFFSET)
        )
        assertOffset(
            \wk_person_detection_request_v1.struct_size,
            Int(WK_PERSON_DETECTION_REQUEST_V1_STRUCT_SIZE_OFFSET)
        )
        assertOffset(
            \wk_person_detection_request_v1.width,
            Int(WK_PERSON_DETECTION_REQUEST_V1_WIDTH_OFFSET)
        )
        assertOffset(
            \wk_person_detection_request_v1.height,
            Int(WK_PERSON_DETECTION_REQUEST_V1_HEIGHT_OFFSET)
        )
        assertOffset(
            \wk_person_detection_request_v1.bytes_per_row,
            Int(WK_PERSON_DETECTION_REQUEST_V1_BYTES_PER_ROW_OFFSET)
        )
        assertOffset(
            \wk_person_detection_request_v1.rgb_length,
            Int(WK_PERSON_DETECTION_REQUEST_V1_RGB_LENGTH_OFFSET)
        )
        assertOffset(
            \wk_person_detection_request_v1.reserved_0,
            Int(WK_PERSON_DETECTION_REQUEST_V1_RESERVED_0_OFFSET)
        )
        assertOffset(
            \wk_person_detection_request_v1.reserved_1,
            Int(WK_PERSON_DETECTION_REQUEST_V1_RESERVED_1_OFFSET)
        )

        XCTAssertEqual(
            MemoryLayout<wk_person_rect_v1>.size,
            Int(WK_PERSON_RECT_V1_SIZE)
        )
        assertOffset(
            \wk_person_rect_v1.abi_version,
            Int(WK_PERSON_RECT_V1_ABI_VERSION_OFFSET)
        )
        assertOffset(
            \wk_person_rect_v1.struct_size,
            Int(WK_PERSON_RECT_V1_STRUCT_SIZE_OFFSET)
        )
        assertOffset(
            \wk_person_rect_v1.left,
            Int(WK_PERSON_RECT_V1_LEFT_OFFSET)
        )
        assertOffset(
            \wk_person_rect_v1.top,
            Int(WK_PERSON_RECT_V1_TOP_OFFSET)
        )
        assertOffset(
            \wk_person_rect_v1.width,
            Int(WK_PERSON_RECT_V1_WIDTH_OFFSET)
        )
        assertOffset(
            \wk_person_rect_v1.height,
            Int(WK_PERSON_RECT_V1_HEIGHT_OFFSET)
        )
        assertOffset(
            \wk_person_rect_v1.confidence_basis_points,
            Int(WK_PERSON_RECT_V1_CONFIDENCE_BASIS_POINTS_OFFSET)
        )
        assertOffset(
            \wk_person_rect_v1.result_ordinal,
            Int(WK_PERSON_RECT_V1_RESULT_ORDINAL_OFFSET)
        )
        assertOffset(
            \wk_person_rect_v1.reserved_0,
            Int(WK_PERSON_RECT_V1_RESERVED_0_OFFSET)
        )

        XCTAssertEqual(
            MemoryLayout<wk_person_detection_metadata_v1>.size,
            Int(WK_PERSON_DETECTION_METADATA_V1_SIZE)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.abi_version,
            Int(WK_PERSON_DETECTION_METADATA_V1_ABI_VERSION_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.struct_size,
            Int(WK_PERSON_DETECTION_METADATA_V1_STRUCT_SIZE_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.request_revision,
            Int(WK_PERSON_DETECTION_METADATA_V1_REQUEST_REVISION_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.result_count,
            Int(WK_PERSON_DETECTION_METADATA_V1_RESULT_COUNT_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.os_major,
            Int(WK_PERSON_DETECTION_METADATA_V1_OS_MAJOR_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.os_minor,
            Int(WK_PERSON_DETECTION_METADATA_V1_OS_MINOR_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.os_patch,
            Int(WK_PERSON_DETECTION_METADATA_V1_OS_PATCH_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.reserved_0,
            Int(WK_PERSON_DETECTION_METADATA_V1_RESERVED_0_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.os_build,
            Int(WK_PERSON_DETECTION_METADATA_V1_OS_BUILD_OFFSET)
        )
        assertOffset(
            \wk_person_detection_metadata_v1.vision_framework_build,
            Int(WK_PERSON_DETECTION_METADATA_V1_VISION_BUILD_OFFSET)
        )
    }

    func testMalformedRequestsZeroOutputsAndNeverWriteRectangles() {
        let bytes = [UInt8](repeating: 0, count: 12)
        let invalid = status(WK_PERSON_DETECTION_INVALID_INPUT_V1)
        let unsupported = status(
            WK_PERSON_DETECTION_UNSUPPORTED_REVISION_V1
        )

        assertRejected(
            request: request(width: 0, height: 2),
            bytes: bytes,
            expectedStatus: invalid
        )
        assertRejected(
            request: request(width: 16_385, height: 1),
            bytes: bytes,
            expectedStatus: invalid
        )
        assertRejected(
            request: request(width: 8_193, height: 8_193),
            bytes: bytes,
            expectedStatus: invalid
        )

        var wrongABI = request(width: 2, height: 2)
        wrongABI.abi_version = 2
        assertRejected(
            request: wrongABI,
            bytes: bytes,
            expectedStatus: unsupported
        )
        var wrongSize = request(width: 2, height: 2)
        wrongSize.struct_size -= 1
        assertRejected(
            request: wrongSize,
            bytes: bytes,
            expectedStatus: unsupported
        )
        var reserved = request(width: 2, height: 2)
        reserved.reserved_1 = 1
        assertRejected(
            request: reserved,
            bytes: bytes,
            expectedStatus: invalid
        )
        var badStride = request(width: 2, height: 2)
        badStride.bytes_per_row = 7
        assertRejected(
            request: badStride,
            bytes: bytes,
            expectedStatus: invalid
        )
        var shortLength = request(width: 2, height: 2)
        shortLength.rgb_length = 11
        assertRejected(
            request: shortLength,
            bytes: bytes,
            expectedStatus: invalid
        )
        var longLength = request(width: 2, height: 2)
        longLength.rgb_length = 13
        assertRejected(
            request: longLength,
            bytes: bytes,
            expectedStatus: invalid
        )
    }

    func testNullPointersAndCapacityBoundsAreRejected() {
        var request = request(width: 2, height: 2)
        var bytes = [UInt8](repeating: 0, count: 12)
        var rectangles = [wk_person_rect_v1](
            repeating: wk_person_rect_v1(),
            count: 32
        )
        var count: UInt32 = 91
        var metadata = wk_person_detection_metadata_v1()
        let invalid = status(WK_PERSON_DETECTION_INVALID_INPUT_V1)

        bytes.withUnsafeMutableBufferPointer { rgb in
            rectangles.withUnsafeMutableBufferPointer { output in
                XCTAssertEqual(
                    wk_detect_people_rgb_v1(
                        nil,
                        rgb.baseAddress,
                        output.baseAddress,
                        32,
                        &count,
                        &metadata
                    ),
                    invalid
                )
                XCTAssertEqual(count, 0)
                count = 91
                XCTAssertEqual(
                    wk_detect_people_rgb_v1(
                        &request,
                        nil,
                        output.baseAddress,
                        32,
                        &count,
                        &metadata
                    ),
                    invalid
                )
                XCTAssertEqual(count, 0)
                count = 91
                XCTAssertEqual(
                    wk_detect_people_rgb_v1(
                        &request,
                        rgb.baseAddress,
                        nil,
                        32,
                        &count,
                        &metadata
                    ),
                    invalid
                )
                XCTAssertEqual(count, 0)
                XCTAssertEqual(
                    wk_detect_people_rgb_v1(
                        &request,
                        rgb.baseAddress,
                        output.baseAddress,
                        32,
                        nil,
                        &metadata
                    ),
                    invalid
                )
                count = 91
                XCTAssertEqual(
                    wk_detect_people_rgb_v1(
                        &request,
                        rgb.baseAddress,
                        output.baseAddress,
                        32,
                        &count,
                        nil
                    ),
                    invalid
                )
                XCTAssertEqual(count, 0)
            }
        }

        assertRejected(
            request: request,
            bytes: bytes,
            capacity: 0,
            expectedStatus: invalid
        )
        assertRejected(
            request: request,
            bytes: bytes,
            capacity: 33,
            expectedStatus: invalid
        )
    }

    func testProductionVisionRequestRunsAndReportsPublicRuntimeMetadata() {
        let side = 256
        var request = request(width: UInt32(side), height: UInt32(side))
        var bytes = [UInt8](repeating: 0, count: side * side * 3)
        for pixel in 0..<(side * side) {
            let value: UInt8 = ((pixel / side) / 16 + (pixel % side) / 16)
                .isMultiple(of: 2) ? 48 : 208
            bytes[pixel * 3] = value
            bytes[pixel * 3 + 1] = value
            bytes[pixel * 3 + 2] = value
        }
        var rectangles = [wk_person_rect_v1](
            repeating: wk_person_rect_v1(),
            count: 32
        )
        var count: UInt32 = 99
        var metadata = wk_person_detection_metadata_v1()
        let result = bytes.withUnsafeMutableBufferPointer { rgb in
            rectangles.withUnsafeMutableBufferPointer { output in
                wk_detect_people_rgb_v1(
                    &request,
                    rgb.baseAddress,
                    output.baseAddress,
                    32,
                    &count,
                    &metadata
                )
            }
        }

        XCTAssertEqual(result, status(WK_PERSON_DETECTION_OK_V1))
        XCTAssertEqual(count, 0)
        XCTAssertEqual(
            metadata.abi_version,
            UInt32(WK_PERSON_DETECTION_ABI_V1)
        )
        XCTAssertEqual(
            metadata.struct_size,
            UInt32(WK_PERSON_DETECTION_METADATA_V1_SIZE)
        )
        XCTAssertEqual(
            metadata.request_revision,
            UInt32(WK_PERSON_DETECTION_REQUEST_REVISION_V1)
        )
        XCTAssertEqual(metadata.result_count, count)
        XCTAssertGreaterThan(metadata.os_major, 0)
        XCTAssertFalse(
            metadataString(
                metadata,
                offset: Int(
                    WK_PERSON_DETECTION_METADATA_V1_OS_BUILD_OFFSET
                )
            ).isEmpty
        )
        XCTAssertFalse(
            metadataString(
                metadata,
                offset: Int(
                    WK_PERSON_DETECTION_METADATA_V1_VISION_BUILD_OFFSET
                )
            ).isEmpty
        )
    }

    func testReviewedOpenCVFixturesThroughProductionCABI() throws {
        let fixtures = [
            FixtureExpectation(
                name: "building",
                extension: "jpg",
                countRange: 0...0,
                expectedPeople: [],
                minimumIoU: 0
            ),
            FixtureExpectation(
                name: "basketball1",
                extension: "png",
                countRange: 2...3,
                expectedPeople: [
                    CGRect(x: 29, y: 80, width: 145, height: 391),
                    CGRect(x: 420, y: 13, width: 220, height: 467),
                ],
                minimumIoU: 0.25
            ),
            FixtureExpectation(
                name: "basketball1",
                extension: "png",
                crop: CGRect(x: 0, y: 0, width: 220, height: 480),
                countRange: 1...1,
                expectedPeople: [
                    CGRect(x: 29, y: 80, width: 145, height: 391),
                ],
                minimumIoU: 0.25
            ),
            FixtureExpectation(
                name: "basketball2",
                extension: "png",
                countRange: 2...3,
                expectedPeople: [
                    CGRect(x: 29, y: 80, width: 145, height: 391),
                    CGRect(x: 420, y: 13, width: 220, height: 467),
                ],
                minimumIoU: 0.25
            ),
        ]

        for fixture in fixtures {
            let detected = try detectFixture(fixture)
            XCTAssertTrue(
                fixture.countRange.contains(detected.count),
                "\(fixture.name): unexpected count \(detected.count)"
            )
            for expected in fixture.expectedPeople {
                let bestIoU = detected.map { intersectionOverUnion($0, expected) }
                    .max() ?? 0
                XCTAssertGreaterThanOrEqual(
                    bestIoU,
                    fixture.minimumIoU,
                    "\(fixture.name): expected person was not covered"
                )
            }
        }
    }

    func testRectangleConversionClipsRoundsAndUsesTopLeftCoordinates() throws {
        let observation = PersonDetectionObservation(
            x: -0.1,
            y: 0.1,
            width: 0.35,
            height: 0.4,
            confidence: 0.12345,
            ordinal: 7
        )
        let rectangles = try converted(
            [observation],
            width: 10,
            height: 10
        )
        let rectangle = try XCTUnwrap(rectangles.first)
        XCTAssertEqual(rectangle.left, 0)
        XCTAssertEqual(rectangle.top, 5)
        XCTAssertEqual(rectangle.width, 3)
        XCTAssertEqual(rectangle.height, 4)
        XCTAssertEqual(rectangle.confidence_basis_points, 1_235)
        XCTAssertEqual(rectangle.result_ordinal, 7)
    }

    func testOverlappingRectanglesArePreservedInProviderOrder() throws {
        let observations = [
            PersonDetectionObservation(
                x: 0.1,
                y: 0.1,
                width: 0.6,
                height: 0.7,
                confidence: 0.5,
                ordinal: 4
            ),
            PersonDetectionObservation(
                x: 0.4,
                y: 0.2,
                width: 0.5,
                height: 0.6,
                confidence: 1.5,
                ordinal: 9
            ),
        ]
        let rectangles = try converted(
            observations,
            width: 100,
            height: 100
        )

        XCTAssertEqual(rectangles.count, 2)
        XCTAssertEqual(rectangles.map(\.result_ordinal), [4, 9])
        XCTAssertLessThan(rectangles[1].left, rectangles[0].left + rectangles[0].width)
        XCTAssertLessThan(rectangles[0].top, rectangles[1].top + rectangles[1].height)
        XCTAssertEqual(rectangles[1].confidence_basis_points, 10_000)
    }

    func testMalformedProviderOutputFailsAsAWhole() {
        let valid = PersonDetectionObservation(
            x: 0.1,
            y: 0.1,
            width: 0.2,
            height: 0.2,
            confidence: 0.8,
            ordinal: 0
        )
        for malformed in [
            PersonDetectionObservation(
                x: .nan, y: 0, width: 1, height: 1,
                confidence: 1, ordinal: 1
            ),
            PersonDetectionObservation(
                x: 0, y: 0, width: .infinity, height: 1,
                confidence: 1, ordinal: 1
            ),
            PersonDetectionObservation(
                x: 0, y: 0, width: 1, height: 1,
                confidence: .nan, ordinal: 1
            ),
            PersonDetectionObservation(
                x: 0, y: 0, width: 1, height: 1,
                confidence: .infinity, ordinal: 1
            ),
            PersonDetectionObservation(
                x: 0, y: 0, width: 1, height: 1,
                confidence: -.infinity, ordinal: 1
            ),
            PersonDetectionObservation(
                x: 0, y: 0, width: 0, height: 1,
                confidence: 1, ordinal: 1
            ),
            PersonDetectionObservation(
                x: 2, y: 2, width: 1, height: 1,
                confidence: 1, ordinal: 1
            ),
        ] {
            guard case .invalidProviderOutput =
                PersonDetectionConversion.convert(
                    [valid, malformed],
                    imageWidth: 100,
                    imageHeight: 100,
                    capacity: 32
                )
            else {
                return XCTFail("malformed output was accepted")
            }
        }
    }

    func testOverflowIsBoundedAndReturnsNoPartialRectangles() {
        let observations = (0..<34).map {
            PersonDetectionObservation(
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                confidence: 1,
                ordinal: UInt32($0)
            )
        }
        guard case .overflow(let count) = PersonDetectionConversion.convert(
            observations,
            imageWidth: 100,
            imageHeight: 100,
            capacity: 32
        ) else {
            return XCTFail("crowded output did not overflow")
        }
        XCTAssertEqual(count, UInt32(WK_PERSON_DETECTION_OVERFLOW_COUNT_V1))

        guard case .overflow(let capacityCount) =
            PersonDetectionConversion.convert(
                Array(observations.prefix(2)),
                imageWidth: 100,
                imageHeight: 100,
                capacity: 1
            )
        else {
            return XCTFail("undersized capacity did not overflow")
        }
        XCTAssertEqual(capacityCount, 2)

        guard case .overflow(let thirtyOneCount) =
            PersonDetectionConversion.convert(
                Array(observations.prefix(32)),
                imageWidth: 100,
                imageHeight: 100,
                capacity: 31
            )
        else {
            return XCTFail("capacity 31 did not overflow")
        }
        XCTAssertEqual(thirtyOneCount, 32)
    }

    func testVisionErrorsMapToStableTerminalStatuses() {
        let retryable = status(WK_PERSON_DETECTION_RETRYABLE_FAILURE_V1)
        let permanent = status(
            WK_PERSON_DETECTION_PERMANENT_UNAVAILABLE_V1
        )
        let internalFailure = status(
            WK_PERSON_DETECTION_INTERNAL_FAILURE_V1
        )
        let processUnavailable = status(
            WK_PERSON_DETECTION_PROCESS_UNAVAILABLE_V1
        )

        for code in [1, 3, 6, 9, 10, 17, 20] {
            XCTAssertEqual(
                PersonDetectionErrorMapping.status(
                    domain: VNErrorDomain,
                    code: code
                ),
                retryable
            )
        }
        for code in [2, 4, 5, 7, 8, 12, 13, 14, 15, 16, 18, 19, 21, 22] {
            XCTAssertEqual(
                PersonDetectionErrorMapping.status(
                    domain: VNErrorDomain,
                    code: code
                ),
                permanent
            )
        }
        for code in [-1, 0, 11, 999] {
            XCTAssertEqual(
                PersonDetectionErrorMapping.status(
                    domain: VNErrorDomain,
                    code: code
                ),
                internalFailure
            )
        }
        XCTAssertEqual(
            PersonDetectionErrorMapping.status(
                domain: NSCocoaErrorDomain,
                code: 1
            ),
            internalFailure
        )
        XCTAssertEqual(
            PersonDetectionErrorMapping.status(
                for: NSError(
                    domain: VNErrorDomain,
                    code: 9,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "Error creating fallback context: check process entitlements (DESIGN)"
                    ]
                )
            ),
            processUnavailable
        )
        XCTAssertEqual(
            PersonDetectionErrorMapping.status(
                for: NSError(
                    domain: VNErrorDomain,
                    code: 9,
                    userInfo: [
                        NSLocalizedDescriptionKey: "Transient internal inference failure"
                    ]
                )
            ),
            retryable
        )
    }

    private func request(
        width: UInt32,
        height: UInt32
    ) -> wk_person_detection_request_v1 {
        var request = wk_person_detection_request_v1()
        request.abi_version = UInt32(WK_PERSON_DETECTION_ABI_V1)
        request.struct_size = UInt32(WK_PERSON_DETECTION_REQUEST_V1_SIZE)
        request.width = width
        request.height = height
        request.bytes_per_row = UInt64(width) * 3
        request.rgb_length = request.bytes_per_row * UInt64(height)
        return request
    }

    private func detectFixture(
        _ fixture: FixtureExpectation
    ) throws -> [CGRect] {
        let url = try XCTUnwrap(
            Bundle.module.url(
                forResource: fixture.name,
                withExtension: fixture.extension,
                subdirectory: "Fixtures/PersonDetection"
            ),
            "missing fixture \(fixture.name)"
        )
        let source = try XCTUnwrap(
            CGImageSourceCreateWithURL(url as CFURL, nil)
        )
        let image = try XCTUnwrap(CGImageSourceCreateImageAtIndex(source, 0, nil))
        let crop = fixture.crop ?? CGRect(
            x: 0,
            y: 0,
            width: image.width,
            height: image.height
        )
        let width = Int(crop.width)
        let height = Int(crop.height)
        var rgba = [UInt8](repeating: 0, count: width * height * 4)
        let colorSpace = try XCTUnwrap(
            CGColorSpace(name: CGColorSpace.sRGB)
        )
        let bitmapInfo = CGBitmapInfo(
            rawValue: CGImageAlphaInfo.noneSkipLast.rawValue
        ).union(.byteOrder32Big)
        try rgba.withUnsafeMutableBytes { bytes in
            let context = try XCTUnwrap(
                CGContext(
                    data: bytes.baseAddress,
                    width: width,
                    height: height,
                    bitsPerComponent: 8,
                    bytesPerRow: width * 4,
                    space: colorSpace,
                    bitmapInfo: bitmapInfo.rawValue
                )
            )
            context.translateBy(x: 0, y: CGFloat(height))
            context.scaleBy(x: 1, y: -1)
            context.draw(
                image,
                in: CGRect(
                    x: -crop.origin.x,
                    y: -crop.origin.y,
                    width: CGFloat(image.width),
                    height: CGFloat(image.height)
                )
            )
        }

        var rgb = [UInt8](repeating: 0, count: width * height * 3)
        for pixel in 0..<(width * height) {
            rgb[pixel * 3] = rgba[pixel * 4]
            rgb[pixel * 3 + 1] = rgba[pixel * 4 + 1]
            rgb[pixel * 3 + 2] = rgba[pixel * 4 + 2]
        }
        var request = request(width: UInt32(width), height: UInt32(height))
        var rectangles = [wk_person_rect_v1](
            repeating: wk_person_rect_v1(),
            count: 32
        )
        var count: UInt32 = 0
        var metadata = wk_person_detection_metadata_v1()
        let result = rgb.withUnsafeMutableBufferPointer { input in
            rectangles.withUnsafeMutableBufferPointer { output in
                wk_detect_people_rgb_v1(
                    &request,
                    input.baseAddress,
                    output.baseAddress,
                    UInt32(output.count),
                    &count,
                    &metadata
                )
            }
        }
        XCTAssertEqual(
            result,
            status(WK_PERSON_DETECTION_OK_V1),
            "\(fixture.name): Vision status \(result)"
        )
        guard result == status(WK_PERSON_DETECTION_OK_V1) else {
            return []
        }
        return rectangles.prefix(Int(count)).map {
            CGRect(
                x: Int($0.left),
                y: Int($0.top),
                width: Int($0.width),
                height: Int($0.height)
            )
        }
    }

    private func intersectionOverUnion(_ left: CGRect, _ right: CGRect) -> Double {
        let intersection = left.intersection(right)
        guard !intersection.isNull, !intersection.isEmpty else {
            return 0
        }
        let intersectionArea = intersection.width * intersection.height
        let unionArea = left.width * left.height
            + right.width * right.height
            - intersectionArea
        guard unionArea > 0 else {
            return 0
        }
        return Double(intersectionArea / unionArea)
    }

    private func assertOffset<Root>(
        _ keyPath: PartialKeyPath<Root>,
        _ expected: Int,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(
            MemoryLayout<Root>.offset(of: keyPath),
            expected,
            file: file,
            line: line
        )
    }

    private func assertRejected(
        request: wk_person_detection_request_v1,
        bytes: [UInt8],
        capacity: UInt32 = 32,
        expectedStatus: Int32,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        var request = request
        var bytes = bytes
        var rectangles = [wk_person_rect_v1](
            repeating: wk_person_rect_v1(),
            count: 32
        )
        rectangles[0].left = 0xfeed_beef
        var count: UInt32 = 77
        var metadata = wk_person_detection_metadata_v1()
        metadata.request_revision = 77
        let result = bytes.withUnsafeMutableBufferPointer { rgb in
            rectangles.withUnsafeMutableBufferPointer { output in
                wk_detect_people_rgb_v1(
                    &request,
                    rgb.baseAddress,
                    output.baseAddress,
                    capacity,
                    &count,
                    &metadata
                )
            }
        }
        XCTAssertEqual(result, expectedStatus, file: file, line: line)
        XCTAssertEqual(count, 0, file: file, line: line)
        XCTAssertEqual(metadata.abi_version, 0, file: file, line: line)
        XCTAssertEqual(metadata.request_revision, 0, file: file, line: line)
        XCTAssertEqual(
            rectangles[0].left,
            0xfeed_beef,
            file: file,
            line: line
        )
    }

    private func converted(
        _ observations: [PersonDetectionObservation],
        width: UInt32,
        height: UInt32
    ) throws -> [wk_person_rect_v1] {
        guard case .rectangles(let rectangles) =
            PersonDetectionConversion.convert(
                observations,
                imageWidth: width,
                imageHeight: height,
                capacity: 32
            )
        else {
            throw ConversionTestError.failed
        }
        return rectangles
    }

    private func metadataString(
        _ metadata: wk_person_detection_metadata_v1,
        offset: Int
    ) -> String {
        var metadata = metadata
        return withUnsafeBytes(of: &metadata) { raw in
            let start = raw.baseAddress!.advanced(by: offset)
                .assumingMemoryBound(to: CChar.self)
            return String(cString: start)
        }
    }

    private func status(
        _ status: wk_person_detection_status_v1
    ) -> Int32 {
        Int32(status.rawValue)
    }
}

private enum ConversionTestError: Error {
    case failed
}

private struct FixtureExpectation {
    let name: String
    let `extension`: String
    var crop: CGRect? = nil
    let countRange: ClosedRange<Int>
    let expectedPeople: [CGRect]
    let minimumIoU: Double
}
