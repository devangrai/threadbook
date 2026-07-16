import CoreGraphics
import Darwin
import Foundation
import Vision
import WardrobePhotoKitObjC

struct PersonDetectionObservation {
    let x: Double
    let y: Double
    let width: Double
    let height: Double
    let confidence: Double
    let ordinal: UInt32
}

enum PersonDetectionConversion {
    enum Result {
        case rectangles([wk_person_rect_v1])
        case overflow(UInt32)
        case invalidProviderOutput
    }

    static func convert(
        _ observations: [PersonDetectionObservation],
        imageWidth: UInt32,
        imageHeight: UInt32,
        capacity: UInt32
    ) -> Result {
        if observations.count > Int(capacity)
            || observations.count > Int(WK_PERSON_DETECTION_MAX_RECTS_V1)
        {
            return .overflow(boundedCount(observations.count))
        }

        var converted: [wk_person_rect_v1] = []
        converted.reserveCapacity(observations.count)
        for observation in observations {
            guard let rectangle = convert(
                observation,
                imageWidth: imageWidth,
                imageHeight: imageHeight
            ) else {
                return .invalidProviderOutput
            }
            converted.append(rectangle)
        }
        return .rectangles(converted)
    }

    static func boundedCount(_ count: Int) -> UInt32 {
        UInt32(min(count, Int(WK_PERSON_DETECTION_OVERFLOW_COUNT_V1)))
    }

    private static func convert(
        _ observation: PersonDetectionObservation,
        imageWidth: UInt32,
        imageHeight: UInt32
    ) -> wk_person_rect_v1? {
        let values = [
            observation.x,
            observation.y,
            observation.width,
            observation.height,
            observation.confidence,
        ]
        guard values.allSatisfy(\.isFinite),
              observation.width > 0,
              observation.height > 0
        else {
            return nil
        }

        let normalizedRight = observation.x + observation.width
        let normalizedTop = observation.y + observation.height
        guard normalizedRight.isFinite, normalizedTop.isFinite else {
            return nil
        }

        let clippedLeft = max(0, observation.x)
        let clippedRight = min(1, normalizedRight)
        let clippedBottom = max(0, observation.y)
        let clippedTop = min(1, normalizedTop)
        guard clippedRight > clippedLeft, clippedTop > clippedBottom else {
            return nil
        }

        let pixelWidth = Double(imageWidth)
        let pixelHeight = Double(imageHeight)
        let left = clampedPixelEdge(
            floor(clippedLeft * pixelWidth),
            maximum: imageWidth
        )
        let right = clampedPixelEdge(
            ceil(clippedRight * pixelWidth),
            maximum: imageWidth
        )
        let top = clampedPixelEdge(
            floor((1 - clippedTop) * pixelHeight),
            maximum: imageHeight
        )
        let bottom = clampedPixelEdge(
            ceil((1 - clippedBottom) * pixelHeight),
            maximum: imageHeight
        )
        guard right > left, bottom > top else {
            return nil
        }

        let boundedConfidence = min(1, max(0, observation.confidence))
        let confidenceBasisPoints = UInt32(
            (boundedConfidence * 10_000).rounded(.toNearestOrAwayFromZero)
        )
        var result = wk_person_rect_v1()
        result.abi_version = UInt32(WK_PERSON_DETECTION_ABI_V1)
        result.struct_size = UInt32(WK_PERSON_RECT_V1_SIZE)
        result.left = left
        result.top = top
        result.width = right - left
        result.height = bottom - top
        result.confidence_basis_points = confidenceBasisPoints
        result.result_ordinal = observation.ordinal
        result.reserved_0 = 0
        return result
    }

    private static func clampedPixelEdge(
        _ value: Double,
        maximum: UInt32
    ) -> UInt32 {
        UInt32(min(Double(maximum), max(0, value)))
    }
}

private struct PersonDetectionRuntimeMetadata {
    let osMajor: UInt32
    let osMinor: UInt32
    let osPatch: UInt32
    let osBuild: [UInt8]
    let visionBuild: [UInt8]

    static func current() -> PersonDetectionRuntimeMetadata? {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        guard let osMajor = UInt32(exactly: version.majorVersion),
              let osMinor = UInt32(exactly: version.minorVersion),
              let osPatch = UInt32(exactly: version.patchVersion),
              let osBuild = fixedCString(kernelBuild()),
              let visionBuild = fixedCString(
                Bundle(for: VNDetectHumanRectanglesRequest.self)
                    .object(forInfoDictionaryKey: "CFBundleVersion") as? String
              )
        else {
            return nil
        }
        return PersonDetectionRuntimeMetadata(
            osMajor: osMajor,
            osMinor: osMinor,
            osPatch: osPatch,
            osBuild: osBuild,
            visionBuild: visionBuild
        )
    }

    private static func kernelBuild() -> String? {
        var length = 0
        guard sysctlbyname("kern.osversion", nil, &length, nil, 0) == 0,
              length > 1
        else {
            return nil
        }
        var bytes = [CChar](repeating: 0, count: length)
        guard sysctlbyname(
            "kern.osversion",
            &bytes,
            &length,
            nil,
            0
        ) == 0 else {
            return nil
        }
        return String(cString: bytes)
    }

    private static func fixedCString(_ value: String?) -> [UInt8]? {
        guard let value else {
            return nil
        }
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count < 32, !bytes.contains(0) else {
            return nil
        }
        return bytes + [0]
    }
}

private enum PersonDetectionProvider {
    static func detect(
        request: wk_person_detection_request_v1,
        rgb: UnsafePointer<UInt8>
    ) -> (
        status: Int32,
        count: UInt32,
        rectangles: [wk_person_rect_v1]
    ) {
        let pixelCount = Int(request.width) * Int(request.height)
        var rgba = Data(count: pixelCount * 4)
        rgba.withUnsafeMutableBytes { rawDestination in
            let destination = rawDestination.bindMemory(to: UInt8.self)
            for pixel in 0..<pixelCount {
                let sourceOffset = pixel * 3
                let destinationOffset = pixel * 4
                destination[destinationOffset] = rgb[sourceOffset]
                destination[destinationOffset + 1] = rgb[sourceOffset + 1]
                destination[destinationOffset + 2] = rgb[sourceOffset + 2]
                destination[destinationOffset + 3] = 255
            }
        }
        let bitmapInfo = CGBitmapInfo(
            rawValue: CGImageAlphaInfo.noneSkipLast.rawValue
        ).union(.byteOrder32Big)
        guard let provider = CGDataProvider(data: rgba as CFData),
              let colorSpace = CGColorSpace(name: CGColorSpace.sRGB),
              let image = CGImage(
                width: Int(request.width),
                height: Int(request.height),
                bitsPerComponent: 8,
                bitsPerPixel: 32,
                bytesPerRow: Int(request.width) * 4,
                space: colorSpace,
                bitmapInfo: bitmapInfo,
                provider: provider,
                decode: nil,
                shouldInterpolate: false,
                intent: .defaultIntent
              )
        else {
            return (permanentUnavailableStatus, 0, [])
        }

        let visionRequest = VNDetectHumanRectanglesRequest()
        visionRequest.revision = VNDetectHumanRectanglesRequestRevision2
        visionRequest.upperBodyOnly = false
        let handler = VNImageRequestHandler(cgImage: image, orientation: .up)
        var operationError: Error?
        let contained = wk_photokit_objc_perform {
            do {
                try handler.perform([visionRequest])
            } catch {
                operationError = error
            }
        }
        guard contained else {
            return (internalFailureStatus, 0, [])
        }
        if let operationError {
            return (
                PersonDetectionErrorMapping.status(for: operationError),
                0,
                []
            )
        }
        guard let results = visionRequest.results else {
            return (permanentUnavailableStatus, 0, [])
        }
        guard results.count <= Int(WK_PERSON_DETECTION_MAX_RECTS_V1) else {
            return (
                overflowStatus,
                PersonDetectionConversion.boundedCount(results.count),
                []
            )
        }

        let observations = results.enumerated().map { index, observation in
            PersonDetectionObservation(
                x: observation.boundingBox.origin.x,
                y: observation.boundingBox.origin.y,
                width: observation.boundingBox.width,
                height: observation.boundingBox.height,
                confidence: Double(observation.confidence),
                ordinal: UInt32(index)
            )
        }
        switch PersonDetectionConversion.convert(
            observations,
            imageWidth: request.width,
            imageHeight: request.height,
            capacity: UInt32(WK_PERSON_DETECTION_MAX_RECTS_V1)
        ) {
        case .rectangles(let rectangles):
            return (okStatus, UInt32(rectangles.count), rectangles)
        case .overflow(let count):
            return (overflowStatus, count, [])
        case .invalidProviderOutput:
            return (permanentUnavailableStatus, 0, [])
        }
    }
}

enum PersonDetectionErrorMapping {
    static func status(for error: Error) -> Int32 {
        let error = error as NSError
        if isVisionProcessUnavailable(error) {
            return processUnavailableStatus
        }
        return status(domain: error.domain, code: error.code)
    }

    static func status(domain: String, code: Int) -> Int32 {
        guard domain == VNErrorDomain else {
            return internalFailureStatus
        }
        switch code {
        case 1, 3, 6, 9, 10, 17, 20:
            return retryableFailureStatus
        case 2, 4, 5, 7, 8, 12, 13, 14, 15, 16, 18, 19, 21, 22:
            return permanentUnavailableStatus
        default:
            return internalFailureStatus
        }
    }

    private static func isVisionProcessUnavailable(_ error: NSError) -> Bool {
        guard error.domain == VNErrorDomain, error.code == 9,
              let description = error.userInfo[NSLocalizedDescriptionKey] as? String
        else {
            return false
        }
        return description.localizedCaseInsensitiveContains(
            "check process entitlements"
        )
    }
}

@_cdecl("wk_detect_people_rgb_v1")
public func wkDetectPeopleRGBV1(
    _ requestPointer: UnsafePointer<wk_person_detection_request_v1>?,
    _ rgb: UnsafePointer<UInt8>?,
    _ outRectangles: UnsafeMutablePointer<wk_person_rect_v1>?,
    _ outputCapacity: UInt32,
    _ outCount: UnsafeMutablePointer<UInt32>?,
    _ outMetadata: UnsafeMutablePointer<wk_person_detection_metadata_v1>?
) -> Int32 {
    if let outCount {
        outCount.pointee = 0
    }
    if let outMetadata {
        memset(
            outMetadata,
            0,
            MemoryLayout<wk_person_detection_metadata_v1>.size
        )
    }

    guard let requestPointer, let rgb, let outRectangles,
          let outCount, let outMetadata
    else {
        return invalidInputStatus
    }
    let request = requestPointer.pointee
    guard request.abi_version == UInt32(WK_PERSON_DETECTION_ABI_V1),
          request.struct_size == UInt32(WK_PERSON_DETECTION_REQUEST_V1_SIZE)
    else {
        return unsupportedRevisionStatus
    }
    guard request.reserved_0 == 0, request.reserved_1 == 0,
          request.width > 0,
          request.width <= UInt32(WK_PERSON_DETECTION_MAX_DIMENSION_V1),
          request.height > 0,
          request.height <= UInt32(WK_PERSON_DETECTION_MAX_DIMENSION_V1),
          outputCapacity > 0,
          outputCapacity <= UInt32(WK_PERSON_DETECTION_MAX_RECTS_V1)
    else {
        return invalidInputStatus
    }

    let (pixelCount, pixelOverflow) = UInt64(request.width)
        .multipliedReportingOverflow(by: UInt64(request.height))
    guard !pixelOverflow,
          pixelCount <= UInt64(WK_PERSON_DETECTION_MAX_PIXELS_V1)
    else {
        return invalidInputStatus
    }
    let (expectedStride, strideOverflow) = UInt64(request.width)
        .multipliedReportingOverflow(by: 3)
    guard !strideOverflow, request.bytes_per_row == expectedStride else {
        return invalidInputStatus
    }
    let (expectedLength, lengthOverflow) = request.bytes_per_row
        .multipliedReportingOverflow(by: UInt64(request.height))
    guard !lengthOverflow, request.rgb_length == expectedLength,
          request.rgb_length <= UInt64(Int.max)
    else {
        return invalidInputStatus
    }

    guard let runtime = PersonDetectionRuntimeMetadata.current() else {
        return permanentUnavailableStatus
    }
    writeMetadata(runtime, count: 0, to: outMetadata)

    let detection = PersonDetectionProvider.detect(request: request, rgb: rgb)
    let boundedCount = PersonDetectionConversion.boundedCount(
        Int(detection.count)
    )
    outCount.pointee = boundedCount
    outMetadata.pointee.result_count = boundedCount

    guard detection.status == okStatus else {
        return detection.status
    }
    if detection.rectangles.count > Int(outputCapacity) {
        let count = PersonDetectionConversion.boundedCount(
            detection.rectangles.count
        )
        outCount.pointee = count
        outMetadata.pointee.result_count = count
        return overflowStatus
    }
    for (index, rectangle) in detection.rectangles.enumerated() {
        outRectangles[index] = rectangle
    }
    return okStatus
}

private func writeMetadata(
    _ runtime: PersonDetectionRuntimeMetadata,
    count: UInt32,
    to metadata: UnsafeMutablePointer<wk_person_detection_metadata_v1>
) {
    metadata.pointee.abi_version = UInt32(WK_PERSON_DETECTION_ABI_V1)
    metadata.pointee.struct_size = UInt32(
        WK_PERSON_DETECTION_METADATA_V1_SIZE
    )
    metadata.pointee.request_revision = UInt32(
        WK_PERSON_DETECTION_REQUEST_REVISION_V1
    )
    metadata.pointee.result_count = count
    metadata.pointee.os_major = runtime.osMajor
    metadata.pointee.os_minor = runtime.osMinor
    metadata.pointee.os_patch = runtime.osPatch
    metadata.pointee.reserved_0 = 0
    let raw = UnsafeMutableRawPointer(metadata)
    runtime.osBuild.withUnsafeBytes { source in
        raw.advanced(
            by: Int(WK_PERSON_DETECTION_METADATA_V1_OS_BUILD_OFFSET)
        ).copyMemory(from: source.baseAddress!, byteCount: source.count)
    }
    runtime.visionBuild.withUnsafeBytes { source in
        raw.advanced(
            by: Int(WK_PERSON_DETECTION_METADATA_V1_VISION_BUILD_OFFSET)
        ).copyMemory(from: source.baseAddress!, byteCount: source.count)
    }
}

private let okStatus = Int32(WK_PERSON_DETECTION_OK_V1.rawValue)
private let invalidInputStatus = Int32(
    WK_PERSON_DETECTION_INVALID_INPUT_V1.rawValue
)
private let unsupportedRevisionStatus = Int32(
    WK_PERSON_DETECTION_UNSUPPORTED_REVISION_V1.rawValue
)
private let retryableFailureStatus = Int32(
    WK_PERSON_DETECTION_RETRYABLE_FAILURE_V1.rawValue
)
private let permanentUnavailableStatus = Int32(
    WK_PERSON_DETECTION_PERMANENT_UNAVAILABLE_V1.rawValue
)
private let overflowStatus = Int32(
    WK_PERSON_DETECTION_OUTPUT_OVERFLOW_V1.rawValue
)
private let internalFailureStatus = Int32(
    WK_PERSON_DETECTION_INTERNAL_FAILURE_V1.rawValue
)
private let processUnavailableStatus = Int32(
    WK_PERSON_DETECTION_PROCESS_UNAVAILABLE_V1.rawValue
)
