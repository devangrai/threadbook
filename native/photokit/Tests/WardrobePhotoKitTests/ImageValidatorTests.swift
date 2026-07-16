import Darwin
import Foundation
import ImageIO
import UniformTypeIdentifiers
import XCTest
@testable import WardrobePhotoKit

final class ImageValidatorTests: XCTestCase {
    func testValidPNGIsDecodedAndDescriptorIsClosed() throws {
        let data = try makeImageData(type: .png)
        let fd = try openFixture(data)
        var width: UInt32 = 99
        var height: UInt32 = 99
        var frames: UInt32 = 99
        let status = withUTI("public.png") {
            ImageValidator.validate(
                duplicatedReadOnlyFD: fd,
                uti: $0.baseAddress,
                utiLength: $0.count,
                outWidth: &width,
                outHeight: &height,
                outFrameCount: &frames
            )
        }
        XCTAssertEqual(status, .ok)
        XCTAssertEqual(width, 2)
        XCTAssertEqual(height, 3)
        XCTAssertEqual(frames, 1)
        XCTAssertEqual(fcntl(fd, F_GETFD), -1)
        XCTAssertEqual(errno, EBADF)
    }

    func testUTIMismatchAndTrailingBytesFailWithoutWritingOutputs() throws {
        var data = try makeImageData(type: .png)
        data.append(0)
        let fd = try openFixture(data)
        var width: UInt32 = 41
        var height: UInt32 = 42
        var frames: UInt32 = 43
        let status = withUTI("public.jpeg") {
            ImageValidator.validate(
                duplicatedReadOnlyFD: fd,
                uti: $0.baseAddress,
                utiLength: $0.count,
                outWidth: &width,
                outHeight: &height,
                outFrameCount: &frames
            )
        }
        XCTAssertEqual(status, .invalid)
        XCTAssertEqual(width, 41)
        XCTAssertEqual(height, 42)
        XCTAssertEqual(frames, 43)
        XCTAssertEqual(fcntl(fd, F_GETFD), -1)
    }

    func testValidJPEGIsDecodedThroughTheSameDescriptorBoundary() throws {
        let fd = try openFixture(try makeImageData(type: .jpeg))
        var width: UInt32 = 0
        var height: UInt32 = 0
        var frames: UInt32 = 0
        let status = withUTI("public.jpeg") {
            ImageValidator.validate(
                duplicatedReadOnlyFD: fd,
                uti: $0.baseAddress,
                utiLength: $0.count,
                outWidth: &width,
                outHeight: &height,
                outFrameCount: &frames
            )
        }
        XCTAssertEqual(status, .ok)
        XCTAssertEqual(width, 2)
        XCTAssertEqual(height, 3)
        XCTAssertEqual(frames, 1)
    }

    func testFramingRejectsTruncationAPNGAndAcceptsOnePrimaryHEIFShape() throws {
        let png = try makeImageData(type: .png)
        XCTAssertEqual(ImageFraming.validate(png), .png)
        XCTAssertNil(ImageFraming.validate(png.dropLast()))

        var animated = png
        animated.insert(contentsOf: pngChunk(type: "acTL"), at: 33)
        XCTAssertNil(ImageFraming.validate(animated))

        var corrupt = png
        let marker = Data("IDAT".utf8)
        let markerRange = try XCTUnwrap(corrupt.range(of: marker))
        corrupt[markerRange.upperBound] ^= 1
        XCTAssertNil(ImageFraming.validate(corrupt))

        let heif = syntheticHEIF()
        XCTAssertEqual(ImageFraming.validate(heif), .heif)
        XCTAssertNil(ImageFraming.validate(heif + Data([0])))
    }

    func testWriteOnlyDescriptorIsRejectedAndOwned() throws {
        let data = try makeImageData(type: .png)
        let url = try fixtureURL(data)
        let fd = open(url.path, O_WRONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        var width: UInt32 = 1
        var height: UInt32 = 1
        var frames: UInt32 = 1
        let status = withUTI("public.png") {
            ImageValidator.validate(
                duplicatedReadOnlyFD: fd,
                uti: $0.baseAddress,
                utiLength: $0.count,
                outWidth: &width,
                outHeight: &height,
                outFrameCount: &frames
            )
        }
        XCTAssertEqual(status, .invalid)
        XCTAssertEqual(fcntl(fd, F_GETFD), -1)
        try? FileManager.default.removeItem(at: url)
    }

    private func makeImageData(
        type: UTType,
        width: Int = 2,
        height: Int = 3
    ) throws -> Data {
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        let context = try XCTUnwrap(
            CGContext(
                data: nil,
                width: width,
                height: height,
                bitsPerComponent: 8,
                bytesPerRow: 0,
                space: colorSpace,
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
            )
        )
        context.setFillColor(red: 0.2, green: 0.4, blue: 0.6, alpha: 1)
        context.fill(
            CGRect(x: 0, y: 0, width: width, height: height)
        )
        let image = try XCTUnwrap(context.makeImage())
        let output = NSMutableData()
        let destination = try XCTUnwrap(
            CGImageDestinationCreateWithData(
                output,
                type.identifier as CFString,
                1,
                nil
            )
        )
        CGImageDestinationAddImage(destination, image, nil)
        XCTAssertTrue(CGImageDestinationFinalize(destination))
        return output as Data
    }

    private func openFixture(_ data: Data) throws -> Int32 {
        let url = try fixtureURL(data)
        let fd = open(url.path, O_RDONLY | O_CLOEXEC)
        try FileManager.default.removeItem(at: url)
        return fd
    }

    private func fixtureURL(_ data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("wk-photokit-\(UUID().uuidString)")
        try data.write(to: url, options: .atomic)
        return url
    }

    private func withUTI<T>(
        _ value: String,
        body: (UnsafeBufferPointer<UInt8>) -> T
    ) -> T {
        Array(value.utf8).withUnsafeBufferPointer(body)
    }

    private func pngChunk(type: String) -> [UInt8] {
        let typeBytes = Array(type.utf8)
        var crc = UInt32.max
        for byte in typeBytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                let mask = UInt32(bitPattern: -Int32(crc & 1))
                crc = (crc >> 1) ^ (0xedb8_8320 & mask)
            }
        }
        crc = ~crc
        return [0, 0, 0, 0] + typeBytes + [
            UInt8((crc >> 24) & 0xff),
            UInt8((crc >> 16) & 0xff),
            UInt8((crc >> 8) & 0xff),
            UInt8(crc & 0xff),
        ]
    }

    private func syntheticHEIF() -> Data {
        func box(_ type: String, _ payload: [UInt8]) -> [UInt8] {
            let size = UInt32(8 + payload.count)
            return [
                UInt8((size >> 24) & 0xff),
                UInt8((size >> 16) & 0xff),
                UInt8((size >> 8) & 0xff),
                UInt8(size & 0xff),
            ] + Array(type.utf8) + payload
        }
        let ftyp = box(
            "ftyp",
            Array("heic".utf8) + [0, 0, 0, 0] + Array("mif1".utf8)
        )
        let pitm = box("pitm", [0, 0, 0, 0, 0, 1])
        let iloc = box("iloc", [])
        let iinf = box("iinf", [])
        let meta = box("meta", [0, 0, 0, 0] + pitm + iloc + iinf)
        return Data(ftyp + meta + box("mdat", [0]))
    }
}
