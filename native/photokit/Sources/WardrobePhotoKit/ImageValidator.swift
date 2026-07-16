import Darwin
import Foundation
import ImageIO
import UniformTypeIdentifiers
import WardrobePhotoKitObjC

enum ImageContainer: Equatable {
    case png
    case jpeg
    case heif
}

enum ImageFraming {
    private static let pngSignature: [UInt8] = [
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ]
    private static let heifBrands: Set<String> = [
        "heic", "heix", "hevc", "hevx", "mif1",
    ]

    static func validate(_ data: Data) -> ImageContainer? {
        let bytes = [UInt8](data)
        let png = bytes.starts(with: pngSignature)
        let jpeg = bytes.count >= 2 && bytes[0] == 0xff && bytes[1] == 0xd8
        let heif = isHEIFSignature(bytes)
        guard [png, jpeg, heif].filter({ $0 }).count == 1 else {
            return nil
        }
        if png {
            return validatePNG(bytes) ? .png : nil
        }
        if jpeg {
            return validateJPEG(bytes) ? .jpeg : nil
        }
        return validateHEIF(bytes) ? .heif : nil
    }

    private static func validatePNG(_ bytes: [UInt8]) -> Bool {
        var offset = pngSignature.count
        var sawHeader = false
        var sawImageData = false
        var sawEnd = false
        while offset < bytes.count {
            guard
                offset <= bytes.count - 12,
                let length = readBE32(bytes, at: offset).flatMap(Int.init(exactly:))
            else {
                return false
            }
            let typeStart = offset + 4
            let dataStart = offset + 8
            let (dataEnd, overflow) = dataStart.addingReportingOverflow(length)
            guard
                !overflow,
                dataEnd <= bytes.count - 4,
                let type = ascii(bytes, range: typeStart..<(typeStart + 4)),
                let expectedCRC = readBE32(bytes, at: dataEnd),
                crc32(bytes, range: typeStart..<dataEnd) == expectedCRC
            else {
                return false
            }
            if !sawHeader {
                guard type == "IHDR", length == 13 else {
                    return false
                }
                sawHeader = true
            } else if type == "IHDR" {
                return false
            }
            if type == "IDAT" {
                sawImageData = true
            }
            if type == "acTL" || type == "fcTL" || type == "fdAT" {
                return false
            }
            offset = dataEnd + 4
            if type == "IEND" {
                guard length == 0, !sawEnd, offset == bytes.count else {
                    return false
                }
                sawEnd = true
            } else if sawEnd {
                return false
            }
        }
        return sawHeader && sawImageData && sawEnd && offset == bytes.count
    }

    private static func validateJPEG(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 4 else {
            return false
        }
        var offset = 2
        var inEntropy = false
        var sawScan = false
        while offset < bytes.count {
            if inEntropy {
                guard let markerOffset = bytes[offset...].firstIndex(of: 0xff) else {
                    return false
                }
                offset = markerOffset
            }
            guard bytes[offset] == 0xff else {
                return false
            }
            while offset < bytes.count, bytes[offset] == 0xff {
                offset += 1
            }
            guard offset < bytes.count else {
                return false
            }
            let marker = bytes[offset]
            offset += 1

            if inEntropy, marker == 0x00 {
                continue
            }
            if marker >= 0xd0 && marker <= 0xd7 {
                guard inEntropy else {
                    return false
                }
                continue
            }
            if marker == 0xd9 {
                return sawScan && offset == bytes.count
            }
            if marker == 0xd8 || marker == 0x01 {
                return false
            }
            inEntropy = false
            guard
                offset <= bytes.count - 2,
                let segmentLength = readBE16(bytes, at: offset).flatMap(Int.init(exactly:)),
                segmentLength >= 2,
                offset <= bytes.count - segmentLength
            else {
                return false
            }
            offset += segmentLength
            if marker == 0xda {
                sawScan = true
                inEntropy = true
            }
        }
        return false
    }

    private static func validateHEIF(_ bytes: [UInt8]) -> Bool {
        guard let boxes = parseBoxes(bytes, range: 0..<bytes.count), !boxes.isEmpty else {
            return false
        }
        guard boxes[0].type == "ftyp", boxes.filter({ $0.type == "ftyp" }).count == 1 else {
            return false
        }
        let ftyp = boxes[0]
        guard ftyp.payload.count >= 8, ftyp.payload.count % 4 == 0 else {
            return false
        }
        var brands: Set<String> = []
        if let major = ascii(bytes, range: ftyp.payload.lowerBound..<(ftyp.payload.lowerBound + 4)) {
            brands.insert(major)
        }
        var brandOffset = ftyp.payload.lowerBound + 8
        while brandOffset < ftyp.payload.upperBound {
            guard let brand = ascii(bytes, range: brandOffset..<(brandOffset + 4)) else {
                return false
            }
            brands.insert(brand)
            brandOffset += 4
        }
        guard !brands.isDisjoint(with: heifBrands) else {
            return false
        }
        guard
            boxes.filter({ $0.type == "meta" }).count == 1,
            boxes.contains(where: { $0.type == "mdat" }),
            let meta = boxes.first(where: { $0.type == "meta" }),
            meta.payload.count >= 4
        else {
            return false
        }
        let childRange = (meta.payload.lowerBound + 4)..<meta.payload.upperBound
        guard let children = parseBoxes(bytes, range: childRange) else {
            return false
        }
        guard
            children.filter({ $0.type == "pitm" }).count == 1,
            children.contains(where: { $0.type == "iloc" }),
            children.contains(where: { $0.type == "iinf" }),
            let primary = children.first(where: { $0.type == "pitm" })
        else {
            return false
        }
        let primaryBytes = primary.payload
        guard primaryBytes.count == 6 || primaryBytes.count == 8 else {
            return false
        }
        let version = bytes[primaryBytes.lowerBound]
        guard (version == 0 && primaryBytes.count == 6)
            || (version == 1 && primaryBytes.count == 8)
        else {
            return false
        }
        return bytes[(primaryBytes.lowerBound + 1)..<(primaryBytes.lowerBound + 4)]
            .allSatisfy { $0 == 0 }
    }

    private struct Box {
        let type: String
        let payload: Range<Int>
    }

    private static func parseBoxes(_ bytes: [UInt8], range: Range<Int>) -> [Box]? {
        var boxes: [Box] = []
        var offset = range.lowerBound
        while offset < range.upperBound {
            guard
                offset <= range.upperBound - 8,
                let shortSize = readBE32(bytes, at: offset),
                let type = ascii(bytes, range: (offset + 4)..<(offset + 8))
            else {
                return nil
            }
            var headerSize = 8
            let boxSize: UInt64
            if shortSize == 1 {
                guard
                    offset <= range.upperBound - 16,
                    let longSize = readBE64(bytes, at: offset + 8)
                else {
                    return nil
                }
                headerSize = 16
                boxSize = longSize
            } else {
                guard shortSize != 0 else {
                    return nil
                }
                boxSize = UInt64(shortSize)
            }
            guard
                boxSize >= UInt64(headerSize),
                let size = Int(exactly: boxSize),
                offset <= range.upperBound - size
            else {
                return nil
            }
            let end = offset + size
            boxes.append(
                Box(type: type, payload: (offset + headerSize)..<end)
            )
            offset = end
        }
        return offset == range.upperBound ? boxes : nil
    }

    private static func isHEIFSignature(_ bytes: [UInt8]) -> Bool {
        guard
            bytes.count >= 16,
            let size = readBE32(bytes, at: 0),
            size >= 16,
            ascii(bytes, range: 4..<8) == "ftyp"
        else {
            return false
        }
        let major = ascii(bytes, range: 8..<12)
        if let major, heifBrands.contains(major) {
            return true
        }
        let ftypEnd = min(Int(size), bytes.count)
        guard ftypEnd >= 16 else {
            return false
        }
        var offset = 16
        while offset <= ftypEnd - 4 {
            if let brand = ascii(bytes, range: offset..<(offset + 4)),
               heifBrands.contains(brand)
            {
                return true
            }
            offset += 4
        }
        return false
    }

    private static func ascii(_ bytes: [UInt8], range: Range<Int>) -> String? {
        guard
            range.lowerBound >= 0,
            range.upperBound <= bytes.count,
            range.allSatisfy({ bytes[$0] >= 0x20 && bytes[$0] <= 0x7e })
        else {
            return nil
        }
        return String(bytes: bytes[range], encoding: .ascii)
    }

    private static func readBE16(_ bytes: [UInt8], at offset: Int) -> UInt16? {
        guard offset >= 0, offset <= bytes.count - 2 else {
            return nil
        }
        return (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
    }

    private static func readBE32(_ bytes: [UInt8], at offset: Int) -> UInt32? {
        guard offset >= 0, offset <= bytes.count - 4 else {
            return nil
        }
        return (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }

    private static func readBE64(_ bytes: [UInt8], at offset: Int) -> UInt64? {
        guard
            let high = readBE32(bytes, at: offset),
            let low = readBE32(bytes, at: offset + 4)
        else {
            return nil
        }
        return (UInt64(high) << 32) | UInt64(low)
    }

    private static func crc32(_ bytes: [UInt8], range: Range<Int>) -> UInt32 {
        var crc = UInt32.max
        for index in range {
            crc ^= UInt32(bytes[index])
            for _ in 0..<8 {
                let mask = UInt32(bitPattern: -Int32(crc & 1))
                crc = (crc >> 1) ^ (0xedb8_8320 & mask)
            }
        }
        return ~crc
    }
}

enum ImageValidator {
    private static let maximumBytes = 40 * 1_024 * 1_024
    private static let maximumDimension = 16_384
    private static let maximumPixels = 64_000_000
    private static let allowedUTIs: [String: ImageContainer] = [
        "public.png": .png,
        "public.jpeg": .jpeg,
        "public.heic": .heif,
        "public.heif": .heif,
    ]

    static func validate(
        duplicatedReadOnlyFD: Int32,
        uti: UnsafePointer<UInt8>?,
        utiLength: Int,
        outWidth: UnsafeMutablePointer<UInt32>?,
        outHeight: UnsafeMutablePointer<UInt32>?,
        outFrameCount: UnsafeMutablePointer<UInt32>?
    ) -> ABIStatus {
        defer {
            if duplicatedReadOnlyFD >= 0 {
                close(duplicatedReadOnlyFD)
            }
        }
        guard
            duplicatedReadOnlyFD >= 0,
            let uti,
            utiLength > 0,
            utiLength <= 128,
            let outWidth,
            let outHeight,
            let outFrameCount
        else {
            return .invalid
        }
        let utiData = Data(bytes: uti, count: utiLength)
        guard
            let suppliedUTI = String(data: utiData, encoding: .utf8),
            suppliedUTI.utf8.count == utiLength,
            let expectedContainer = allowedUTIs[suppliedUTI]
        else {
            return .invalid
        }
        let flags = fcntl(duplicatedReadOnlyFD, F_GETFL)
        guard flags >= 0, flags & O_ACCMODE == O_RDONLY else {
            return .invalid
        }
        var before = stat()
        guard
            fstat(duplicatedReadOnlyFD, &before) == 0,
            before.st_mode & S_IFMT == S_IFREG,
            before.st_size > 0,
            before.st_size <= off_t(maximumBytes),
            let byteCount = Int(exactly: before.st_size),
            let data = readExactly(
                fd: duplicatedReadOnlyFD,
                byteCount: byteCount
            )
        else {
            return .invalid
        }
        var after = stat()
        guard
            fstat(duplicatedReadOnlyFD, &after) == 0,
            before.st_dev == after.st_dev,
            before.st_ino == after.st_ino,
            before.st_size == after.st_size,
            ImageFraming.validate(data) == expectedContainer
        else {
            return .invalid
        }

        var result: (UInt32, UInt32, UInt32)?
        let contained = wk_photokit_objc_perform {
            result = inspectWithImageIO(
                data: data,
                suppliedUTI: suppliedUTI,
                expectedContainer: expectedContainer
            )
        }
        guard contained, let result else {
            return .invalid
        }
        outWidth.pointee = result.0
        outHeight.pointee = result.1
        outFrameCount.pointee = result.2
        return .ok
    }

    private static func readExactly(fd: Int32, byteCount: Int) -> Data? {
        var data = Data(count: byteCount)
        let completed = data.withUnsafeMutableBytes { destination -> Bool in
            guard let base = destination.baseAddress else {
                return false
            }
            var offset = 0
            while offset < byteCount {
                let readCount = pread(
                    fd,
                    base.advanced(by: offset),
                    byteCount - offset,
                    off_t(offset)
                )
                if readCount < 0 {
                    if errno == EINTR {
                        continue
                    }
                    return false
                }
                guard readCount > 0 else {
                    return false
                }
                offset += readCount
            }
            var trailing: UInt8 = 0
            return pread(fd, &trailing, 1, off_t(byteCount)) == 0
        }
        return completed ? data : nil
    }

    private static func inspectWithImageIO(
        data: Data,
        suppliedUTI: String,
        expectedContainer: ImageContainer
    ) -> (UInt32, UInt32, UInt32)? {
        guard
            let source = CGImageSourceCreateWithData(data as CFData, nil),
            CGImageSourceGetCount(source) == 1,
            let sourceType = CGImageSourceGetType(source) as String?,
            sourceTypeMatches(
                sourceType,
                suppliedUTI: suppliedUTI,
                expectedContainer: expectedContainer
            ),
            let properties = CGImageSourceCopyPropertiesAtIndex(
                source,
                0,
                nil
            ) as? [CFString: Any],
            let width = exactPositiveInt(properties[kCGImagePropertyPixelWidth]),
            let height = exactPositiveInt(properties[kCGImagePropertyPixelHeight]),
            width <= maximumDimension,
            height <= maximumDimension,
            width <= maximumPixels / height
        else {
            return nil
        }
        let options: [CFString: Any] = [
            kCGImageSourceShouldCache: true,
            kCGImageSourceShouldCacheImmediately: true,
        ]
        guard
            let image = CGImageSourceCreateImageAtIndex(
                source,
                0,
                options as CFDictionary
            ),
            image.width > 0,
            image.height > 0,
            image.width <= maximumDimension,
            image.height <= maximumDimension,
            image.width <= maximumPixels / image.height,
            let outputWidth = UInt32(exactly: width),
            let outputHeight = UInt32(exactly: height)
        else {
            return nil
        }
        return (outputWidth, outputHeight, 1)
    }

    private static func sourceTypeMatches(
        _ sourceType: String,
        suppliedUTI: String,
        expectedContainer: ImageContainer
    ) -> Bool {
        guard let actual = UTType(sourceType) else {
            return false
        }
        switch expectedContainer {
        case .png:
            return suppliedUTI == "public.png" && actual.conforms(to: .png)
        case .jpeg:
            return suppliedUTI == "public.jpeg" && actual.conforms(to: .jpeg)
        case .heif:
            let heif = UTType("public.heif")
            return (actual.conforms(to: .heic) || heif.map(actual.conforms(to:)) == true)
                && (suppliedUTI == "public.heic" || suppliedUTI == "public.heif")
        }
    }

    private static func exactPositiveInt(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber else {
            return nil
        }
        let double = number.doubleValue
        guard
            double.isFinite,
            double > 0,
            double.rounded(.towardZero) == double,
            let integer = Int(exactly: double)
        else {
            return nil
        }
        return integer
    }
}
