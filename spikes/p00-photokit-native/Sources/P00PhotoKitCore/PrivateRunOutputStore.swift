import CryptoKit
import Darwin
import Foundation
import ImageIO

public struct ImageDimensions: Equatable, Sendable {
    public let width: Int
    public let height: Int

    public init(width: Int, height: Int) {
        self.width = width
        self.height = height
    }
}

public struct MaterializedArtifact: Equatable, Sendable {
    public let sha256: String
    public let length: Int64
    public let dimensions: ImageDimensions
    public let outputName: String
    public let provenanceName: String
}

public enum ContentStoreError: Error, Equatable {
    case runAlreadyExists
    case invalidRunDirectory
    case invalidComponent
    case rootChanged
    case exclusiveCreate
    case insufficientSpace
    case resourceLimit
    case sinkLimit
    case write
    case synchronize
    case lengthMismatch
    case hashMismatch
    case invalidImage
    case dimensionMismatch
    case frameLimit
    case pixelLimit
    case allocationLimit
    case descriptorMismatch
    case provenance
}

private struct FileIdentity: Equatable {
    let device: dev_t
    let inode: ino_t
}

public final class PrivateRunOutputStore: @unchecked Sendable {
    public typealias CapacityProvider = (Int32) -> UInt64?

    public static let frameLimit = 1
    public static let pixelLimit = 200_000_000
    public static let decodeAllocationLimit: Int64 = 800_000_000
    public static let maximumDecodedBytesPerPixel: Int64 = 8
    public static let reserveFreeBytes: UInt64 = 2 * 1_024 * 1_024 * 1_024
    public static let maximumSinksPerRun = 4
    public static let maximumProvenanceBytes = 64 * 1_024

    public let runDirectory: URL

    private let rootDescriptor: Int32
    private let rootIdentity: FileIdentity
    private let capacityProvider: CapacityProvider
    private let sinkCountLock = NSLock()
    private var sinkCount = 0

    public convenience init(createFreshRunDirectory runDirectory: URL) throws {
        try self.init(
            createFreshRunDirectory: runDirectory,
            capacityProvider: Self.availableCapacity
        )
    }

    init(
        createFreshRunDirectory runDirectory: URL,
        capacityProvider: @escaping CapacityProvider
    ) throws {
        self.runDirectory = runDirectory.standardizedFileURL
        self.capacityProvider = capacityProvider
        guard mkdir(self.runDirectory.path, 0o700) == 0 else {
            if errno == EEXIST {
                throw ContentStoreError.runAlreadyExists
            }
            throw ContentStoreError.invalidRunDirectory
        }
        let descriptor = self.runDirectory.path.withCString {
            open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw ContentStoreError.invalidRunDirectory
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              Self.isPrivateDirectory(metadata) else {
            close(descriptor)
            throw ContentStoreError.invalidRunDirectory
        }
        rootDescriptor = descriptor
        rootIdentity = FileIdentity(device: metadata.st_dev, inode: metadata.st_ino)
    }

    deinit {
        close(rootDescriptor)
    }

    public func makeSink(outputName: String) throws -> StreamingImageSink {
        try Self.validateComponent(outputName)
        try verifyRoot()
        try requireCapacity(
            descriptor: rootDescriptor,
            requiredBytes: Self.reserveFreeBytes
                + UInt64(TransferStateMachine.maximumResourceBytes)
        )
        sinkCountLock.lock()
        guard sinkCount < Self.maximumSinksPerRun else {
            sinkCountLock.unlock()
            throw ContentStoreError.sinkLimit
        }
        sinkCount += 1
        sinkCountLock.unlock()
        let duplicate = fcntl(rootDescriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0 else {
            throw ContentStoreError.invalidRunDirectory
        }
        do {
            return try StreamingImageSink(
                rootDescriptor: duplicate,
                rootIdentity: rootIdentity,
                capacityProvider: capacityProvider,
                outputName: outputName
            )
        } catch {
            close(duplicate)
            throw error
        }
    }

    private func verifyRoot() throws {
        try Self.verifyRoot(descriptor: rootDescriptor, identity: rootIdentity)
    }

    private func requireCapacity(descriptor: Int32, requiredBytes: UInt64) throws {
        guard let available = capacityProvider(descriptor),
              available >= requiredBytes else {
            throw ContentStoreError.insufficientSpace
        }
    }

    private static func availableCapacity(descriptor: Int32) -> UInt64? {
        var status = statvfs()
        guard fstatvfs(descriptor, &status) == 0 else {
            return nil
        }
        let (bytes, overflow) = UInt64(status.f_bavail)
            .multipliedReportingOverflow(by: UInt64(status.f_frsize))
        return overflow ? nil : bytes
    }

    fileprivate static func verifyRoot(
        descriptor: Int32,
        identity: FileIdentity
    ) throws {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              isPrivateDirectory(metadata),
              FileIdentity(device: metadata.st_dev, inode: metadata.st_ino) == identity else {
            throw ContentStoreError.rootChanged
        }
    }

    private static func isPrivateDirectory(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFDIR
            && (metadata.st_mode & 0o777) == 0o700
    }

    fileprivate static func validateComponent(_ value: String) throws {
        guard !value.isEmpty,
              value.utf8.count <= 255,
              value != ".",
              value != "..",
              !value.contains("/"),
              !value.utf8.contains(0) else {
            throw ContentStoreError.invalidComponent
        }
    }
}

public final class StreamingImageSink: @unchecked Sendable {
    private let rootDescriptor: Int32
    private let rootIdentity: FileIdentity
    private let capacityProvider: PrivateRunOutputStore.CapacityProvider
    private let outputName: String
    private var descriptor: Int32 = -1
    private var outputIdentity: FileIdentity?
    private var hasher = SHA256()
    private var finalized = false
    public private(set) var byteCount: Int64 = 0

    fileprivate init(
        rootDescriptor: Int32,
        rootIdentity: FileIdentity,
        capacityProvider: @escaping PrivateRunOutputStore.CapacityProvider,
        outputName: String
    ) throws {
        self.rootDescriptor = rootDescriptor
        self.rootIdentity = rootIdentity
        self.capacityProvider = capacityProvider
        self.outputName = outputName
    }

    deinit {
        if descriptor >= 0 {
            close(descriptor)
            descriptor = -1
        }
        close(rootDescriptor)
    }

    public func append(_ data: Data) throws {
        guard !finalized else {
            throw ContentStoreError.write
        }
        guard !data.isEmpty else {
            return
        }
        guard Int64(data.count) <= TransferStateMachine.maximumResourceBytes - byteCount else {
            throw ContentStoreError.resourceLimit
        }
        try PrivateRunOutputStore.verifyRoot(
            descriptor: rootDescriptor,
            identity: rootIdentity
        )
        let remainingAllowance = UInt64(
            TransferStateMachine.maximumResourceBytes - byteCount
        )
        let required = PrivateRunOutputStore.reserveFreeBytes + remainingAllowance
        guard let available = capacityProvider(rootDescriptor),
              available >= required else {
            throw ContentStoreError.insufficientSpace
        }
        try createOutputIfNeeded()
        try verifyContinuity()
        let wroteAll = data.withUnsafeBytes { buffer -> Bool in
            guard let base = buffer.baseAddress else { return true }
            var offset = 0
            while offset < buffer.count {
                let result = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    buffer.count - offset
                )
                if result < 0 {
                    if errno == EINTR {
                        continue
                    }
                    return false
                }
                guard result > 0 else {
                    return false
                }
                offset += result
            }
            return true
        }
        guard wroteAll else {
            throw ContentStoreError.write
        }
        hasher.update(data: data)
        byteCount += Int64(data.count)
    }

    public func finalize(
        expected: FixtureExpectation,
        expectedLength: Int64,
        expectedDimensions: ImageDimensions,
        provenanceName: String,
        provenance: ProvenanceRecord
    ) throws -> MaterializedArtifact {
        guard !finalized, descriptor >= 0 else {
            throw ContentStoreError.write
        }
        finalized = true
        try PrivateRunOutputStore.validateComponent(provenanceName)
        guard outputName != provenanceName else {
            throw ContentStoreError.invalidComponent
        }
        guard byteCount == expectedLength else {
            throw ContentStoreError.lengthMismatch
        }
        try verifyContinuity()
        guard fsync(descriptor) == 0 else {
            throw ContentStoreError.synchronize
        }
        let dimensions = try Self.verifyImage(
            descriptor: descriptor,
            expectedDimensions: expectedDimensions
        )
        let descriptorHash = try Self.sha256(descriptor: descriptor)
        let streamedHash = Self.encodeDigest(hasher.finalize())
        guard streamedHash == expected.sha256 else {
            throw ContentStoreError.hashMismatch
        }
        guard descriptorHash == streamedHash else {
            throw ContentStoreError.descriptorMismatch
        }
        try verifyContinuity()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let provenanceData: Data
        do {
            provenanceData = try encoder.encode(provenance)
        } catch {
            throw ContentStoreError.provenance
        }
        let provenanceFile = try writeProvenance(
            data: provenanceData,
            destinationName: provenanceName
        )
        defer {
            close(provenanceFile.descriptor)
        }
        guard fsync(rootDescriptor) == 0 else {
            throw ContentStoreError.synchronize
        }
        try verifyContinuity()
        try Self.verifyProvenance(
            provenanceFile,
            rootDescriptor: rootDescriptor,
            destinationName: provenanceName,
            expectedData: provenanceData
        )
        close(descriptor)
        descriptor = -1

        return MaterializedArtifact(
            sha256: streamedHash,
            length: byteCount,
            dimensions: dimensions,
            outputName: outputName,
            provenanceName: provenanceName
        )
    }

    public func discard() {
        if descriptor >= 0 {
            close(descriptor)
            descriptor = -1
        }
        finalized = true
    }

    private func writeProvenance(
        data: Data,
        destinationName: String
    ) throws -> OpenFile {
        try PrivateRunOutputStore.verifyRoot(
            descriptor: rootDescriptor,
            identity: rootIdentity
        )
        guard data.count <= PrivateRunOutputStore.maximumProvenanceBytes else {
            throw ContentStoreError.provenance
        }
        let required = PrivateRunOutputStore.reserveFreeBytes + UInt64(data.count)
        guard let available = capacityProvider(rootDescriptor),
              available >= required else {
            throw ContentStoreError.insufficientSpace
        }
        let provenanceDescriptor = destinationName.withCString {
            openat(
                rootDescriptor,
                $0,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600
            )
        }
        guard provenanceDescriptor >= 0 else {
            throw ContentStoreError.provenance
        }
        var metadata = stat()
        guard fstat(provenanceDescriptor, &metadata) == 0 else {
            close(provenanceDescriptor)
            throw ContentStoreError.provenance
        }
        let provenanceIdentity = FileIdentity(
            device: metadata.st_dev,
            inode: metadata.st_ino
        )
        guard Self.isPrivateRegularFile(metadata),
              metadata.st_dev == rootIdentity.device else {
            close(provenanceDescriptor)
            throw ContentStoreError.provenance
        }
        guard Self.writeAll(data, descriptor: provenanceDescriptor),
              fsync(provenanceDescriptor) == 0 else {
            close(provenanceDescriptor)
            throw ContentStoreError.provenance
        }
        do {
            try PrivateRunOutputStore.verifyRoot(
                descriptor: rootDescriptor,
                identity: rootIdentity
            )
        } catch {
            close(provenanceDescriptor)
            throw error
        }
        return OpenFile(
            descriptor: provenanceDescriptor,
            identity: provenanceIdentity
        )
    }

    private func verifyContinuity() throws {
        try PrivateRunOutputStore.verifyRoot(
            descriptor: rootDescriptor,
            identity: rootIdentity
        )
        var metadata = stat()
        guard descriptor >= 0,
              let outputIdentity,
              fstat(descriptor, &metadata) == 0,
              Self.isPrivateRegularFile(metadata),
              FileIdentity(device: metadata.st_dev, inode: metadata.st_ino)
                == outputIdentity,
              metadata.st_dev == rootIdentity.device,
              metadata.st_size == byteCount else {
            throw ContentStoreError.descriptorMismatch
        }
        guard Self.pathIdentity(
            rootDescriptor: rootDescriptor,
            name: outputName
        ) == outputIdentity else {
            throw ContentStoreError.descriptorMismatch
        }
    }

    private func createOutputIfNeeded() throws {
        guard descriptor < 0 else {
            return
        }
        descriptor = outputName.withCString {
            openat(
                rootDescriptor,
                $0,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600
            )
        }
        guard descriptor >= 0 else {
            throw ContentStoreError.exclusiveCreate
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              Self.isPrivateRegularFile(metadata),
              metadata.st_dev == rootIdentity.device else {
            close(descriptor)
            descriptor = -1
            throw ContentStoreError.exclusiveCreate
        }
        outputIdentity = FileIdentity(device: metadata.st_dev, inode: metadata.st_ino)
    }

    private static func verifyImage(
        descriptor: Int32,
        expectedDimensions: ImageDimensions
    ) throws -> ImageDimensions {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_size > 0,
              metadata.st_size <= TransferStateMachine.maximumResourceBytes,
              metadata.st_size <= Int64(Int.max) else {
            throw ContentStoreError.invalidImage
        }
        let size = Int(metadata.st_size)
        guard let mapping = mmap(nil, size, PROT_READ, MAP_PRIVATE, descriptor, 0),
              mapping != MAP_FAILED else {
            throw ContentStoreError.invalidImage
        }
        guard let provider = CGDataProvider(
            dataInfo: nil,
            data: UnsafeRawPointer(mapping),
            size: size,
            releaseData: { _, data, size in
                _ = munmap(UnsafeMutableRawPointer(mutating: data), size)
            }
        ) else {
            _ = munmap(mapping, size)
            throw ContentStoreError.invalidImage
        }
        let sourceOptions = [
            kCGImageSourceShouldCache: false,
        ] as CFDictionary
        guard let source = CGImageSourceCreateWithDataProvider(provider, sourceOptions) else {
            throw ContentStoreError.invalidImage
        }
        guard CGImageSourceGetCount(source) == PrivateRunOutputStore.frameLimit else {
            throw ContentStoreError.frameLimit
        }
        guard let properties = CGImageSourceCopyPropertiesAtIndex(
            source,
            0,
            sourceOptions
        ) as? [CFString: Any],
            let width = positiveInteger(properties[kCGImagePropertyPixelWidth]),
            let height = positiveInteger(properties[kCGImagePropertyPixelHeight]) else {
            throw ContentStoreError.invalidImage
        }
        let metadataDimensions = ImageDimensions(width: width, height: height)
        try validateMetadataDimensions(
            metadataDimensions,
            expectedDimensions: expectedDimensions
        )

        let decodeOptions = [
            kCGImageSourceShouldCache: true,
            kCGImageSourceShouldCacheImmediately: true,
        ] as CFDictionary
        guard let image = CGImageSourceCreateImageAtIndex(source, 0, decodeOptions) else {
            throw ContentStoreError.invalidImage
        }
        let decodedDimensions = ImageDimensions(width: image.width, height: image.height)
        guard decodedDimensions == metadataDimensions,
              decodedDimensions == expectedDimensions else {
            throw ContentStoreError.dimensionMismatch
        }
        guard image.bytesPerRow > 0,
              image.height <= Int.max / image.bytesPerRow,
              Int64(image.bytesPerRow * image.height)
                <= PrivateRunOutputStore.decodeAllocationLimit else {
            throw ContentStoreError.allocationLimit
        }
        return decodedDimensions
    }

    static func validateMetadataDimensions(
        _ dimensions: ImageDimensions,
        expectedDimensions: ImageDimensions
    ) throws {
        guard dimensions.width > 0, dimensions.height > 0,
              dimensions.width <= PrivateRunOutputStore.pixelLimit / dimensions.height else {
            throw ContentStoreError.pixelLimit
        }
        let pixels = Int64(dimensions.width) * Int64(dimensions.height)
        guard pixels <= PrivateRunOutputStore.decodeAllocationLimit
            / PrivateRunOutputStore.maximumDecodedBytesPerPixel else {
            throw ContentStoreError.allocationLimit
        }
        guard dimensions == expectedDimensions else {
            throw ContentStoreError.dimensionMismatch
        }
    }

    private static func positiveInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber else {
            return nil
        }
        let integer = number.int64Value
        guard integer > 0, integer <= Int64(Int.max) else {
            return nil
        }
        return Int(integer)
    }

    private static func pathIdentity(
        rootDescriptor: Int32,
        name: String
    ) -> FileIdentity? {
        var metadata = stat()
        let result = name.withCString {
            fstatat(rootDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }
        guard result == 0, (metadata.st_mode & S_IFMT) == S_IFREG else {
            return nil
        }
        return FileIdentity(device: metadata.st_dev, inode: metadata.st_ino)
    }

    private static func verifyProvenance(
        _ file: OpenFile,
        rootDescriptor: Int32,
        destinationName: String,
        expectedData: Data
    ) throws {
        guard try read(
            descriptor: file.descriptor,
            maximumBytes: PrivateRunOutputStore.maximumProvenanceBytes
        ) == expectedData,
            pathIdentity(
                rootDescriptor: rootDescriptor,
                name: destinationName
            ) == file.identity else {
            throw ContentStoreError.provenance
        }
    }

    private static func isPrivateRegularFile(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFREG
            && (metadata.st_mode & 0o777) == 0o600
            && metadata.st_nlink == 1
    }

    private static func sha256(descriptor: Int32) throws -> String {
        var digest = SHA256()
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: TransferStateMachine.maximumChunkBytes)
        while true {
            let count = pread(descriptor, &buffer, buffer.count, offset)
            if count < 0 {
                if errno == EINTR {
                    continue
                }
                throw ContentStoreError.descriptorMismatch
            }
            if count == 0 {
                break
            }
            digest.update(data: Data(buffer[0..<count]))
            offset += off_t(count)
        }
        return encodeDigest(digest.finalize())
    }

    private static func read(descriptor: Int32, maximumBytes: Int) throws -> Data {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              isPrivateRegularFile(metadata),
              metadata.st_size >= 0,
              metadata.st_size <= maximumBytes else {
            throw ContentStoreError.descriptorMismatch
        }
        var data = Data(count: Int(metadata.st_size))
        let succeeded = data.withUnsafeMutableBytes { buffer -> Bool in
            guard let base = buffer.baseAddress else { return true }
            var offset = 0
            while offset < buffer.count {
                let count = pread(
                    descriptor,
                    base.advanced(by: offset),
                    buffer.count - offset,
                    off_t(offset)
                )
                if count < 0 {
                    if errno == EINTR {
                        continue
                    }
                    return false
                }
                guard count > 0 else {
                    return false
                }
                offset += count
            }
            return true
        }
        guard succeeded else {
            throw ContentStoreError.descriptorMismatch
        }
        return data
    }

    private static func writeAll(_ data: Data, descriptor: Int32) -> Bool {
        data.withUnsafeBytes { buffer -> Bool in
            guard let base = buffer.baseAddress else { return true }
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    buffer.count - offset
                )
                if count < 0 {
                    if errno == EINTR {
                        continue
                    }
                    return false
                }
                guard count > 0 else {
                    return false
                }
                offset += count
            }
            return true
        }
    }

    private static func encodeDigest<D: Sequence>(_ digest: D) -> String
    where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}

private struct OpenFile {
    let descriptor: Int32
    let identity: FileIdentity
}
