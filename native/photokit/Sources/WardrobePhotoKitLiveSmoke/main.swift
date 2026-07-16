import CryptoKit
import Darwin
import Foundation
import WardrobePhotoKitObjC

private let usageDescription =
    "Wardrobe uses your Photos library to let you select an album and import its original images into your private local wardrobe."

private enum SmokeFailure: Error {
    case failed
}

private struct AppIdentity: Codable, Equatable {
    let bundleSHA256: String
    let executableSHA256: String
    let infoPlistSHA256: String
    let designatedRequirementSHA256: String
    let sourceTreeSHA256: String
}

private struct BeforeSnapshot: Codable {
    let schemaVersion: Int
    let packageExecutableSHA256: String
    let nativeCallbacks: Bool
    let authorization: String
    let setupComplete: Bool
    let completeGeneration: UInt64
    let photokitRevision: UInt64
    let availableCount: Int
    let unavailableCount: Int
    let materializedSHA256: [String]
    let decisionSeeded: Bool

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case packageExecutableSHA256 = "package_executable_sha256"
        case nativeCallbacks = "native_callbacks"
        case authorization
        case setupComplete = "setup_complete"
        case completeGeneration = "complete_generation"
        case photokitRevision = "photokit_revision"
        case availableCount = "available_count"
        case unavailableCount = "unavailable_count"
        case materializedSHA256 = "materialized_sha256"
        case decisionSeeded = "decision_seeded"
    }
}

private struct AfterSnapshot: Codable {
    let schemaVersion: Int
    let packageExecutableSHA256: String
    let nativeCallbacks: Bool
    let authorization: String
    let startupTrigger: Bool
    let completeGeneration: UInt64
    let photokitRevision: UInt64
    let availableCount: Int
    let unavailableCount: Int
    let missingReason: String
    let retainedBlobSHA256: [String]
    let decisionPreserved: Bool

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case packageExecutableSHA256 = "package_executable_sha256"
        case nativeCallbacks = "native_callbacks"
        case authorization
        case startupTrigger = "startup_trigger"
        case completeGeneration = "complete_generation"
        case photokitRevision = "photokit_revision"
        case availableCount = "available_count"
        case unavailableCount = "unavailable_count"
        case missingReason = "missing_reason"
        case retainedBlobSHA256 = "retained_blob_sha256"
        case decisionPreserved = "decision_preserved"
    }
}

private struct Checkpoint: Codable {
    let schemaVersion: Int
    let nonceSHA256: String
    let identity: AppIdentity
    let fixtureSHA256: [String]
    let completeGeneration: UInt64
    let photokitRevision: UInt64

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case nonceSHA256 = "nonce_sha256"
        case identity
        case fixtureSHA256 = "fixture_sha256"
        case completeGeneration = "complete_generation"
        case photokitRevision = "photokit_revision"
    }
}

private struct Evidence: Codable {
    let schemaVersion = 1
    let stage: String
    let nonceSHA256: String
    let bundleSHA256: String
    let executableSHA256: String
    let infoPlistSHA256: String
    let designatedRequirementSHA256: String
    let sourceTreeSHA256: String
    let fixtureSHA256: [String]
    let initialGeneration: UInt64?
    let finalGeneration: UInt64?
    let initialRevision: UInt64?
    let finalRevision: UInt64?
    let initialAvailableCount: Int?
    let finalAvailableCount: Int?
    let finalUnavailableCount: Int?
    let nativeCallbacks: Bool
    let startupTransition: Bool
    let blobsRetained: Bool
    let decisionPreserved: Bool

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case stage
        case nonceSHA256 = "nonce_sha256"
        case bundleSHA256 = "bundle_sha256"
        case executableSHA256 = "executable_sha256"
        case infoPlistSHA256 = "info_plist_sha256"
        case designatedRequirementSHA256 = "designated_requirement_sha256"
        case sourceTreeSHA256 = "source_tree_sha256"
        case fixtureSHA256 = "fixture_sha256"
        case initialGeneration = "initial_generation"
        case finalGeneration = "final_generation"
        case initialRevision = "initial_revision"
        case finalRevision = "final_revision"
        case initialAvailableCount = "initial_available_count"
        case finalAvailableCount = "final_available_count"
        case finalUnavailableCount = "final_unavailable_count"
        case nativeCallbacks = "native_callbacks"
        case startupTransition = "startup_transition"
        case blobsRetained = "blobs_retained"
        case decisionPreserved = "decision_preserved"
    }
}

private struct Arguments {
    let stage: String
    let app: URL
    let sourceRoot: URL
    let state: URL
    let snapshot: URL
    let fixtures: [URL]
    let nonce: String?

    static func parse() throws -> Arguments {
        let values = Array(CommandLine.arguments.dropFirst())
        guard values.first == "prepare" || values.first == "verify" else {
            throw SmokeFailure.failed
        }
        let stage = values[0]
        var options: [String: [String]] = [:]
        var index = 1
        while index < values.count {
            let key = values[index]
            guard key.hasPrefix("--"), index + 1 < values.count else {
                throw SmokeFailure.failed
            }
            options[key, default: []].append(values[index + 1])
            index += 2
        }
        let permitted: Set<String> = [
            "--app", "--source-root", "--state", "--snapshot", "--fixture", "--nonce",
        ]
        guard Set(options.keys).isSubset(of: permitted) else {
            throw SmokeFailure.failed
        }
        func one(_ key: String) throws -> String {
            guard let entries = options[key], entries.count == 1 else {
                throw SmokeFailure.failed
            }
            return entries[0]
        }
        let fixtures = options["--fixture", default: []].map {
            URL(fileURLWithPath: $0)
        }
        if stage == "prepare" {
            guard fixtures.count == 2, options["--nonce"]?.count == 1 else {
                throw SmokeFailure.failed
            }
        } else {
            guard fixtures.isEmpty, options["--nonce"] == nil else {
                throw SmokeFailure.failed
            }
        }
        return Arguments(
            stage: stage,
            app: URL(fileURLWithPath: try one("--app")),
            sourceRoot: URL(fileURLWithPath: try one("--source-root")),
            state: URL(fileURLWithPath: try one("--state")),
            snapshot: URL(fileURLWithPath: try one("--snapshot")),
            fixtures: fixtures,
            nonce: options["--nonce"]?.first
        )
    }
}

private func main() throws {
    let arguments = try Arguments.parse()
    try productionABIPreflight()
    let identity = try inspectApp(
        arguments.app,
        sourceRoot: arguments.sourceRoot
    )
    try launchAndWait(arguments.app)

    if arguments.stage == "prepare" {
        try prepare(arguments, identity: identity)
    } else {
        try verify(arguments, identity: identity)
    }
}

private func prepare(_ arguments: Arguments, identity: AppIdentity) throws {
    guard
        !FileManager.default.fileExists(atPath: arguments.state.path),
        let nonce = arguments.nonce,
        nonce.utf8.count >= 32,
        nonce.utf8.count <= 256
    else {
        throw SmokeFailure.failed
    }
    let fixtureHashes = try arguments.fixtures.map(hashFile).sorted()
    guard Set(fixtureHashes).count == 2 else {
        throw SmokeFailure.failed
    }
    let snapshot: BeforeSnapshot = try decodeExact(
        arguments.snapshot,
        keys: [
            "schema_version", "package_executable_sha256", "native_callbacks",
            "authorization", "setup_complete", "complete_generation",
            "photokit_revision", "available_count", "unavailable_count",
            "materialized_sha256", "decision_seeded",
        ]
    )
    guard
        snapshot.schemaVersion == 1,
        snapshot.packageExecutableSHA256 == identity.executableSHA256,
        snapshot.nativeCallbacks,
        snapshot.authorization == "authorized",
        snapshot.setupComplete,
        snapshot.completeGeneration > 0,
        snapshot.photokitRevision > 0,
        snapshot.availableCount == 2,
        snapshot.unavailableCount == 0,
        snapshot.materializedSHA256.sorted() == fixtureHashes,
        snapshot.decisionSeeded
    else {
        throw SmokeFailure.failed
    }
    let nonceHash = hash(Data(nonce.utf8))
    let checkpoint = Checkpoint(
        schemaVersion: 1,
        nonceSHA256: nonceHash,
        identity: identity,
        fixtureSHA256: fixtureHashes,
        completeGeneration: snapshot.completeGeneration,
        photokitRevision: snapshot.photokitRevision
    )
    try writePrivate(checkpoint, to: arguments.state)
    try emit(
        Evidence(
            stage: "prepared",
            nonceSHA256: nonceHash,
            bundleSHA256: identity.bundleSHA256,
            executableSHA256: identity.executableSHA256,
            infoPlistSHA256: identity.infoPlistSHA256,
            designatedRequirementSHA256: identity.designatedRequirementSHA256,
            sourceTreeSHA256: identity.sourceTreeSHA256,
            fixtureSHA256: fixtureHashes,
            initialGeneration: snapshot.completeGeneration,
            finalGeneration: nil,
            initialRevision: snapshot.photokitRevision,
            finalRevision: nil,
            initialAvailableCount: 2,
            finalAvailableCount: nil,
            finalUnavailableCount: nil,
            nativeCallbacks: true,
            startupTransition: false,
            blobsRetained: true,
            decisionPreserved: true
        )
    )
}

private func verify(_ arguments: Arguments, identity: AppIdentity) throws {
    let checkpoint: Checkpoint = try decodeExact(
        arguments.state,
        keys: [
            "schema_version", "nonce_sha256", "identity", "fixture_sha256",
            "complete_generation", "photokit_revision",
        ]
    )
    guard
        checkpoint.schemaVersion == 1,
        checkpoint.identity == identity,
        checkpoint.fixtureSHA256.count == 2
    else {
        throw SmokeFailure.failed
    }
    let snapshot: AfterSnapshot = try decodeExact(
        arguments.snapshot,
        keys: [
            "schema_version", "package_executable_sha256", "native_callbacks",
            "authorization", "startup_trigger", "complete_generation",
            "photokit_revision", "available_count", "unavailable_count",
            "missing_reason", "retained_blob_sha256", "decision_preserved",
        ]
    )
    guard
        snapshot.schemaVersion == 1,
        snapshot.packageExecutableSHA256 == identity.executableSHA256,
        snapshot.nativeCallbacks,
        snapshot.authorization == "authorized",
        snapshot.startupTrigger,
        snapshot.completeGeneration > checkpoint.completeGeneration,
        snapshot.photokitRevision > checkpoint.photokitRevision,
        snapshot.availableCount == 1,
        snapshot.unavailableCount == 1,
        snapshot.missingReason == "asset_not_in_scope",
        snapshot.retainedBlobSHA256.sorted() == checkpoint.fixtureSHA256.sorted(),
        snapshot.decisionPreserved
    else {
        throw SmokeFailure.failed
    }
    try emit(
        Evidence(
            stage: "verified",
            nonceSHA256: checkpoint.nonceSHA256,
            bundleSHA256: identity.bundleSHA256,
            executableSHA256: identity.executableSHA256,
            infoPlistSHA256: identity.infoPlistSHA256,
            designatedRequirementSHA256: identity.designatedRequirementSHA256,
            sourceTreeSHA256: identity.sourceTreeSHA256,
            fixtureSHA256: checkpoint.fixtureSHA256,
            initialGeneration: checkpoint.completeGeneration,
            finalGeneration: snapshot.completeGeneration,
            initialRevision: checkpoint.photokitRevision,
            finalRevision: snapshot.photokitRevision,
            initialAvailableCount: 2,
            finalAvailableCount: 1,
            finalUnavailableCount: 1,
            nativeCallbacks: true,
            startupTransition: true,
            blobsRetained: true,
            decisionPreserved: true
        )
    )
}

private func productionABIPreflight() throws {
    var handle: OpaquePointer?
    guard
        wk_photokit_create_v1(UInt32(WK_PHOTOKIT_ABI_V1), &handle)
            == Int32(WK_PHOTOKIT_OK_V1.rawValue),
        handle != nil
    else {
        throw SmokeFailure.failed
    }
    let semaphore = DispatchSemaphore(value: 0)
    var status: Int32 = Int32(WK_PHOTOKIT_INTERNAL_V1.rawValue)
    let thread = Thread {
        status = wk_photokit_quiesce_v1(handle, 1_000)
        semaphore.signal()
    }
    thread.start()
    guard
        semaphore.wait(timeout: .now() + 2) == .success,
        status == Int32(WK_PHOTOKIT_OK_V1.rawValue),
        wk_photokit_destroy_v1(&handle) == Int32(WK_PHOTOKIT_OK_V1.rawValue),
        handle == nil
    else {
        throw SmokeFailure.failed
    }
}

private func inspectApp(_ app: URL, sourceRoot: URL) throws -> AppIdentity {
    let infoURL = app.appendingPathComponent("Contents/Info.plist")
    let infoData = try Data(contentsOf: infoURL)
    guard
        let plist = try PropertyListSerialization.propertyList(
            from: infoData,
            format: nil
        ) as? [String: Any],
        let executableName = plist["CFBundleExecutable"] as? String,
        !executableName.isEmpty,
        plist["NSPhotoLibraryUsageDescription"] as? String == usageDescription
    else {
        throw SmokeFailure.failed
    }
    let executable = app
        .appendingPathComponent("Contents/MacOS")
        .appendingPathComponent(executableName)
    let requirement = try processOutput(
        "/usr/bin/codesign",
        ["-d", "-r-", app.path],
        includeStandardError: true
    )
    guard requirement.contains("designated =>") else {
        throw SmokeFailure.failed
    }
    return AppIdentity(
        bundleSHA256: try hashTree(app),
        executableSHA256: try hashFile(executable),
        infoPlistSHA256: hash(infoData),
        designatedRequirementSHA256: hash(Data(requirement.utf8)),
        sourceTreeSHA256: try hashTree(sourceRoot, excludingBuildOutput: true)
    )
}

private func launchAndWait(_ app: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    process.arguments = ["-W", "-n", app.path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw SmokeFailure.failed
    }
}

private func decodeExact<T: Decodable>(
    _ url: URL,
    keys: Set<String>
) throws -> T {
    let data = try Data(contentsOf: url)
    guard
        data.count > 0,
        data.count <= 65_536,
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
        Set(object.keys) == keys
    else {
        throw SmokeFailure.failed
    }
    return try JSONDecoder().decode(T.self, from: data)
}

private func hashFile(_ url: URL) throws -> String {
    hash(try Data(contentsOf: url, options: [.mappedIfSafe]))
}

private func hashTree(
    _ root: URL,
    excludingBuildOutput: Bool = false
) throws -> String {
    let manager = FileManager.default
    guard
        let enumerator = manager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: []
        )
    else {
        throw SmokeFailure.failed
    }
    var files: [URL] = []
    for case let url as URL in enumerator {
        let relative = String(url.path.dropFirst(root.path.count + 1))
        if excludingBuildOutput,
           relative == ".build" || relative.hasPrefix(".build/")
        {
            enumerator.skipDescendants()
            continue
        }
        let values = try url.resourceValues(
            forKeys: [.isRegularFileKey, .isSymbolicLinkKey]
        )
        if values.isRegularFile == true || values.isSymbolicLink == true {
            files.append(url)
        }
    }
    files.sort { $0.path < $1.path }
    var digest = SHA256()
    for file in files {
        let relative = String(file.path.dropFirst(root.path.count + 1))
        digest.update(data: Data(relative.utf8))
        digest.update(data: Data([0]))
        let values = try file.resourceValues(forKeys: [.isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            digest.update(
                data: Data(
                    try manager.destinationOfSymbolicLink(atPath: file.path).utf8
                )
            )
        } else {
            digest.update(data: try Data(contentsOf: file, options: [.mappedIfSafe]))
        }
        digest.update(data: Data([0]))
    }
    return hex(Data(digest.finalize()))
}

private func hash(_ data: Data) -> String {
    hex(Data(SHA256.hash(data: data)))
}

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func processOutput(
    _ executable: String,
    _ arguments: [String],
    includeStandardError: Bool
) throws -> String {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = includeStandardError ? FileHandle.nullDevice : pipe
    process.standardError = includeStandardError ? pipe : FileHandle.nullDevice
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard
        process.terminationStatus == 0,
        let output = String(data: data, encoding: .utf8),
        output.utf8.count <= 16_384
    else {
        throw SmokeFailure.failed
    }
    return output
}

private func writePrivate<T: Encodable>(_ value: T, to url: URL) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(value)
    let temporary = url
        .deletingLastPathComponent()
        .appendingPathComponent(".\(UUID().uuidString).tmp")
    try data.write(to: temporary, options: [.atomic])
    guard chmod(temporary.path, S_IRUSR | S_IWUSR) == 0 else {
        try? FileManager.default.removeItem(at: temporary)
        throw SmokeFailure.failed
    }
    guard rename(temporary.path, url.path) == 0 else {
        try? FileManager.default.removeItem(at: temporary)
        throw SmokeFailure.failed
    }
}

private func emit<T: Encodable>(_ value: T) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(value)
    guard data.count <= 16_384 else {
        throw SmokeFailure.failed
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0a]))
}

do {
    try main()
} catch {
    // No paths, identifiers, framework errors, or personal metadata escape.
    FileHandle.standardError.write(Data("live smoke failed\n".utf8))
    exit(1)
}
