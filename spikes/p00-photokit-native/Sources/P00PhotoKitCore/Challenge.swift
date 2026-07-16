import Foundation

public struct LiveChallenge: Equatable, Sendable {
    public static let evidenceNonceEnvironmentKey = "P00_PHOTOS_EVIDENCE_NONCE"
    public static let challengeEnvironmentKey = "P00_PHOTOS_LIVE_CHALLENGE_JSON"
    public static let approvedProvenance =
        "dedicated_nonpersonal_synthetic_photos_library_v1"

    public let schemaVersion: Int
    public let nonce: String
    public let runID: String
    public let harnessRunID: String
    public let sourceFingerprint: String
    public let executableSHA256: String
    public let nonpersonalProvenance: String
    public let outputContract: OutputContract
    public let local: FixtureExpectation
    public let cloud: FixtureExpectation

    public init(evidenceNonce: String, rawJSON: String) throws {
        guard Self.isLowerSHA256(evidenceNonce),
              let data = rawJSON.data(using: .utf8),
              data.count <= 16 * 1_024 else {
            throw ChallengeError.invalidNonce
        }
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw ChallengeError.invalidJSON
        }
        guard let dictionary = object as? [String: Any],
              Set(dictionary.keys) == Self.topLevelFields else {
            throw ChallengeError.invalidFields
        }
        try Self.validateExactJSONTypes(dictionary)
        let payload: Payload
        do {
            payload = try JSONDecoder().decode(Payload.self, from: data)
        } catch {
            throw ChallengeError.invalidJSON
        }
        guard payload.schemaVersion == 1,
              payload.nonce == evidenceNonce,
              Self.isRunID(payload.runID),
              Self.isSafeIdentifier(payload.harnessRunID),
              Self.isLowerSHA256(payload.sourceFingerprint),
              Self.isLowerSHA256(payload.executableSHA256),
              payload.nonpersonalProvenance == Self.approvedProvenance,
              payload.outputContract.isValid(runID: payload.runID),
              payload.local.isValid,
              payload.cloud.isValid else {
            throw ChallengeError.invalidValue
        }
        guard payload.local.fixtureID != payload.cloud.fixtureID,
              payload.local.sha256 != payload.cloud.sha256 else {
            throw ChallengeError.fixturesNotDistinct
        }

        schemaVersion = payload.schemaVersion
        nonce = payload.nonce
        runID = payload.runID
        harnessRunID = payload.harnessRunID
        sourceFingerprint = payload.sourceFingerprint
        executableSHA256 = payload.executableSHA256
        nonpersonalProvenance = payload.nonpersonalProvenance
        outputContract = payload.outputContract
        local = payload.local
        cloud = payload.cloud
    }

    public func fixture(for role: FixtureRole) -> FixtureExpectation {
        role == .local ? local : cloud
    }

    public static func isLowerSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    private static let topLevelFields: Set<String> = [
        "schema_version",
        "nonce",
        "run_id",
        "harness_run_id",
        "source_fingerprint",
        "executable_sha256",
        "nonpersonal_provenance",
        "output_contract",
        "local",
        "cloud",
    ]

    private static let outputFields: Set<String> = [
        "kind",
        "bundle_id",
        "relative_directory",
        "must_not_exist",
        "asset_suffix",
        "provenance_suffix",
    ]

    private static let fixtureFields: Set<String> = [
        "fixture_id",
        "sha256",
        "pixel_width",
        "pixel_height",
    ]

    private static func validateExactJSONTypes(_ dictionary: [String: Any]) throws {
        guard isJSONInteger(dictionary["schema_version"]),
              let output = dictionary["output_contract"] as? [String: Any],
              Set(output.keys) == outputFields,
              output["must_not_exist"] is Bool else {
            throw ChallengeError.invalidFields
        }
        for role in ["local", "cloud"] {
            guard let fixture = dictionary[role] as? [String: Any],
                  Set(fixture.keys) == fixtureFields,
                  isJSONInteger(fixture["pixel_width"]),
                  isJSONInteger(fixture["pixel_height"]) else {
                throw ChallengeError.invalidFields
            }
        }
    }

    private static func isJSONInteger(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber else { return false }
        return CFGetTypeID(number) != CFBooleanGetTypeID()
            && !CFNumberIsFloatType(number)
    }

    fileprivate static func isSafeIdentifier(_ value: String) -> Bool {
        guard let first = value.utf8.first, !value.isEmpty, value.utf8.count <= 128,
              isASCIIAlphaNumeric(first) else {
            return false
        }
        return value.utf8.allSatisfy {
            isASCIIAlphaNumeric($0) || [46, 95, 58, 45].contains($0)
        }
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (48...57).contains(byte)
            || (65...90).contains(byte)
            || (97...122).contains(byte)
    }

    private static func isRunID(_ value: String) -> Bool {
        value.utf8.count == 36
            && value.hasPrefix("p00-")
            && value.dropFirst(4).utf8.allSatisfy {
                (48...57).contains($0) || (97...102).contains($0)
            }
    }
}

public enum FixtureRole: String, Codable, Equatable, Sendable {
    case local
    case cloud
}

public struct FixtureExpectation: Codable, Equatable, Sendable {
    public let fixtureID: String
    public let sha256: String
    public let pixelWidth: Int
    public let pixelHeight: Int

    enum CodingKeys: String, CodingKey {
        case fixtureID = "fixture_id"
        case sha256
        case pixelWidth = "pixel_width"
        case pixelHeight = "pixel_height"
    }

    fileprivate var isValid: Bool {
        LiveChallenge.isSafeIdentifier(fixtureID)
            && LiveChallenge.isLowerSHA256(sha256)
            && pixelWidth > 0
            && pixelHeight > 0
            && pixelWidth <= PrivateRunOutputStore.pixelLimit / pixelHeight
    }
}

public struct OutputContract: Codable, Equatable, Sendable {
    public let kind: String
    public let bundleID: String
    public let relativeDirectory: String
    public let mustNotExist: Bool
    public let assetSuffix: String
    public let provenanceSuffix: String

    enum CodingKeys: String, CodingKey {
        case kind
        case bundleID = "bundle_id"
        case relativeDirectory = "relative_directory"
        case mustNotExist = "must_not_exist"
        case assetSuffix = "asset_suffix"
        case provenanceSuffix = "provenance_suffix"
    }

    fileprivate func isValid(runID: String) -> Bool {
        kind == "sandbox_container_v1"
            && bundleID == "com.wardrobe.p00-photokit-native"
            && relativeDirectory
                == "Library/Application Support/P00PhotoKitNative/\(runID)"
            && mustNotExist
            && assetSuffix == ".asset"
            && provenanceSuffix == ".provenance.json"
    }
}

public enum ChallengeError: Error, Equatable {
    case invalidNonce
    case invalidJSON
    case invalidFields
    case invalidValue
    case fixturesNotDistinct
}

private struct Payload: Codable {
    let schemaVersion: Int
    let nonce: String
    let runID: String
    let harnessRunID: String
    let sourceFingerprint: String
    let executableSHA256: String
    let nonpersonalProvenance: String
    let outputContract: OutputContract
    let local: FixtureExpectation
    let cloud: FixtureExpectation

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case nonce
        case runID = "run_id"
        case harnessRunID = "harness_run_id"
        case sourceFingerprint = "source_fingerprint"
        case executableSHA256 = "executable_sha256"
        case nonpersonalProvenance = "nonpersonal_provenance"
        case outputContract = "output_contract"
        case local
        case cloud
    }
}
