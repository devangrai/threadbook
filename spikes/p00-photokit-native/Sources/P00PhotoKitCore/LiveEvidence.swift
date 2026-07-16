import Foundation

public struct LiveEvidenceContext: Equatable, Sendable {
    public let runID: String
    public let harnessRunID: String
    public let sourceFingerprint: String
    public let executableSHA256: String
    public let bundleID: String
    public let nonpersonalProvenance: String
    public let connectorInstance: String
    public let connectorGeneration: String

    public init(challenge: LiveChallenge) {
        let aliases = AliasFactory(nonce: challenge.nonce)
        runID = challenge.runID
        harnessRunID = challenge.harnessRunID
        sourceFingerprint = challenge.sourceFingerprint
        executableSHA256 = challenge.executableSHA256
        bundleID = challenge.outputContract.bundleID
        nonpersonalProvenance = challenge.nonpersonalProvenance
        connectorInstance = aliases.runAlias(
            context: "connector-instance-v1",
            value: [
                challenge.outputContract.bundleID,
                challenge.nonpersonalProvenance,
            ].joined(separator: ":")
        )
        connectorGeneration = aliases.runAlias(
            context: "enrolled-library-generation-v1",
            value: [
                challenge.nonpersonalProvenance,
                challenge.local.fixtureID,
                challenge.local.sha256,
                challenge.cloud.fixtureID,
                challenge.cloud.sha256,
            ].joined(separator: ":")
        )
    }

    public init(
        runID: String,
        harnessRunID: String,
        sourceFingerprint: String,
        executableSHA256: String,
        bundleID: String,
        nonpersonalProvenance: String,
        connectorInstance: String,
        connectorGeneration: String
    ) {
        self.runID = runID
        self.harnessRunID = harnessRunID
        self.sourceFingerprint = sourceFingerprint
        self.executableSHA256 = executableSHA256
        self.bundleID = bundleID
        self.nonpersonalProvenance = nonpersonalProvenance
        self.connectorInstance = connectorInstance
        self.connectorGeneration = connectorGeneration
    }
}

public struct CompletedResourceEvidence: Equatable, Sendable {
    public let role: FixtureRole
    public let fixtureID: String
    public let assetAlias: String
    public let resourceAlias: String
    public let blobSHA256: String
    public let byteCount: Int64
    public let pixelWidth: Int
    public let pixelHeight: Int
    public let progressCallbackCount: Int

    public init(
        role: FixtureRole,
        fixtureID: String,
        assetAlias: String,
        resourceAlias: String,
        blobSHA256: String,
        byteCount: Int64,
        pixelWidth: Int,
        pixelHeight: Int,
        progressCallbackCount: Int
    ) {
        self.role = role
        self.fixtureID = fixtureID
        self.assetAlias = assetAlias
        self.resourceAlias = resourceAlias
        self.blobSHA256 = blobSHA256
        self.byteCount = byteCount
        self.pixelWidth = pixelWidth
        self.pixelHeight = pixelHeight
        self.progressCallbackCount = progressCallbackCount
    }
}

public enum LiveEvent: Equatable, Sendable {
    case authorizationGranted
    case resourceSelected(assetAlias: String, resourceAlias: String)
    case probeStarted(assetAlias: String, resourceAlias: String)
    case probeNetworkRequired(assetAlias: String, resourceAlias: String)
    case retryStarted(assetAlias: String, resourceAlias: String)
    case transferProgress(assetAlias: String, resourceAlias: String, permille: Int)
    case assetCompleted(CompletedResourceEvidence)
    case sessionCompleted
}

public enum LiveEvidenceEncoder {
    public static let prefix = "P00_PHOTOS_LIVE "
    public static let maximumMessageBytes = 64 * 1_024

    public static func line(
        nonce: String,
        sequence: Int,
        event: LiveEvent
    ) throws -> Data {
        var record: [String: Any] = [
            "schema_version": 1,
            "scenario": "p00_photokit_native_live",
            "challenge_nonce": nonce,
            "sequence": sequence,
        ]
        switch event {
        case .authorizationGranted:
            record["event"] = "authorization_granted"
        case let .resourceSelected(asset, resource):
            addResource(
                event: "resource_selected",
                asset: asset,
                resource: resource,
                to: &record
            )
        case let .probeStarted(asset, resource):
            addResource(
                event: "probe_started",
                asset: asset,
                resource: resource,
                to: &record
            )
            record["network_allowed"] = false
        case let .probeNetworkRequired(asset, resource):
            addResource(
                event: "probe_network_required",
                asset: asset,
                resource: resource,
                to: &record
            )
            record["network_allowed"] = false
        case let .retryStarted(asset, resource):
            addResource(
                event: "retry_started",
                asset: asset,
                resource: resource,
                to: &record
            )
            record["network_allowed"] = true
        case let .transferProgress(asset, resource, permille):
            guard (0...1_000).contains(permille) else {
                throw LiveEvidenceError.encoding
            }
            addResource(
                event: "transfer_progress",
                asset: asset,
                resource: resource,
                to: &record
            )
            record["progress_permille"] = permille
        case let .assetCompleted(evidence):
            addResource(
                event: "asset_completed",
                asset: evidence.assetAlias,
                resource: evidence.resourceAlias,
                to: &record
            )
            record["byte_count"] = evidence.byteCount
            record["progress_callback_count"] = evidence.progressCallbackCount
            record["residency"] = evidence.role.rawValue
            record["outcome"] = "pass"
        case .sessionCompleted:
            record["event"] = "session_completed"
            record["outcome"] = "pass"
        }
        guard JSONSerialization.isValidJSONObject(record) else {
            throw LiveEvidenceError.encoding
        }
        let payload = try JSONSerialization.data(
            withJSONObject: record,
            options: [.sortedKeys]
        )
        var line = Data(prefix.utf8)
        line.append(payload)
        line.append(0x0A)
        guard line.count <= maximumMessageBytes else {
            throw LiveEvidenceError.messageTooLarge
        }
        return line
    }

    private static func addResource(
        event: String,
        asset: String,
        resource: String,
        to record: inout [String: Any]
    ) {
        record["event"] = event
        record["asset_alias"] = asset
        record["resource_alias"] = resource
    }
}

public enum LiveEvidenceError: Error, Equatable {
    case encoding
    case messageTooLarge
}

public struct ProvenanceRecord: Codable, Equatable, Sendable {
    public let schemaVersion = 1
    public let runID: String
    public let harnessRunID: String
    public let sourceFingerprint: String
    public let executableSHA256: String
    public let bundleID: String
    public let fixtureRole: String
    public let fixtureID: String
    public let nonpersonalProvenance: String
    public let connectorInstance: String
    public let connectorGeneration: String
    public let assetAlias: String
    public let resourceAlias: String
    public let representationPolicy = "original_primary_v1"
    public let residency: String
    public let blobSHA256: String
    public let byteCount: Int64
    public let pixelWidth: Int
    public let pixelHeight: Int

    public init(
        context: LiveEvidenceContext,
        evidence: CompletedResourceEvidence
    ) {
        runID = context.runID
        harnessRunID = context.harnessRunID
        sourceFingerprint = context.sourceFingerprint
        executableSHA256 = context.executableSHA256
        bundleID = context.bundleID
        fixtureRole = evidence.role.rawValue
        fixtureID = evidence.fixtureID
        nonpersonalProvenance = context.nonpersonalProvenance
        connectorInstance = context.connectorInstance
        connectorGeneration = context.connectorGeneration
        assetAlias = evidence.assetAlias
        resourceAlias = evidence.resourceAlias
        residency = evidence.role.rawValue
        blobSHA256 = evidence.blobSHA256
        byteCount = evidence.byteCount
        pixelWidth = evidence.pixelWidth
        pixelHeight = evidence.pixelHeight
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case runID = "run_id"
        case harnessRunID = "harness_run_id"
        case sourceFingerprint = "source_fingerprint"
        case executableSHA256 = "executable_sha256"
        case bundleID = "bundle_id"
        case fixtureRole = "fixture_role"
        case fixtureID = "fixture_id"
        case nonpersonalProvenance = "nonpersonal_provenance"
        case connectorInstance = "connector_instance"
        case connectorGeneration = "connector_generation"
        case assetAlias = "asset_alias"
        case resourceAlias = "resource_alias"
        case representationPolicy = "representation_policy"
        case residency
        case blobSHA256 = "blob_sha256"
        case byteCount = "byte_count"
        case pixelWidth = "pixel_width"
        case pixelHeight = "pixel_height"
    }
}
