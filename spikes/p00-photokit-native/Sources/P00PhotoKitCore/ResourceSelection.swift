import Foundation

public enum AssetKind: Equatable, Sendable {
    case image
    case video
    case audio
    case unknown
}

public enum ResourceKind: Equatable, Sendable {
    case originalPhoto
    case adjustedPhoto
    case pairedVideo
    case video
    case audio
    case adjustmentData
    case alternatePhoto
    case unknown
}

public struct ResourceCandidate: Equatable, Sendable {
    public let token: String
    public let kind: ResourceKind
    public let uniformTypeIdentifier: String

    public init(token: String, kind: ResourceKind, uniformTypeIdentifier: String) {
        self.token = token
        self.kind = kind
        self.uniformTypeIdentifier = uniformTypeIdentifier
    }
}

public enum ResourceRejection: Error, Equatable, Sendable {
    case notStillImage
    case livePhoto
    case emptyResourceSet
    case ambiguousResourceSet
    case unsupportedResource
    case unsupportedType
}

public enum OriginalPrimaryResourcePolicy {
    public static let identifier = "original_primary_v1"

    public static let allowedTypes: Set<String> = [
        "public.heic",
        "public.heif",
        "public.jpeg",
        "public.png",
    ]

    public static func select(
        assetKind: AssetKind,
        isLivePhoto: Bool,
        candidates: [ResourceCandidate]
    ) -> Result<ResourceCandidate, ResourceRejection> {
        guard assetKind == .image else {
            return .failure(.notStillImage)
        }
        guard !isLivePhoto else {
            return .failure(.livePhoto)
        }
        guard !candidates.isEmpty else {
            return .failure(.emptyResourceSet)
        }

        // The spike deliberately excludes edits, sidecars, and compound assets.
        guard candidates.count == 1, let candidate = candidates.first else {
            return .failure(.ambiguousResourceSet)
        }
        guard candidate.kind == .originalPhoto else {
            return .failure(.unsupportedResource)
        }
        guard allowedTypes.contains(candidate.uniformTypeIdentifier.lowercased()) else {
            return .failure(.unsupportedType)
        }
        return .success(candidate)
    }
}
