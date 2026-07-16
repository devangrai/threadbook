import Foundation
import Photos

enum AssetMediaKind: Equatable {
    case image
    case other
}

enum CandidateResourceKind: Equatable {
    case originalPhoto
    case adjustedPhoto
    case alternatePhoto
    case pairedVideo
    case video
    case adjustmentData
    case other
}

struct ResourceCandidate: Equatable {
    let index: Int
    let kind: CandidateResourceKind
    let uniformTypeIdentifier: String
}

enum ResourceRejection: String, Error, Equatable {
    case notStillImage = "not_still_image"
    case livePhoto = "live_photo"
    case burst = "burst"
    case emptyResourceSet = "empty_resource_set"
    case ambiguousResourceSet = "ambiguous_resource_set"
    case unsupportedResource = "unsupported_resource"
    case unsupportedType = "unsupported_type"
}

enum OriginalPrimaryResourcePolicy {
    static let revision = "original-primary-v1"
    static let allowedTypes: Set<String> = [
        "public.heic",
        "public.heif",
        "public.jpeg",
        "public.png",
    ]

    static func select(
        mediaKind: AssetMediaKind,
        isLivePhoto: Bool,
        representsBurst: Bool,
        candidates: [ResourceCandidate]
    ) -> Result<ResourceCandidate, ResourceRejection> {
        guard mediaKind == .image else {
            return .failure(.notStillImage)
        }
        guard !isLivePhoto else {
            return .failure(.livePhoto)
        }
        guard !representsBurst else {
            return .failure(.burst)
        }
        guard !candidates.isEmpty else {
            return .failure(.emptyResourceSet)
        }
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

    static func candidates(for resources: [PHAssetResource]) -> [ResourceCandidate] {
        resources.enumerated().map { offset, resource in
            ResourceCandidate(
                index: offset,
                kind: map(resource.type),
                uniformTypeIdentifier: resource.uniformTypeIdentifier
            )
        }
    }

    private static func map(_ type: PHAssetResourceType) -> CandidateResourceKind {
        switch type {
        case .photo:
            return .originalPhoto
        case .fullSizePhoto:
            return .adjustedPhoto
        case .alternatePhoto:
            return .alternatePhoto
        case .pairedVideo, .fullSizePairedVideo:
            return .pairedVideo
        case .video, .fullSizeVideo:
            return .video
        case .adjustmentData:
            return .adjustmentData
        default:
            return .other
        }
    }
}
