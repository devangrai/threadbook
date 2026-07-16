import Foundation
import Photos
import WardrobePhotoKitObjC

final class PhotoKitCoordinator {
    static let shared = PhotoKitCoordinator()

    private init() {}

    func execute(_ command: NativeCommand, operation: NativeOperation) {
        DispatchQueue.main.async { [weak self, operation] in
            guard let self, !operation.isStopped else {
                return
            }
            var performed = false
            let contained = wk_photokit_objc_perform {
                performed = true
                self.executeOnMain(command, operation: operation)
            }
            if !contained || !performed {
                operation.fail(reason: "internal")
            }
        }
    }

    private func executeOnMain(_ command: NativeCommand, operation: NativeOperation) {
        dispatchPrecondition(condition: .onQueue(.main))
        switch command.kind {
        case .inspectAuthorization:
            emitAuthorization(operation: operation)
            operation.complete()
        case .requestAuthorization:
            requestAuthorization(operation: operation)
        case .listAlbums:
            listAlbums(operation: operation)
        case .enumerateAlbum:
            guard let identifier = command.albumIdentifier else {
                operation.fail(reason: "invalid")
                return
            }
            enumerateAlbum(identifier: identifier, operation: operation)
        case .streamResource:
            guard
                let resourceToken = command.resourceToken,
                let allowNetwork = command.allowNetwork
            else {
                operation.fail(reason: "invalid")
                return
            }
            streamResource(
                resourceToken: resourceToken,
                allowNetwork: allowNetwork,
                operation: operation
            )
        case .cancelOperation:
            operation.fail(reason: "invalid")
        }
    }

    private func emitAuthorization(operation: NativeOperation) {
        operationEvent(
            operation,
            event: "authorization",
            fields: [
                "status": authorizationName(
                    PHPhotoLibrary.authorizationStatus(for: .readWrite)
                ),
            ]
        )
    }

    private func requestAuthorization(operation: NativeOperation) {
        PHPhotoLibrary.requestAuthorization(for: .readWrite) { status in
            guard !operation.isStopped else {
                return
            }
            self.operationEvent(
                operation,
                event: "authorization",
                fields: ["status": self.authorizationName(status)]
            )
            operation.complete()
        }
    }

    private func listAlbums(operation: NativeOperation) {
        guard PHPhotoLibrary.authorizationStatus(for: .readWrite) == .authorized else {
            operation.fail(reason: "authorization_unavailable")
            return
        }
        let result = PHAssetCollection.fetchAssetCollections(
            with: .album,
            subtype: .albumRegular,
            options: nil
        )
        let count = min(result.count, NativeProtocol.maximumAlbums)
        if count > 0 {
            for index in 0..<count {
                guard !operation.isStopped else {
                    return
                }
                let album = result.object(at: index)
                guard
                    let label = boundedLabel(album.localizedTitle ?? "Untitled Album"),
                    boundedIdentifier(album.localIdentifier)
                else {
                    operation.fail(reason: "invalid_album")
                    return
                }
                operationEvent(
                    operation,
                    event: "album",
                    fields: [
                        "album_identifier": album.localIdentifier,
                        "label": label,
                    ]
                )
            }
        }
        operation.complete(
            fields: [
                "album_count": count,
                "truncated": result.count > NativeProtocol.maximumAlbums,
            ]
        )
    }

    private func enumerateAlbum(identifier: String, operation: NativeOperation) {
        guard PHPhotoLibrary.authorizationStatus(for: .readWrite) == .authorized else {
            operation.fail(reason: "authorization_unavailable")
            return
        }
        let albums = PHAssetCollection.fetchAssetCollections(
            withLocalIdentifiers: [identifier],
            options: nil
        )
        guard albums.count == 1 else {
            operation.fail(reason: "scope_unavailable")
            return
        }
        let album = albums.object(at: 0)
        guard
            album.assetCollectionType == .album,
            album.assetCollectionSubtype == .albumRegular
        else {
            operation.fail(reason: "scope_unavailable")
            return
        }
        let options = PHFetchOptions()
        options.predicate = NSPredicate(
            format: "mediaType == %d",
            PHAssetMediaType.image.rawValue
        )
        let assets = PHAsset.fetchAssets(in: album, options: options)
        guard assets.count <= NativeProtocol.maximumAssets else {
            operation.fail(reason: "scope_too_large")
            return
        }

        struct Observation {
            let identifier: String
            let resource: PHAssetResource?
            let resourceToken: String?
            let uti: String?
            let rejection: String?
        }
        var observations: [Observation] = []
        observations.reserveCapacity(assets.count)
        if assets.count > 0 {
            for index in 0..<assets.count {
                guard !operation.isStopped else {
                    return
                }
                let asset = assets.object(at: index)
                guard boundedIdentifier(asset.localIdentifier) else {
                    operation.fail(reason: "invalid_asset")
                    return
                }
                let resources = PHAssetResource.assetResources(for: asset)
                let selection = OriginalPrimaryResourcePolicy.select(
                    mediaKind: asset.mediaType == .image ? .image : .other,
                    isLivePhoto: asset.mediaSubtypes.contains(.photoLive),
                    representsBurst: asset.representsBurst,
                    candidates: OriginalPrimaryResourcePolicy.candidates(for: resources)
                )
                switch selection {
                case let .success(candidate):
                    observations.append(
                        Observation(
                            identifier: asset.localIdentifier,
                            resource: resources[candidate.index],
                            resourceToken: UUID().uuidString.lowercased(),
                            uti: candidate.uniformTypeIdentifier.lowercased(),
                            rejection: nil
                        )
                    )
                case let .failure(rejection):
                    observations.append(
                        Observation(
                            identifier: asset.localIdentifier,
                            resource: nil,
                            resourceToken: nil,
                            uti: nil,
                            rejection: rejection.rawValue
                        )
                    )
                }
            }
        }

        for observation in observations {
            guard !operation.isStopped else {
                return
            }
            var fields: [String: Any] = [
                "asset_identifier": observation.identifier,
                "selection_policy": OriginalPrimaryResourcePolicy.revision,
            ]
            if
                let uti = observation.uti,
                let resource = observation.resource,
                let resourceToken = observation.resourceToken
            {
                guard operation.retain(resource: resource, token: resourceToken) else {
                    operation.fail(reason: "resource_limit")
                    return
                }
                fields["supported"] = true
                fields["uti"] = uti
                fields["resource_token"] = resourceToken
            } else {
                fields["supported"] = false
                fields["reason"] = observation.rejection ?? "unsupported_resource"
            }
            operationEvent(operation, event: "asset", fields: fields)
        }
        operation.complete(fields: ["asset_count": observations.count])
    }

    private func streamResource(
        resourceToken: String,
        allowNetwork: Bool,
        operation: NativeOperation
    ) {
        guard PHPhotoLibrary.authorizationStatus(for: .readWrite) == .authorized else {
            operation.fail(reason: "authorization_unavailable")
            return
        }
        guard let resource = operation.retainedResource(token: resourceToken) else {
            operation.fail(reason: "resource_unavailable")
            return
        }
        requestResource(
            resource,
            resourceToken: resourceToken,
            networkAllowed: allowNetwork,
            operation: operation
        )
    }

    private func requestResource(
        _ resource: PHAssetResource,
        resourceToken: String,
        networkAllowed: Bool,
        operation: NativeOperation
    ) {
        guard !operation.isStopped else {
            return
        }
        let options = PHAssetResourceRequestOptions()
        options.isNetworkAccessAllowed = networkAllowed
        if networkAllowed {
            options.progressHandler = { progress in
                operation.emitProgress(progress)
            }
        }
        let resourceManager = PHAssetResourceManager.default()
        let cancellation = RequestCancellation(
            resourceManager: resourceManager
        )
        let installed = operation.installCancellation { completion in
            cancellation.request(completion: completion)
        }
        guard installed else {
            cancellation.abandon()
            return
        }
        let bytesBeforeRequest = operation.byteCount
        var requestID: PHAssetResourceDataRequestID?
        let contained = wk_photokit_objc_perform {
            requestID = resourceManager.requestData(
                for: resource,
                options: options,
                dataReceivedHandler: { callbackData in
                    guard operation.acceptCallbackBytes(callbackData) else {
                        return
                    }
                },
                completionHandler: { error in
                    guard !operation.isStopped else {
                        return
                    }
                    let accepted = operation.byteCount - bytesBeforeRequest
                    if self.isNetworkAccessRequired(error), accepted == 0 {
                        operation.fail(reason: "network_access_required")
                    } else if error != nil {
                        operation.fail(
                            reason: accepted > 0
                                ? "partial_transfer"
                                : "transfer_failed"
                        )
                    } else if accepted <= 0 {
                        operation.fail(reason: "empty_resource")
                    } else {
                        operation.complete(
                            fields: [
                                "bytes": operation.byteCount,
                                "materialization": networkAllowed ? "cloud" : "local",
                                "resource_token": resourceToken,
                            ]
                        )
                    }
                }
            )
        }
        guard contained, let requestID else {
            cancellation.abandon()
            operation.fail(reason: "internal")
            return
        }
        cancellation.register(requestID: requestID)
    }

    private func isNetworkAccessRequired(_ error: Error?) -> Bool {
        guard let error = error as NSError? else {
            return false
        }
        return error.domain == PHPhotosErrorDomain
            && error.code == PHPhotosError.networkAccessRequired.rawValue
    }

    private func authorizationName(_ status: PHAuthorizationStatus) -> String {
        switch status {
        case .notDetermined:
            return "not_determined"
        case .restricted:
            return "restricted"
        case .denied:
            return "denied"
        case .authorized:
            return "authorized"
        case .limited:
            return "limited"
        @unknown default:
            return "restricted"
        }
    }

    private func operationEvent(
        _ operation: NativeOperation,
        event: String,
        fields: [String: Any]
    ) {
        operation.emit(event: event, fields: fields)
    }

    private func boundedLabel(_ label: String) -> String? {
        let normalized = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard
            !normalized.isEmpty,
            normalized.utf8.count <= NativeProtocol.maximumLabelBytes,
            !normalized.utf8.contains(0)
        else {
            return nil
        }
        return normalized
    }

    private func boundedIdentifier(_ identifier: String) -> Bool {
        !identifier.isEmpty
            && identifier.utf8.count <= NativeProtocol.maximumIdentifierBytes
            && !identifier.utf8.contains(0)
    }
}

final class RequestCancellation {
    private let condition = NSLock()
    private let cancelRequest: (PHAssetResourceDataRequestID) -> Void
    private var requestID: PHAssetResourceDataRequestID?
    private var pendingCompletion: (() -> Void)?
    private var abandoned = false

    init(resourceManager: PHAssetResourceManager) {
        cancelRequest = { requestID in
            _ = wk_photokit_objc_perform {
                resourceManager.cancelDataRequest(requestID)
            }
        }
    }

    init(
        cancelRequest: @escaping (PHAssetResourceDataRequestID) -> Void
    ) {
        self.cancelRequest = cancelRequest
    }

    func request(completion: @escaping () -> Void) {
        condition.lock()
        if abandoned {
            condition.unlock()
            completion()
            return
        }
        if let requestID {
            condition.unlock()
            cancel(requestID: requestID, completion: completion)
            return
        }
        pendingCompletion = completion
        condition.unlock()
    }

    func register(requestID: PHAssetResourceDataRequestID) {
        condition.lock()
        guard !abandoned else {
            condition.unlock()
            return
        }
        self.requestID = requestID
        let completion = pendingCompletion
        pendingCompletion = nil
        condition.unlock()
        if let completion {
            cancel(requestID: requestID, completion: completion)
        }
    }

    func abandon() {
        condition.lock()
        abandoned = true
        let completion = pendingCompletion
        pendingCompletion = nil
        condition.unlock()
        completion?()
    }

    private func cancel(
        requestID: PHAssetResourceDataRequestID,
        completion: @escaping () -> Void
    ) {
        let action = {
            self.cancelRequest(requestID)
            completion()
        }
        if Thread.isMainThread {
            action()
        } else {
            DispatchQueue.main.async(execute: action)
        }
    }
}
