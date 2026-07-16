import Foundation
import Photos
import P00PhotoKitCore

final class PhotoResourceOperation {
    typealias Completion = (Result<CompletedResourceEvidence, TransferFailure>) -> Void

    private let operationQueue: DispatchQueue
    private let requestLaunchQueue: DispatchQueue
    private let manager = PHAssetResourceManager.default()
    private let resource: PHAssetResource
    private let challenge: LiveChallenge
    private let selectedDimensions: ImageDimensions
    private let assetAlias: String
    private let resourceAlias: String
    private let outputStore: PrivateRunOutputStore
    private let evidenceContext: LiveEvidenceContext
    private let emitter: LiveRecordEmitter
    private let completion: Completion
    private let pendingGate = PendingByteGate(
        limit: TransferStateMachine.maximumPendingCallbackBytes
    )
    private var state: TransferStateMachine
    private var sink: StreamingImageSink?
    private var registeredRequests: [UInt64: PHAssetResourceDataRequestID] = [:]
    private var deliveredTerminal = false
    private var lastEmittedProgress: Double?

    init(
        resource: PHAssetResource,
        challenge: LiveChallenge,
        selectedDimensions: ImageDimensions,
        assetAlias: String,
        resourceAlias: String,
        outputStore: PrivateRunOutputStore,
        evidenceContext: LiveEvidenceContext,
        emitter: LiveRecordEmitter,
        completion: @escaping Completion
    ) {
        self.resource = resource
        self.challenge = challenge
        self.selectedDimensions = selectedDimensions
        self.assetAlias = assetAlias
        self.resourceAlias = resourceAlias
        self.outputStore = outputStore
        self.evidenceContext = evidenceContext
        self.emitter = emitter
        self.completion = completion
        state = TransferStateMachine(resourceToken: resourceAlias)
        operationQueue = DispatchQueue(
            label: "com.wardrobe.p00-photokit-native.operation.\(resourceAlias)"
        )
        requestLaunchQueue = DispatchQueue(
            label: "com.wardrobe.p00-photokit-native.request.\(resourceAlias)"
        )
    }

    func start() {
        operationQueue.async { [weak self] in
            guard let self else { return }
            guard self.authorizationIsExact() else {
                self.fail(.authorizationChanged)
                return
            }
            do {
                self.sink = try self.outputStore.makeSink(
                    outputName: self.assetOutputName
                )
                try self.emitter.emit(
                    .probeStarted(
                        assetAlias: self.assetAlias,
                        resourceAlias: self.resourceAlias
                    )
                )
            } catch {
                self.fail(.outputIntegrity)
                return
            }
            self.issueRequest(networkAllowed: false, generation: self.state.generation)
        }
    }

    func cancel() {
        operationQueue.async { [weak self] in
            guard let self else { return }
            let requestIDs = self.state.cancel()
            self.pendingGate.close()
            requestIDs.forEach {
                self.manager.cancelDataRequest(PHAssetResourceDataRequestID($0))
            }
            self.sink?.discard()
            self.deliver(.failure(.cancelled))
        }
    }

    private func issueRequest(networkAllowed: Bool, generation: UInt64) {
        requestLaunchQueue.async { [weak self] in
            guard let self else { return }
            let options = PHAssetResourceRequestOptions()
            options.isNetworkAccessAllowed = networkAllowed
            if networkAllowed {
                options.progressHandler = { [weak self] progress in
                    self?.operationQueue.async {
                        self?.handleProgress(progress, generation: generation)
                    }
                }
            }
            let requestID = NetworkRequestAuthorizationGate.perform(
                networkAllowed: networkAllowed,
                authorizationIsExact: self.authorizationIsExact
            ) {
                self.manager.requestData(
                    for: self.resource,
                    options: options,
                    dataReceivedHandler: { [weak self] data in
                        self?.copyCallbackDataSynchronously(data, generation: generation)
                    },
                    completionHandler: { [weak self] error in
                        self?.operationQueue.async {
                            self?.handleCompletion(error, generation: generation)
                        }
                    }
                )
            }
            guard let requestID else {
                self.operationQueue.async {
                    self.fail(.authorizationChanged)
                }
                return
            }
            self.operationQueue.async {
                self.registerRequest(requestID, generation: generation)
            }
        }
    }

    private func registerRequest(
        _ requestID: PHAssetResourceDataRequestID,
        generation: UInt64
    ) {
        registeredRequests[generation] = requestID
        let registration = state.registerRequest(id: Int32(requestID), generation: generation)
        if registration?.cancelImmediately == true {
            manager.cancelDataRequest(requestID)
            registeredRequests.removeValue(forKey: generation)
        } else if registration == nil, state.terminalResult != nil {
            registeredRequests.removeValue(forKey: generation)
        }
    }

    private func copyCallbackDataSynchronously(_ callbackData: Data, generation: UInt64) {
        guard callbackData.count <= Int(TransferStateMachine.maximumResourceBytes) else {
            operationQueue.async { [weak self] in self?.fail(.resourceLimit) }
            return
        }
        callbackData.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let count = min(
                    TransferStateMachine.maximumChunkBytes,
                    buffer.count - offset
                )
                guard pendingGate.acquire(count) else { return }
                let copied = Data(bytes: base.advanced(by: offset), count: count)
                operationQueue.async { [weak self] in
                    defer { self?.pendingGate.release(count) }
                    self?.handleCopiedChunk(copied, generation: generation)
                }
                offset += count
            }
        }
    }

    private func handleCopiedChunk(_ data: Data, generation: UInt64) {
        guard state.terminalResult == nil else { return }
        if let failure = state.acceptChunk(byteCount: data.count, generation: generation) {
            fail(failure)
            return
        }
        guard generation == state.generation, let sink else { return }
        do {
            try sink.append(data)
        } catch {
            fail(.outputIntegrity)
        }
    }

    private func handleProgress(_ progress: Double, generation: UInt64) {
        guard state.terminalResult == nil else { return }
        if let failure = state.observeProgress(progress, generation: generation) {
            fail(failure)
            return
        }
        guard generation == state.generation, state.phase == .retrying else { return }
        let shouldEmit = lastEmittedProgress == nil
            || progress >= 1
            || progress - (lastEmittedProgress ?? 0) >= 0.05
        guard shouldEmit else { return }
        lastEmittedProgress = progress
        do {
            try emitter.emit(
                .transferProgress(
                    assetAlias: assetAlias,
                    resourceAlias: resourceAlias,
                    permille: Int((progress * 1_000).rounded(.down))
                )
            )
        } catch {
            fail(.protocolViolation)
        }
    }

    private func handleCompletion(_ error: Error?, generation: UInt64) {
        registeredRequests.removeValue(forKey: generation)
        guard state.terminalResult == nil else { return }
        let failure = error.map {
            let error = $0 as NSError
            return FrameworkFailure(domain: error.domain, code: error.code)
        }
        switch state.phase {
        case .probing:
            handleProbeCompletion(failure, generation: generation)
        case .retrying:
            handleRetryCompletion(failure, generation: generation)
        case .awaitingRetry, .terminal:
            break
        }
    }

    private func handleProbeCompletion(_ failure: FrameworkFailure?, generation: UInt64) {
        let identity = PhotoErrorIdentity(
            networkRequiredDomain: PHPhotosErrorDomain,
            networkRequiredCode: PHPhotosError.networkAccessRequired.rawValue
        )
        if failure == nil {
            guard let evidence = finalizeOutput(role: .local) else { return }
            guard state.completeProbe(
                failure: nil,
                errorIdentity: identity,
                generation: generation
            ) == .localComplete else {
                fail(.protocolViolation)
                return
            }
            complete(evidence)
            return
        }
        let decision = state.completeProbe(
            failure: failure,
            errorIdentity: identity,
            generation: generation
        )
        guard decision == .retrySameResource else {
            fail(.unexpectedProbeFailure)
            return
        }
        guard dimensionsMatch(challenge.cloud) else {
            fail(.outputIntegrity)
            return
        }
        sink?.discard()
        do {
            try emitter.emit(
                .probeNetworkRequired(
                    assetAlias: assetAlias,
                    resourceAlias: resourceAlias
                )
            )
            sink = try outputStore.makeSink(outputName: assetOutputName)
            let retryGeneration = try state.beginRetry(resourceToken: resourceAlias).get()
            try emitter.emit(
                .retryStarted(assetAlias: assetAlias, resourceAlias: resourceAlias)
            )
            issueRequest(networkAllowed: true, generation: retryGeneration)
        } catch {
            fail(.outputIntegrity)
        }
    }

    private func handleRetryCompletion(_ failure: FrameworkFailure?, generation: UInt64) {
        guard failure == nil,
              state.progressCallbackCount > 0,
              let evidence = finalizeOutput(role: .cloud) else {
            _ = state.completeRetry(failure: failure, generation: generation)
            fail(failure == nil ? .missingProgress : .transferFailure)
            return
        }
        guard state.completeRetry(failure: nil, generation: generation) == .cloudComplete else {
            fail(.protocolViolation)
            return
        }
        complete(evidence)
    }

    private func finalizeOutput(role: FixtureRole) -> CompletedResourceEvidence? {
        let fixture = challenge.fixture(for: role)
        guard authorizationIsExact(), dimensionsMatch(fixture), let sink else {
            fail(.outputIntegrity)
            return nil
        }
        let evidence = CompletedResourceEvidence(
            role: role,
            fixtureID: fixture.fixtureID,
            assetAlias: assetAlias,
            resourceAlias: resourceAlias,
            blobSHA256: fixture.sha256,
            byteCount: state.acceptedBytes,
            pixelWidth: fixture.pixelWidth,
            pixelHeight: fixture.pixelHeight,
            progressCallbackCount: state.progressCallbackCount
        )
        do {
            let provenanceName =
                resourceAlias + challenge.outputContract.provenanceSuffix
            let artifact = try sink.finalize(
                expected: fixture,
                expectedLength: state.acceptedBytes,
                expectedDimensions: selectedDimensions,
                provenanceName: provenanceName,
                provenance: ProvenanceRecord(
                    context: evidenceContext,
                    evidence: evidence
                )
            )
            guard artifact.sha256 == fixture.sha256,
                  artifact.length == state.acceptedBytes else {
                throw ContentStoreError.descriptorMismatch
            }
            return evidence
        } catch {
            fail(.outputIntegrity)
            return nil
        }
    }

    private func dimensionsMatch(_ fixture: FixtureExpectation) -> Bool {
        selectedDimensions == ImageDimensions(
            width: fixture.pixelWidth,
            height: fixture.pixelHeight
        )
    }

    private var assetOutputName: String {
        resourceAlias + challenge.outputContract.assetSuffix
    }

    private func authorizationIsExact() -> Bool {
        PHPhotoLibrary.authorizationStatus(for: .readWrite) == .authorized
    }

    private func complete(_ evidence: CompletedResourceEvidence) {
        pendingGate.close()
        do {
            try emitter.emit(.assetCompleted(evidence))
            deliver(.success(evidence))
        } catch {
            deliver(.failure(.protocolViolation))
        }
    }

    private func fail(_ failure: TransferFailure) {
        if state.terminalResult == nil {
            _ = state.fail(failure)
        }
        pendingGate.close()
        registeredRequests.values.forEach { manager.cancelDataRequest($0) }
        registeredRequests.removeAll()
        sink?.discard()
        deliver(.failure(failure))
    }

    private func deliver(_ result: Result<CompletedResourceEvidence, TransferFailure>) {
        guard !deliveredTerminal else { return }
        deliveredTerminal = true
        DispatchQueue.main.async { [completion] in completion(result) }
    }
}
