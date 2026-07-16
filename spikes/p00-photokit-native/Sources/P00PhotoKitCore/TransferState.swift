import Foundation

public struct FrameworkFailure: Equatable, Sendable {
    public let domain: String
    public let code: Int

    public init(domain: String, code: Int) {
        self.domain = domain
        self.code = code
    }
}

public struct PhotoErrorIdentity: Equatable, Sendable {
    public let networkRequiredDomain: String
    public let networkRequiredCode: Int

    public init(networkRequiredDomain: String, networkRequiredCode: Int) {
        self.networkRequiredDomain = networkRequiredDomain
        self.networkRequiredCode = networkRequiredCode
    }

    public func isNetworkAccessRequired(_ failure: FrameworkFailure?) -> Bool {
        failure?.domain == networkRequiredDomain && failure?.code == networkRequiredCode
    }
}

public enum TransferPhase: Equatable, Sendable {
    case probing
    case awaitingRetry
    case retrying
    case terminal
}

public enum MaterializationClass: String, Equatable, Sendable {
    case local
    case cloud
}

public enum TransferFailure: String, Error, Equatable, Sendable {
    case cancelled
    case emptySuccess
    case unexpectedProbeFailure
    case partialNetworkRequired
    case invalidProgress
    case missingProgress
    case transferFailure
    case oversizedChunk
    case resourceLimit
    case resourceMismatch
    case invalidTransition
    case authorizationChanged
    case outputIntegrity
    case protocolViolation
}

public enum TerminalResult: Equatable, Sendable {
    case completed(MaterializationClass)
    case failed(TransferFailure)
}

public enum CompletionDecision: Equatable, Sendable {
    case localComplete
    case retrySameResource
    case cloudComplete
    case terminalFailure(TransferFailure)
    case ignored
}

public struct RequestRegistration: Equatable, Sendable {
    public let requestID: Int32
    public let generation: UInt64
    public let cancelImmediately: Bool
}

public struct TransferStateMachine: Equatable, Sendable {
    public static let maximumChunkBytes = 1_048_576
    public static let maximumPendingCallbackBytes = 8 * maximumChunkBytes
    public static let maximumResourceBytes: Int64 = 512 * 1_024 * 1_024

    public private(set) var phase: TransferPhase = .probing
    public private(set) var generation: UInt64 = 1
    public private(set) var activeResourceToken: String
    public private(set) var acceptedBytes: Int64 = 0
    public private(set) var progressCallbackCount = 0
    public private(set) var lastProgress: Double?
    public private(set) var terminalResult: TerminalResult?
    public private(set) var terminalEmissionCount = 0
    public private(set) var cancelRequested = false

    private var requestIDs: [UInt64: Int32] = [:]

    public init(resourceToken: String) {
        self.activeResourceToken = resourceToken
    }

    public mutating func registerRequest(
        id: Int32,
        generation requestGeneration: UInt64
    ) -> RequestRegistration? {
        guard requestGeneration == generation else {
            return nil
        }
        requestIDs[requestGeneration] = id
        if cancelRequested {
            return RequestRegistration(
                requestID: id,
                generation: requestGeneration,
                cancelImmediately: true
            )
        }
        guard phase != .terminal else {
            requestIDs.removeValue(forKey: requestGeneration)
            return nil
        }
        return RequestRegistration(
            requestID: id,
            generation: requestGeneration,
            cancelImmediately: cancelRequested
        )
    }

    public mutating func cancel() -> [Int32] {
        guard phase != .terminal else {
            return []
        }
        cancelRequested = true
        let registered = requestIDs.values.sorted()
        finish(.failed(.cancelled))
        return registered
    }

    public mutating func acceptChunk(
        byteCount: Int,
        generation callbackGeneration: UInt64
    ) -> TransferFailure? {
        guard callbackGeneration == generation, phase == .probing || phase == .retrying else {
            return nil
        }
        guard byteCount > 0, byteCount <= Self.maximumChunkBytes else {
            finish(.failed(.oversizedChunk))
            return .oversizedChunk
        }
        guard acceptedBytes <= Self.maximumResourceBytes - Int64(byteCount) else {
            finish(.failed(.resourceLimit))
            return .resourceLimit
        }
        acceptedBytes += Int64(byteCount)
        return nil
    }

    public mutating func observeProgress(
        _ value: Double,
        generation callbackGeneration: UInt64
    ) -> TransferFailure? {
        guard callbackGeneration == generation, phase == .retrying else {
            return nil
        }
        guard value.isFinite, (0.0...1.0).contains(value), value >= (lastProgress ?? 0.0) else {
            finish(.failed(.invalidProgress))
            return .invalidProgress
        }
        lastProgress = value
        progressCallbackCount += 1
        return nil
    }

    public mutating func completeProbe(
        failure: FrameworkFailure?,
        errorIdentity: PhotoErrorIdentity,
        generation callbackGeneration: UInt64
    ) -> CompletionDecision {
        guard callbackGeneration == generation, phase == .probing, terminalResult == nil else {
            return .ignored
        }
        requestIDs.removeValue(forKey: callbackGeneration)

        if failure == nil {
            guard acceptedBytes > 0 else {
                finish(.failed(.emptySuccess))
                return .terminalFailure(.emptySuccess)
            }
            finish(.completed(.local))
            return .localComplete
        }

        if errorIdentity.isNetworkAccessRequired(failure) {
            guard acceptedBytes == 0 else {
                finish(.failed(.partialNetworkRequired))
                return .terminalFailure(.partialNetworkRequired)
            }
            phase = .awaitingRetry
            return .retrySameResource
        }

        finish(.failed(.unexpectedProbeFailure))
        return .terminalFailure(.unexpectedProbeFailure)
    }

    public mutating func beginRetry(resourceToken: String) -> Result<UInt64, TransferFailure> {
        guard phase == .awaitingRetry, terminalResult == nil else {
            return .failure(.invalidTransition)
        }
        guard resourceToken == activeResourceToken else {
            finish(.failed(.resourceMismatch))
            return .failure(.resourceMismatch)
        }
        generation += 1
        acceptedBytes = 0
        progressCallbackCount = 0
        lastProgress = nil
        phase = .retrying
        return .success(generation)
    }

    public mutating func completeRetry(
        failure: FrameworkFailure?,
        generation callbackGeneration: UInt64
    ) -> CompletionDecision {
        guard callbackGeneration == generation, phase == .retrying, terminalResult == nil else {
            return .ignored
        }
        requestIDs.removeValue(forKey: callbackGeneration)
        guard failure == nil else {
            finish(.failed(.transferFailure))
            return .terminalFailure(.transferFailure)
        }
        guard acceptedBytes > 0 else {
            finish(.failed(.emptySuccess))
            return .terminalFailure(.emptySuccess)
        }
        guard progressCallbackCount > 0 else {
            finish(.failed(.missingProgress))
            return .terminalFailure(.missingProgress)
        }
        finish(.completed(.cloud))
        return .cloudComplete
    }

    @discardableResult
    public mutating func fail(_ failure: TransferFailure) -> Bool {
        guard terminalResult == nil else {
            return false
        }
        finish(.failed(failure))
        return true
    }

    private mutating func finish(_ result: TerminalResult) {
        guard terminalResult == nil else {
            return
        }
        terminalResult = result
        terminalEmissionCount += 1
        phase = .terminal
    }
}
