import Darwin
import Foundation
import Photos
import WardrobePhotoKitObjC

enum ABIStatus: Int32 {
    case ok = 0
    case timeout = 1
    case closed = 2
    case invalid = 3
    case busy = 4
    case `internal` = 5
}

enum FrameKind: UInt32 {
    case control = 1
    case binary = 2
}

struct QueuedFrame {
    let kind: FrameKind
    let sequence: UInt64
    let bytes: Data
}

private struct OperationScope: Hashable {
    let operationID: UUID
    let enrollmentEpoch: UUID
    let reconciliationFence: UInt64
    let generation: UInt64

    init(_ identity: OperationIdentity) {
        operationID = identity.operationID
        enrollmentEpoch = identity.enrollmentEpoch
        reconciliationFence = identity.reconciliationFence
        generation = identity.generation
    }
}

private enum HandleLifecycle {
    case open
    case quiescing
    case quiesced
    case destroying
}

final class NativeOperation {
    let identity: OperationIdentity
    let kind: NativeCommandKind

    private let lock = NSLock()
    private weak var bridge: BridgeHandle?
    private var terminal = false
    private var cancelled = false
    private var cancellationAction: ((@escaping () -> Void) -> Void)?
    private var acceptedBytes = 0
    private var chunkIndex: UInt64 = 0
    private var lastProgressPercent = -1

    init(identity: OperationIdentity, kind: NativeCommandKind, bridge: BridgeHandle) {
        self.identity = identity
        self.kind = kind
        self.bridge = bridge
    }

    var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return terminal || cancelled
    }

    var byteCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return acceptedBytes
    }

    func installCancellation(
        _ action: @escaping (@escaping () -> Void) -> Void
    ) -> Bool {
        lock.lock()
        if terminal || cancelled {
            lock.unlock()
            action {}
            return false
        }
        cancellationAction = action
        lock.unlock()
        return true
    }

    func acceptCallbackBytes(_ callbackBytes: Data) -> Bool {
        guard !callbackBytes.isEmpty else {
            return true
        }

        let maximumPayload =
            Int(WK_PHOTOKIT_MAX_BINARY_V1) - NativeProtocol.binaryHeaderBytes
        return callbackBytes.withUnsafeBytes { source in
            guard let address = source.baseAddress else {
                return true
            }
            var offset = 0
            while offset < source.count {
                lock.lock()
                guard !terminal, !cancelled else {
                    lock.unlock()
                    return false
                }
                let remaining = source.count - offset
                let count = min(maximumPayload, remaining)
                guard acceptedBytes <= NativeProtocol.maximumResourceBytes - count else {
                    lock.unlock()
                    fail(reason: "resource_limit")
                    return false
                }
                let index = chunkIndex
                chunkIndex += 1
                acceptedBytes += count
                lock.unlock()

                // PhotoKit owns the callback buffer. Copy only the slice whose
                // frame is about to enter the backpressured queue.
                let chunk = Data(
                    bytes: address.advanced(by: offset),
                    count: count
                )
                guard
                    let frame = BinaryChunkEncoder.encode(
                        identity: identity,
                        chunkIndex: index,
                        bytes: chunk
                    ),
                    bridge?.enqueueBinary(frame, operation: self) == true
                else {
                    return false
                }
                offset += count
            }
            return true
        }
    }

    func emitProgress(_ value: Double) {
        guard value.isFinite, (0.0...1.0).contains(value) else {
            fail(reason: "invalid_progress")
            return
        }
        let percent = Int((value * 100.0).rounded(.down))
        lock.lock()
        guard !terminal, !cancelled, percent > lastProgressPercent else {
            lock.unlock()
            return
        }
        lastProgressPercent = percent
        lock.unlock()
        bridge?.emitControl(
            operation: self,
            event: "resource_progress",
            fields: ["percent": percent]
        )
    }

    func emit(event: String, fields: [String: Any] = [:]) {
        bridge?.emitControl(operation: self, event: event, fields: fields)
    }

    func retain(resource: PHAssetResource, token: String) -> Bool {
        bridge?.retain(resource: resource, token: token, identity: identity) == true
    }

    func retainedResource(token: String) -> PHAssetResource? {
        bridge?.retainedResource(token: token, identity: identity)
    }

    func complete(fields: [String: Any] = [:]) {
        finish(
            event: "operation_terminal",
            fields: ["status": "completed"].merging(fields) { _, new in new }
        )
    }

    func fail(reason: String) {
        stopAfterCancellation(
            event: "operation_terminal",
            fields: ["status": "failed", "reason": reason]
        )
    }

    func cancel() {
        stopAfterCancellation(
            event: "operation_terminal",
            fields: ["status": "failed", "reason": "cancelled"]
        )
    }

    private func stopAfterCancellation(event: String, fields: [String: Any]) {
        let action: ((@escaping () -> Void) -> Void)?
        lock.lock()
        guard !terminal, !cancelled else {
            lock.unlock()
            return
        }
        cancelled = true
        action = cancellationAction
        cancellationAction = nil
        lock.unlock()
        if let action {
            action { [self] in
                finish(event: event, fields: fields)
            }
        } else {
            finish(event: event, fields: fields)
        }
    }

    private func finish(event: String, fields: [String: Any]) {
        let owner: BridgeHandle?
        lock.lock()
        guard !terminal else {
            lock.unlock()
            return
        }
        terminal = true
        cancellationAction = nil
        owner = bridge
        lock.unlock()
        owner?.finish(operation: self, event: event, fields: fields)
    }
}

final class BridgeHandle {
    private let condition = NSCondition()
    private var lifecycle: HandleLifecycle = .open
    private var frames: [QueuedFrame] = []
    private var frameHead = 0
    private var pendingBinaryBytes = 0
    private var nextFrameSequence: UInt64 = 1
    private var consumerThreadID: UInt64?
    private var consumerActive = false
    private var activeABICalls = 0
    private var operations: [UUID: NativeOperation] = [:]
    private var activeTransfers = 0
    private var retainedResources: [OperationScope: [String: PHAssetResource]] = [:]
    private var retainedResourceCount = 0

    func beginABICall() -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard lifecycle != .destroying else {
            return false
        }
        activeABICalls += 1
        return true
    }

    func endABICall() {
        condition.lock()
        activeABICalls -= 1
        condition.broadcast()
        condition.unlock()
    }

    func send(_ data: Data) -> ABIStatus {
        condition.lock()
        guard lifecycle == .open else {
            condition.unlock()
            return .closed
        }
        guard operations.count < 4 else {
            condition.unlock()
            return .busy
        }
        condition.unlock()

        let command: NativeCommand
        switch StrictCommandDecoder.decode(data) {
        case let .success(decoded):
            command = decoded
        case .failure:
            return .invalid
        }

        if command.kind == .cancelOperation {
            return cancel(command.identity)
        }

        condition.lock()
        guard lifecycle == .open else {
            condition.unlock()
            return .closed
        }
        guard operations[command.identity.operationID] == nil else {
            condition.unlock()
            return .busy
        }
        if command.kind == .streamResource {
            guard activeTransfers < NativeProtocol.maximumConcurrentTransfers else {
                condition.unlock()
                return .busy
            }
            activeTransfers += 1
        } else if command.kind == .enumerateAlbum {
            retainedResources.removeAll(keepingCapacity: true)
            retainedResourceCount = 0
        }
        let operation = NativeOperation(
            identity: command.identity,
            kind: command.kind,
            bridge: self
        )
        operations[command.identity.operationID] = operation
        condition.unlock()

        PhotoKitCoordinator.shared.execute(command, operation: operation)
        return .ok
    }

    func next(timeoutMilliseconds: UInt32) -> (ABIStatus, QueuedFrame?) {
        guard !Thread.isMainThread else {
            return (.invalid, nil)
        }
        let threadID = currentThreadID()
        condition.lock()
        guard lifecycle == .open else {
            condition.unlock()
            return (.closed, nil)
        }
        if let registered = consumerThreadID {
            guard registered == threadID else {
                condition.unlock()
                return (.busy, nil)
            }
        } else {
            consumerThreadID = threadID
        }
        guard !consumerActive else {
            condition.unlock()
            return (.busy, nil)
        }
        consumerActive = true
        defer {
            consumerActive = false
            condition.broadcast()
            condition.unlock()
        }

        let deadline = Date(
            timeIntervalSinceNow: Double(timeoutMilliseconds) / 1_000.0
        )
        while frameHead >= frames.count {
            guard lifecycle == .open else {
                return (.closed, nil)
            }
            if timeoutMilliseconds == 0 || !condition.wait(until: deadline) {
                return (.timeout, nil)
            }
        }
        let frame = frames[frameHead]
        frameHead += 1
        if frame.kind == .binary {
            pendingBinaryBytes -= frame.bytes.count
        }
        compactQueueIfNeeded()
        condition.broadcast()
        return (.ok, frame)
    }

    func enqueueBinary(_ bytes: Data, operation: NativeOperation) -> Bool {
        guard bytes.count <= Int(WK_PHOTOKIT_MAX_BINARY_V1) else {
            return false
        }
        condition.lock()
        defer { condition.unlock() }
        while
            lifecycle == .open,
            !operation.isStopped,
            pendingBinaryBytes > NativeProtocol.maximumPendingBinaryBytes - bytes.count
        {
            condition.wait()
        }
        guard lifecycle == .open, !operation.isStopped else {
            return false
        }
        pendingBinaryBytes += bytes.count
        appendFrame(kind: .binary, bytes: bytes)
        return true
    }

    func retain(
        resource: PHAssetResource,
        token: String,
        identity: OperationIdentity
    ) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard
            lifecycle == .open,
            retainedResourceCount < NativeProtocol.maximumAssets,
            retainedResources[OperationScope(identity)]?[token] == nil
        else {
            return false
        }
        retainedResources[OperationScope(identity), default: [:]][token] = resource
        retainedResourceCount += 1
        return true
    }

    func retainedResource(
        token: String,
        identity: OperationIdentity
    ) -> PHAssetResource? {
        condition.lock()
        defer { condition.unlock() }
        guard lifecycle == .open else {
            return nil
        }
        return retainedResources[OperationScope(identity)]?[token]
    }

    func emitControl(
        operation: NativeOperation,
        event: String,
        fields: [String: Any] = [:]
    ) {
        guard
            let bytes = ControlEventEncoder.encode(
                identity: operation.identity,
                event: event,
                fields: fields
            )
        else {
            operation.fail(reason: "internal")
            return
        }
        condition.lock()
        let canAppend =
            lifecycle == .open
            && !operation.isStopped
            && frames.count - frameHead < 4_092
        if canAppend {
            appendFrame(kind: .control, bytes: bytes)
        }
        condition.unlock()
        if !canAppend, !operation.isStopped {
            operation.fail(reason: "queue_limit")
        }
    }

    func finish(
        operation: NativeOperation,
        event: String,
        fields: [String: Any]
    ) {
        let terminal = ControlEventEncoder.encode(
            identity: operation.identity,
            event: event,
            fields: fields
        )
        condition.lock()
        if lifecycle == .open, let terminal {
            appendFrame(kind: .control, bytes: terminal)
        }
        if operations.removeValue(forKey: operation.identity.operationID) != nil,
           operation.kind == .streamResource
        {
            activeTransfers -= 1
        }
        condition.broadcast()
        condition.unlock()
    }

    func quiesce(timeoutMilliseconds: UInt32) -> ABIStatus {
        guard !Thread.isMainThread else {
            return .invalid
        }
        condition.lock()
        if lifecycle == .quiesced {
            condition.unlock()
            return .ok
        }
        guard lifecycle == .open || lifecycle == .quiescing else {
            condition.unlock()
            return .closed
        }
        lifecycle = .quiescing
        frames.removeAll(keepingCapacity: false)
        frameHead = 0
        pendingBinaryBytes = 0
        retainedResources.removeAll(keepingCapacity: false)
        retainedResourceCount = 0
        let pendingOperations = Array(operations.values)
        condition.broadcast()
        condition.unlock()

        pendingOperations.forEach { $0.cancel() }

        condition.lock()
        let deadline = Date(
            timeIntervalSinceNow: Double(timeoutMilliseconds) / 1_000.0
        )
        while !operations.isEmpty {
            if timeoutMilliseconds == 0 || !condition.wait(until: deadline) {
                condition.unlock()
                return .timeout
            }
        }
        lifecycle = .quiesced
        condition.broadcast()
        condition.unlock()
        return .ok
    }

    func prepareDestroy() -> ABIStatus {
        condition.lock()
        defer { condition.unlock() }
        guard lifecycle == .quiesced else {
            return .busy
        }
        guard activeABICalls == 0, !consumerActive, operations.isEmpty else {
            return .busy
        }
        lifecycle = .destroying
        return .ok
    }

    private func cancel(_ identity: OperationIdentity) -> ABIStatus {
        condition.lock()
        guard lifecycle == .open else {
            condition.unlock()
            return .closed
        }
        guard
            let operation = operations[identity.operationID],
            operation.identity == identity
        else {
            condition.unlock()
            return .invalid
        }
        condition.unlock()
        operation.cancel()
        return .ok
    }

    private func appendFrame(kind: FrameKind, bytes: Data) {
        let sequence = nextFrameSequence
        let (next, overflow) = nextFrameSequence.addingReportingOverflow(1)
        guard !overflow else {
            lifecycle = .quiescing
            condition.broadcast()
            return
        }
        nextFrameSequence = next
        frames.append(QueuedFrame(kind: kind, sequence: sequence, bytes: bytes))
        condition.signal()
    }

    private func compactQueueIfNeeded() {
        if frameHead >= 256, frameHead * 2 >= frames.count {
            frames.removeFirst(frameHead)
            frameHead = 0
        }
    }
}

private func currentThreadID() -> UInt64 {
    var identifier: UInt64 = 0
    pthread_threadid_np(nil, &identifier)
    return identifier
}
