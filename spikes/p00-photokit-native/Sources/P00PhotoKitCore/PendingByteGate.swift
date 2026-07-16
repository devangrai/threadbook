import Foundation

public final class PendingByteGate: @unchecked Sendable {
    public let limit: Int

    private let condition = NSCondition()
    private var pending = 0
    private var closed = false
    public private(set) var peakPendingBytes = 0

    public init(limit: Int) {
        precondition(limit > 0)
        self.limit = limit
    }

    public func acquire(_ byteCount: Int) -> Bool {
        guard byteCount > 0, byteCount <= limit else {
            return false
        }
        condition.lock()
        defer { condition.unlock() }
        while !closed && pending > limit - byteCount {
            condition.wait()
        }
        guard !closed else {
            return false
        }
        pending += byteCount
        peakPendingBytes = max(peakPendingBytes, pending)
        return true
    }

    public func release(_ byteCount: Int) {
        condition.lock()
        pending = max(0, pending - byteCount)
        condition.broadcast()
        condition.unlock()
    }

    public func close() {
        condition.lock()
        closed = true
        condition.broadcast()
        condition.unlock()
    }

    public var pendingBytes: Int {
        condition.lock()
        defer { condition.unlock() }
        return pending
    }
}
