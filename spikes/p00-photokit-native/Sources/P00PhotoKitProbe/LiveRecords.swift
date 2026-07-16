import Foundation
import P00PhotoKitCore

final class LiveRecordEmitter {
    private let nonce: String
    private let lock = NSLock()
    private var nextSequence = 1

    init(nonce: String) {
        self.nonce = nonce
    }

    func emit(_ event: LiveEvent) throws {
        lock.lock()
        defer { lock.unlock() }
        guard nextSequence <= 256 else {
            throw LiveEvidenceError.encoding
        }
        let line = try LiveEvidenceEncoder.line(
            nonce: nonce,
            sequence: nextSequence,
            event: event
        )
        FileHandle.standardOutput.write(line)
        nextSequence += 1
    }
}
