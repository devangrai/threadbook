import Dispatch
import XCTest
@testable import P00PhotoKitCore

final class PendingByteGateTests: XCTestCase {
    func testProductionPendingLimitIsEightBoundedChunks() {
        XCTAssertEqual(
            TransferStateMachine.maximumPendingCallbackBytes,
            8 * TransferStateMachine.maximumChunkBytes
        )
    }

    func testHardLimitBlocksUntilBytesAreReleased() {
        let gate = PendingByteGate(limit: 2)
        XCTAssertTrue(gate.acquire(2))

        let started = DispatchSemaphore(value: 0)
        let acquired = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            started.signal()
            if gate.acquire(1) {
                acquired.signal()
            }
        }
        XCTAssertEqual(started.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(acquired.wait(timeout: .now() + 0.05), .timedOut)
        XCTAssertEqual(gate.pendingBytes, 2)
        XCTAssertEqual(gate.peakPendingBytes, 2)

        gate.release(2)
        XCTAssertEqual(acquired.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(gate.pendingBytes, 1)
        gate.release(1)
    }

    func testCloseWakesBlockedAcquirerWithoutExceedingLimit() {
        let gate = PendingByteGate(limit: 1)
        XCTAssertTrue(gate.acquire(1))
        let finished = DispatchSemaphore(value: 0)
        let resultLock = NSLock()
        var acquired = true
        DispatchQueue.global().async {
            let result = gate.acquire(1)
            resultLock.lock()
            acquired = result
            resultLock.unlock()
            finished.signal()
        }
        gate.close()
        XCTAssertEqual(finished.wait(timeout: .now() + 1), .success)
        resultLock.lock()
        XCTAssertFalse(acquired)
        resultLock.unlock()
        gate.release(1)
    }
}
