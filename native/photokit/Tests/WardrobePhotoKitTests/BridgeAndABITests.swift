import Foundation
import WardrobePhotoKitObjC
import XCTest
@testable import WardrobePhotoKit

final class BridgeAndABITests: XCTestCase {
    func testCallbackBytesAreCopiedAndSplitIntoOwnedFrames() throws {
        let handle = BridgeHandle()
        let operation = NativeOperation(
            identity: identity(),
            kind: .streamResource,
            bridge: handle
        )
        let mutable = NSMutableData(data: Data(repeating: 0x2a, count: 32))
        XCTAssertTrue(operation.acceptCallbackBytes(mutable as Data))
        memset(mutable.mutableBytes, 0, mutable.length)

        let result = onThread {
            handle.next(timeoutMilliseconds: 100)
        }
        XCTAssertEqual(result.0, .ok)
        let frame = try XCTUnwrap(result.1)
        XCTAssertEqual(frame.kind, .binary)
        XCTAssertEqual(frame.bytes.suffix(32), Data(repeating: 0x2a, count: 32))
    }

    func testOversizedCallbackIsSplitIntoBoundedOwnedFrames() throws {
        let handle = BridgeHandle()
        let operation = NativeOperation(
            identity: identity(),
            kind: .streamResource,
            bridge: handle
        )
        let maximumPayload =
            Int(WK_PHOTOKIT_MAX_BINARY_V1) - NativeProtocol.binaryHeaderBytes
        var expected = Data(count: maximumPayload * 2 + 17)
        expected.withUnsafeMutableBytes { bytes in
            for offset in bytes.indices {
                bytes[offset] = UInt8(truncatingIfNeeded: offset)
            }
        }
        let callbackStorage = NSMutableData(data: expected)

        XCTAssertTrue(operation.acceptCallbackBytes(callbackStorage as Data))
        memset(callbackStorage.mutableBytes, 0, callbackStorage.length)

        let results = onThread {
            [
                handle.next(timeoutMilliseconds: 100),
                handle.next(timeoutMilliseconds: 100),
                handle.next(timeoutMilliseconds: 100),
            ]
        }
        var reconstructed = Data()
        for result in results {
            XCTAssertEqual(result.0, .ok)
            let frame = try XCTUnwrap(result.1)
            XCTAssertEqual(frame.kind, .binary)
            XCTAssertLessThanOrEqual(
                frame.bytes.count,
                Int(WK_PHOTOKIT_MAX_BINARY_V1)
            )
            reconstructed.append(frame.bytes.dropFirst(NativeProtocol.binaryHeaderBytes))
        }
        XCTAssertEqual(
            results.map { $0.1?.bytes.count },
            [
                Int(WK_PHOTOKIT_MAX_BINARY_V1),
                Int(WK_PHOTOKIT_MAX_BINARY_V1),
                NativeProtocol.binaryHeaderBytes + 17,
            ]
        )
        XCTAssertEqual(reconstructed, expected)
    }

    func testSingleConsumerAffinityRejectsSecondThread() {
        let handle = BridgeHandle()
        let firstReady = DispatchSemaphore(value: 0)
        let releaseFirst = DispatchSemaphore(value: 0)
        let firstDone = expectation(description: "first")
        let secondDone = expectation(description: "second")
        var firstStatus: ABIStatus?
        var secondStatus: ABIStatus?

        let first = Thread {
            firstStatus = handle.next(timeoutMilliseconds: 0).0
            firstReady.signal()
            releaseFirst.wait()
            firstDone.fulfill()
        }
        first.start()
        firstReady.wait()
        let second = Thread {
            secondStatus = handle.next(timeoutMilliseconds: 0).0
            secondDone.fulfill()
        }
        second.start()
        wait(for: [secondDone], timeout: 2)
        releaseFirst.signal()
        wait(for: [firstDone], timeout: 2)
        XCTAssertEqual(firstStatus, .timeout)
        XCTAssertEqual(secondStatus, .busy)
    }

    func testCABILifecycleNullsOutputsAndRequiresQuiescence() {
        var handle: OpaquePointer?
        XCTAssertEqual(
            wkPhotoKitCreateV1(UInt32(WK_PHOTOKIT_ABI_V1), &handle),
            ABIStatus.ok.rawValue
        )
        XCTAssertNotNil(handle)
        var frame = UnsafeMutableRawPointer(bitPattern: 1)
        XCTAssertEqual(
            wkPhotoKitNextV1(handle, 0, &frame),
            ABIStatus.invalid.rawValue
        )
        XCTAssertNil(frame)
        XCTAssertEqual(
            wkPhotoKitDestroyV1(&handle),
            ABIStatus.busy.rawValue
        )
        XCTAssertEqual(
            onThread { wkPhotoKitQuiesceV1(handle, 1_000) },
            ABIStatus.ok.rawValue
        )
        XCTAssertEqual(
            wkPhotoKitDestroyV1(&handle),
            ABIStatus.ok.rawValue
        )
        XCTAssertNil(handle)
    }

    func testTerminalIsEmittedExactlyOnceAndQueueClosesOnQuiesce() throws {
        let handle = BridgeHandle()
        let operation = NativeOperation(
            identity: identity(),
            kind: .enumerateAlbum,
            bridge: handle
        )
        operation.emit(event: "asset", fields: ["supported": true])
        operation.complete(fields: ["asset_count": 1])
        operation.complete(fields: ["asset_count": 2])

        let drained = onThread {
            [
                handle.next(timeoutMilliseconds: 100),
                handle.next(timeoutMilliseconds: 100),
                handle.next(timeoutMilliseconds: 0),
            ]
        }
        XCTAssertEqual(drained[0].0, .ok)
        XCTAssertEqual(drained[1].0, .ok)
        XCTAssertEqual(drained[2].0, .timeout)
        let terminalData = try XCTUnwrap(drained[1].1?.bytes)
        let terminal = try XCTUnwrap(
            JSONSerialization.jsonObject(with: terminalData) as? [String: Any]
        )
        XCTAssertEqual(terminal["event"] as? String, "operation_terminal")
        XCTAssertEqual(terminal["status"] as? String, "completed")

        XCTAssertEqual(
            onThread { handle.quiesce(timeoutMilliseconds: 1_000) },
            .ok
        )
        XCTAssertEqual(onThread { handle.next(timeoutMilliseconds: 0) }.0, .closed)
    }

    func testCABIRejectsExactPointerAndLengthViolations() {
        var handle: OpaquePointer?
        XCTAssertEqual(
            wkPhotoKitCreateV1(UInt32(WK_PHOTOKIT_ABI_V1), &handle),
            ABIStatus.ok.rawValue
        )
        var byte: UInt8 = 0
        XCTAssertEqual(
            wkPhotoKitSendV1(handle, nil, 1),
            ABIStatus.invalid.rawValue
        )
        XCTAssertEqual(
            wkPhotoKitSendV1(handle, &byte, 0),
            ABIStatus.invalid.rawValue
        )
        XCTAssertEqual(
            wkPhotoKitSendV1(
                handle,
                &byte,
                Int(WK_PHOTOKIT_MAX_CONTROL_V1) + 1
            ),
            ABIStatus.invalid.rawValue
        )
        XCTAssertEqual(
            onThread { wkPhotoKitQuiesceV1(handle, 1_000) },
            ABIStatus.ok.rawValue
        )
        XCTAssertEqual(wkPhotoKitDestroyV1(&handle), ABIStatus.ok.rawValue)
    }

    func testObjectiveCExceptionsAreContainedWithoutText() {
        XCTAssertTrue(wk_photokit_objc_test_exception_containment())
    }

    private func identity() -> OperationIdentity {
        OperationIdentity(
            operationID: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
            enrollmentEpoch: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!,
            reconciliationFence: 1,
            generation: 1,
            requestSequence: 1
        )
    }

    private func onThread<T>(_ body: @escaping () -> T) -> T {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: T?
        let thread = Thread {
            let value = body()
            lock.lock()
            result = value
            lock.unlock()
            semaphore.signal()
        }
        thread.start()
        XCTAssertEqual(semaphore.wait(timeout: .now() + 5), .success)
        lock.lock()
        defer { lock.unlock() }
        return result!
    }
}
