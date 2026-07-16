import XCTest
@testable import P00PhotoKitCore

final class TransferStateTests: XCTestCase {
    private let errors = PhotoErrorIdentity(
        networkRequiredDomain: "PHPhotosErrorDomain",
        networkRequiredCode: 3164
    )

    func testLocalProbeCompletesExactlyOnceAfterNonemptyData() {
        var state = TransferStateMachine(resourceToken: "same")
        XCTAssertNil(state.acceptChunk(byteCount: 128, generation: 1))
        XCTAssertEqual(
            state.completeProbe(failure: nil, errorIdentity: errors, generation: 1),
            .localComplete
        )
        XCTAssertEqual(
            state.completeProbe(failure: nil, errorIdentity: errors, generation: 1),
            .ignored
        )
        XCTAssertEqual(state.terminalResult, .completed(.local))
        XCTAssertEqual(state.terminalEmissionCount, 1)
    }

    func testExactNetworkRequiredRetriesSameResourceWithEmpiricalProgress() throws {
        var state = TransferStateMachine(resourceToken: "same")
        XCTAssertEqual(
            state.completeProbe(
                failure: FrameworkFailure(domain: "PHPhotosErrorDomain", code: 3164),
                errorIdentity: errors,
                generation: 1
            ),
            .retrySameResource
        )
        XCTAssertEqual(try state.beginRetry(resourceToken: "same").get(), 2)
        XCTAssertNil(state.observeProgress(0.25, generation: 2))
        XCTAssertNil(state.observeProgress(1.0, generation: 2))
        XCTAssertNil(state.acceptChunk(byteCount: 512, generation: 2))
        XCTAssertEqual(state.completeRetry(failure: nil, generation: 2), .cloudComplete)
        XCTAssertEqual(state.progressCallbackCount, 2)
        XCTAssertEqual(state.terminalResult, .completed(.cloud))
    }

    func testWrongDomainOrCodeNeverClassifiesCloud() {
        for failure in [
            FrameworkFailure(domain: "OtherDomain", code: 3164),
            FrameworkFailure(domain: "PHPhotosErrorDomain", code: 999),
        ] {
            var state = TransferStateMachine(resourceToken: "same")
            XCTAssertEqual(
                state.completeProbe(failure: failure, errorIdentity: errors, generation: 1),
                .terminalFailure(.unexpectedProbeFailure)
            )
        }
    }

    func testNetworkRequiredAfterAnyAcceptedByteFailsClosed() {
        var state = TransferStateMachine(resourceToken: "same")
        XCTAssertNil(state.acceptChunk(byteCount: 1, generation: 1))
        XCTAssertEqual(
            state.completeProbe(
                failure: FrameworkFailure(domain: "PHPhotosErrorDomain", code: 3164),
                errorIdentity: errors,
                generation: 1
            ),
            .terminalFailure(.partialNetworkRequired)
        )
    }

    func testCloudRetryRequiresProgressAndNonemptyData() throws {
        var noProgress = TransferStateMachine(resourceToken: "same")
        _ = noProgress.completeProbe(
            failure: FrameworkFailure(domain: "PHPhotosErrorDomain", code: 3164),
            errorIdentity: errors,
            generation: 1
        )
        _ = try noProgress.beginRetry(resourceToken: "same").get()
        XCTAssertNil(noProgress.acceptChunk(byteCount: 8, generation: 2))
        XCTAssertEqual(
            noProgress.completeRetry(failure: nil, generation: 2),
            .terminalFailure(.missingProgress)
        )

        var empty = TransferStateMachine(resourceToken: "same")
        _ = empty.completeProbe(
            failure: FrameworkFailure(domain: "PHPhotosErrorDomain", code: 3164),
            errorIdentity: errors,
            generation: 1
        )
        _ = try empty.beginRetry(resourceToken: "same").get()
        XCTAssertNil(empty.observeProgress(0.5, generation: 2))
        XCTAssertEqual(
            empty.completeRetry(failure: nil, generation: 2),
            .terminalFailure(.emptySuccess)
        )
    }

    func testRegressingNonfiniteAndOutOfRangeProgressFail() throws {
        for values in [[0.5, 0.4], [Double.nan], [-0.1], [1.1]] {
            var state = retryingState()
            var observedFailure: TransferFailure?
            for value in values {
                observedFailure = state.observeProgress(value, generation: 2) ?? observedFailure
            }
            XCTAssertEqual(observedFailure, .invalidProgress)
            XCTAssertEqual(state.terminalEmissionCount, 1)
        }
    }

    func testCancelBeforeRegistrationAppliesFenceToLateRegistration() {
        var state = TransferStateMachine(resourceToken: "same")
        XCTAssertEqual(state.cancel(), [])
        XCTAssertEqual(state.registerRequest(id: 41, generation: 1)?.cancelImmediately, true)
        XCTAssertEqual(state.terminalResult, .failed(.cancelled))
        XCTAssertEqual(state.terminalEmissionCount, 1)
    }

    func testRegisteredRequestIsReturnedByCancellation() {
        var state = TransferStateMachine(resourceToken: "same")
        let registration = state.registerRequest(id: 42, generation: 1)
        XCTAssertEqual(registration?.cancelImmediately, false)
        XCTAssertEqual(state.cancel(), [42])
        XCTAssertEqual(state.cancel(), [])
    }

    func testStaleCallbacksAreIgnoredAfterRetryGenerationAdvances() throws {
        var state = retryingState()
        XCTAssertNil(state.acceptChunk(byteCount: 32, generation: 1))
        XCTAssertNil(state.observeProgress(0.8, generation: 1))
        XCTAssertEqual(
            state.completeProbe(failure: nil, errorIdentity: errors, generation: 1),
            .ignored
        )
        XCTAssertEqual(state.acceptedBytes, 0)
        XCTAssertEqual(state.progressCallbackCount, 0)
    }

    func testRetryCannotSwitchResource() {
        var state = TransferStateMachine(resourceToken: "same")
        _ = state.completeProbe(
            failure: FrameworkFailure(domain: "PHPhotosErrorDomain", code: 3164),
            errorIdentity: errors,
            generation: 1
        )
        XCTAssertThrowsError(try state.beginRetry(resourceToken: "different").get()) {
            XCTAssertEqual($0 as? TransferFailure, .resourceMismatch)
        }
        XCTAssertEqual(state.terminalResult, .failed(.resourceMismatch))
    }

    func testChunkAndResourceBoundsAreEnforced() {
        var chunk = TransferStateMachine(resourceToken: "same")
        XCTAssertEqual(
            chunk.acceptChunk(
                byteCount: TransferStateMachine.maximumChunkBytes + 1,
                generation: 1
            ),
            .oversizedChunk
        )

        var resource = TransferStateMachine(resourceToken: "same")
        let oneMiB = TransferStateMachine.maximumChunkBytes
        for _ in 0..<512 {
            XCTAssertNil(resource.acceptChunk(byteCount: oneMiB, generation: 1))
        }
        XCTAssertEqual(resource.acceptChunk(byteCount: 1, generation: 1), .resourceLimit)
    }

    private func retryingState() -> TransferStateMachine {
        var state = TransferStateMachine(resourceToken: "same")
        _ = state.completeProbe(
            failure: FrameworkFailure(domain: "PHPhotosErrorDomain", code: 3164),
            errorIdentity: errors,
            generation: 1
        )
        _ = state.beginRetry(resourceToken: "same")
        return state
    }
}
