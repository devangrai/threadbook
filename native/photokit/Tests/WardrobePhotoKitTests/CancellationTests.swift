import Photos
import XCTest
@testable import WardrobePhotoKit

final class CancellationTests: XCTestCase {
    func testCancellationBeforeRequestRegistrationWaitsAndCancelsExactRequest() {
        var cancelled: [PHAssetResourceDataRequestID] = []
        var completed = false
        let cancellation = RequestCancellation {
            cancelled.append($0)
        }

        cancellation.request {
            completed = true
        }
        XCTAssertFalse(completed)
        XCTAssertTrue(cancelled.isEmpty)

        cancellation.register(requestID: 41)
        XCTAssertEqual(cancelled, [41])
        XCTAssertTrue(completed)
    }

    func testCancellationAfterRequestRegistrationCancelsImmediately() {
        var cancelled: [PHAssetResourceDataRequestID] = []
        var completed = false
        let cancellation = RequestCancellation {
            cancelled.append($0)
        }
        cancellation.register(requestID: 43)
        cancellation.request {
            completed = true
        }
        XCTAssertEqual(cancelled, [43])
        XCTAssertTrue(completed)
    }

    func testAbandoningUnregisteredRequestReleasesWaiterWithoutCancellation() {
        var cancelled: [PHAssetResourceDataRequestID] = []
        var completed = false
        let cancellation = RequestCancellation {
            cancelled.append($0)
        }
        cancellation.request {
            completed = true
        }
        cancellation.abandon()
        XCTAssertTrue(cancelled.isEmpty)
        XCTAssertTrue(completed)
    }
}
