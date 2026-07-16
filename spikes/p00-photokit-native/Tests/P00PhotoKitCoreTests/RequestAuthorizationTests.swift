import XCTest
@testable import P00PhotoKitCore

final class RequestAuthorizationTests: XCTestCase {
    func testNetworkRequestRechecksAuthorizationImmediatelyBeforeLaunch() {
        var order: [String] = []
        let result = NetworkRequestAuthorizationGate.perform(
            networkAllowed: true,
            authorizationIsExact: {
                order.append("authorization")
                return true
            },
            request: {
                order.append("request")
                return 42
            }
        )

        XCTAssertEqual(result, 42)
        XCTAssertEqual(order, ["authorization", "request"])
    }

    func testNetworkRequestIsNotLaunchedAfterAuthorizationRevocation() {
        var launched = false
        let result: Int? = NetworkRequestAuthorizationGate.perform(
            networkAllowed: true,
            authorizationIsExact: { false },
            request: {
                launched = true
                return 42
            }
        )

        XCTAssertNil(result)
        XCTAssertFalse(launched)
    }

    func testOfflineProbeDoesNotRequireNetworkAuthorizationGate() {
        var checked = false
        let result = NetworkRequestAuthorizationGate.perform(
            networkAllowed: false,
            authorizationIsExact: {
                checked = true
                return false
            },
            request: { 42 }
        )

        XCTAssertEqual(result, 42)
        XCTAssertFalse(checked)
    }
}
