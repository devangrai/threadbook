import Foundation
import XCTest
@testable import P00PhotoKitCore

final class ChallengeTests: XCTestCase {
    private let nonce = String(repeating: "a", count: 64)

    func testParsesExactEvaluatorGeneratedRuntimeChallenge() throws {
        let challenge = try LiveChallenge(
            evidenceNonce: nonce,
            rawJSON: try encode(runtimeChallenge())
        )
        XCTAssertEqual(challenge.nonce, nonce)
        XCTAssertEqual(challenge.runID, "p00-" + String(repeating: "b", count: 32))
        XCTAssertEqual(challenge.harnessRunID, "20260714T224112Z-5d6bbee6")
        XCTAssertEqual(challenge.sourceFingerprint, String(repeating: "c", count: 64))
        XCTAssertEqual(challenge.executableSHA256, String(repeating: "d", count: 64))
        XCTAssertEqual(challenge.local.fixtureID, "synthetic-local-v1")
        XCTAssertEqual(challenge.local.pixelWidth, 2)
        XCTAssertEqual(challenge.cloud.pixelHeight, 5)
        XCTAssertEqual(challenge.outputContract.assetSuffix, ".asset")
        XCTAssertTrue(challenge.outputContract.mustNotExist)
    }

    func testRejectsMissingExtraAndNestedExtraFields() throws {
        var value = runtimeChallenge()
        value["challenge_id"] = "obsolete"
        XCTAssertThrowsError(
            try LiveChallenge(evidenceNonce: nonce, rawJSON: try encode(value))
        )

        value = runtimeChallenge()
        value.removeValue(forKey: "source_fingerprint")
        XCTAssertThrowsError(
            try LiveChallenge(evidenceNonce: nonce, rawJSON: try encode(value))
        )

        value = runtimeChallenge()
        var local = try XCTUnwrap(value["local"] as? [String: Any])
        local["blob_length"] = 1
        value["local"] = local
        XCTAssertThrowsError(
            try LiveChallenge(evidenceNonce: nonce, rawJSON: try encode(value))
        )
    }

    func testRejectsNonceMismatchAndMutatedOutputContract() throws {
        XCTAssertThrowsError(
            try LiveChallenge(
                evidenceNonce: String(repeating: "0", count: 64),
                rawJSON: try encode(runtimeChallenge())
            )
        )
        var value = runtimeChallenge()
        var output = try XCTUnwrap(value["output_contract"] as? [String: Any])
        output["relative_directory"] = "/tmp/operator-chosen"
        value["output_contract"] = output
        XCTAssertThrowsError(
            try LiveChallenge(evidenceNonce: nonce, rawJSON: try encode(value))
        )
    }

    private func encode(_ object: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return try XCTUnwrap(String(data: data, encoding: .utf8))
    }

    // Literal output of evaluator make_runtime_challenge using its test constants.
    private func runtimeChallenge() -> [String: Any] {
        let runID = "p00-" + String(repeating: "b", count: 32)
        return [
            "schema_version": 1,
            "nonce": nonce,
            "run_id": runID,
            "harness_run_id": "20260714T224112Z-5d6bbee6",
            "source_fingerprint": String(repeating: "c", count: 64),
            "executable_sha256": String(repeating: "d", count: 64),
            "nonpersonal_provenance":
                "dedicated_nonpersonal_synthetic_photos_library_v1",
            "output_contract": [
                "kind": "sandbox_container_v1",
                "bundle_id": "com.wardrobe.p00-photokit-native",
                "relative_directory":
                    "Library/Application Support/P00PhotoKitNative/\(runID)",
                "must_not_exist": true,
                "asset_suffix": ".asset",
                "provenance_suffix": ".provenance.json",
            ],
            "local": [
                "fixture_id": "synthetic-local-v1",
                "sha256": String(repeating: "e", count: 64),
                "pixel_width": 2,
                "pixel_height": 3,
            ],
            "cloud": [
                "fixture_id": "synthetic-cloud-v1",
                "sha256": String(repeating: "f", count: 64),
                "pixel_width": 4,
                "pixel_height": 5,
            ],
        ]
    }
}
