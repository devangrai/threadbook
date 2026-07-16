import Foundation
import XCTest
@testable import P00PhotoKitCore

final class LiveEvidenceTests: XCTestCase {
    private let nonce = String(repeating: "a", count: 64)
    private let asset = String(repeating: "1", count: 64)
    private let resource = String(repeating: "2", count: 64)

    func testAliasesAreNonceKeyedDomainSeparatedHMACValues() {
        let aliases = AliasFactory(nonce: nonce)
        let assetAlias = aliases.assetAlias(localIdentifier: "asset")
        let resourceAlias = aliases.resourceAlias(binding: "asset")
        let otherRunAsset = AliasFactory(
            nonce: String(repeating: "b", count: 64)
        ).assetAlias(localIdentifier: "asset")
        XCTAssertTrue(LiveChallenge.isLowerSHA256(assetAlias))
        XCTAssertTrue(LiveChallenge.isLowerSHA256(resourceAlias))
        XCTAssertNotEqual(assetAlias, resourceAlias)
        XCTAssertNotEqual(assetAlias, otherRunAsset)
        XCTAssertEqual(
            assetAlias,
            aliases.runAlias(context: "asset-v1", value: "asset")
        )
    }

    func testExactEvaluatorEventShapesAndSequence() throws {
        let cases: [(LiveEvent, Set<String>)] = [
            (.authorizationGranted, []),
            (.resourceSelected(assetAlias: asset, resourceAlias: resource),
             ["asset_alias", "resource_alias"]),
            (.probeStarted(assetAlias: asset, resourceAlias: resource),
             ["asset_alias", "resource_alias", "network_allowed"]),
            (.probeNetworkRequired(assetAlias: asset, resourceAlias: resource),
             ["asset_alias", "resource_alias", "network_allowed"]),
            (.retryStarted(assetAlias: asset, resourceAlias: resource),
             ["asset_alias", "resource_alias", "network_allowed"]),
            (.transferProgress(assetAlias: asset, resourceAlias: resource, permille: 200),
             ["asset_alias", "resource_alias", "progress_permille"]),
            (.assetCompleted(completed),
             [
                "asset_alias", "resource_alias", "byte_count",
                "progress_callback_count", "residency", "outcome",
             ]),
            (.sessionCompleted, ["outcome"]),
        ]
        let common: Set<String> = [
            "schema_version", "scenario", "challenge_nonce", "sequence", "event",
        ]
        for (offset, item) in cases.enumerated() {
            let record = try decode(
                LiveEvidenceEncoder.line(
                    nonce: nonce,
                    sequence: offset + 1,
                    event: item.0
                )
            )
            XCTAssertEqual(Set(record.keys), common.union(item.1))
            XCTAssertEqual(record["sequence"] as? Int, offset + 1)
            XCTAssertEqual(record["challenge_nonce"] as? String, nonce)
            XCTAssertEqual(record["scenario"] as? String, "p00_photokit_native_live")
        }
    }

    func testProvenanceMatchesRequiredExactSchema() throws {
        let context = LiveEvidenceContext(
            runID: "p00-" + String(repeating: "b", count: 32),
            harnessRunID: "20260714T224112Z-5d6bbee6",
            sourceFingerprint: String(repeating: "c", count: 64),
            executableSHA256: String(repeating: "d", count: 64),
            bundleID: "com.wardrobe.p00-photokit-native",
            nonpersonalProvenance:
                "dedicated_nonpersonal_synthetic_photos_library_v1",
            connectorInstance: String(repeating: "e", count: 64),
            connectorGeneration: String(repeating: "9", count: 64)
        )
        let data = try JSONEncoder().encode(
            ProvenanceRecord(context: context, evidence: completed)
        )
        let record = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        XCTAssertEqual(
            Set(record.keys),
            [
                "schema_version", "run_id", "harness_run_id",
                "source_fingerprint", "executable_sha256", "bundle_id",
                "fixture_role", "fixture_id", "nonpersonal_provenance",
                "connector_instance", "connector_generation",
                "asset_alias", "resource_alias", "representation_policy",
                "residency", "blob_sha256", "byte_count", "pixel_width",
                "pixel_height",
            ]
        )
        XCTAssertEqual(
            record["connector_instance"] as? String,
            context.connectorInstance
        )
        XCTAssertEqual(
            record["connector_generation"] as? String,
            context.connectorGeneration
        )
    }

    func testChallengeContextBindingsAreRunBoundAndPrivacySafe() throws {
        let first = try LiveChallenge(
            evidenceNonce: nonce,
            rawJSON: challengeJSON(nonce: nonce)
        )
        let secondNonce = String(repeating: "b", count: 64)
        let second = try LiveChallenge(
            evidenceNonce: secondNonce,
            rawJSON: challengeJSON(nonce: secondNonce)
        )
        let firstContext = LiveEvidenceContext(challenge: first)
        let secondContext = LiveEvidenceContext(challenge: second)

        XCTAssertTrue(LiveChallenge.isLowerSHA256(firstContext.connectorInstance))
        XCTAssertTrue(LiveChallenge.isLowerSHA256(firstContext.connectorGeneration))
        XCTAssertNotEqual(firstContext.connectorInstance, secondContext.connectorInstance)
        XCTAssertNotEqual(firstContext.connectorGeneration, secondContext.connectorGeneration)
        XCTAssertFalse(firstContext.connectorInstance.contains(first.outputContract.bundleID))
        XCTAssertFalse(
            firstContext.connectorGeneration.contains(first.nonpersonalProvenance)
        )
    }

    private var completed: CompletedResourceEvidence {
        CompletedResourceEvidence(
            role: .cloud,
            fixtureID: "synthetic-cloud-v1",
            assetAlias: asset,
            resourceAlias: resource,
            blobSHA256: String(repeating: "f", count: 64),
            byteCount: 19,
            pixelWidth: 4,
            pixelHeight: 5,
            progressCallbackCount: 3
        )
    }

    private func decode(_ line: Data) throws -> [String: Any] {
        let prefix = Data(LiveEvidenceEncoder.prefix.utf8)
        XCTAssertTrue(line.starts(with: prefix))
        return try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(line.dropFirst(prefix.count).dropLast())
            ) as? [String: Any]
        )
    }

    private func challengeJSON(nonce: String) -> String {
        """
        {
          "schema_version": 1,
          "nonce": "\(nonce)",
          "run_id": "p00-\(String(repeating: "b", count: 32))",
          "harness_run_id": "20260714T224112Z-5d6bbee6",
          "source_fingerprint": "\(String(repeating: "c", count: 64))",
          "executable_sha256": "\(String(repeating: "d", count: 64))",
          "nonpersonal_provenance": "dedicated_nonpersonal_synthetic_photos_library_v1",
          "output_contract": {
            "kind": "sandbox_container_v1",
            "bundle_id": "com.wardrobe.p00-photokit-native",
            "relative_directory": "Library/Application Support/P00PhotoKitNative/p00-\(String(repeating: "b", count: 32))",
            "must_not_exist": true,
            "asset_suffix": ".asset",
            "provenance_suffix": ".provenance.json"
          },
          "local": {
            "fixture_id": "synthetic-local-v1",
            "sha256": "\(String(repeating: "1", count: 64))",
            "pixel_width": 1,
            "pixel_height": 1
          },
          "cloud": {
            "fixture_id": "synthetic-cloud-v1",
            "sha256": "\(String(repeating: "2", count: 64))",
            "pixel_width": 1,
            "pixel_height": 1
          }
        }
        """
    }
}
