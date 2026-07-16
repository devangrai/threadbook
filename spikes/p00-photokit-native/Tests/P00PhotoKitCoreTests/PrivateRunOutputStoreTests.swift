import Foundation
import ImageIO
import XCTest
@testable import P00PhotoKitCore

final class PrivateRunOutputStoreTests: XCTestCase {
    private let png = Data(
        base64Encoded: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )!

    func testWritesVerifiedImageAndExactProvenanceDirectly() throws {
        try withStore { store, runDirectory in
            let fixture = fixtureForPNG()
            let evidence = evidence(for: fixture)
            let sink = try store.makeSink(outputName: "image.asset")
            try sink.append(png)
            let artifact = try sink.finalize(
                expected: fixture,
                expectedLength: Int64(png.count),
                expectedDimensions: ImageDimensions(width: 1, height: 1),
                provenanceName: "image.provenance.json",
                provenance: ProvenanceRecord(context: context, evidence: evidence)
            )
            XCTAssertEqual(artifact.sha256, fixture.sha256)
            XCTAssertEqual(artifact.length, Int64(png.count))
            XCTAssertEqual(artifact.dimensions, ImageDimensions(width: 1, height: 1))

            let blobURL = runDirectory.appendingPathComponent("image.asset")
            let provenanceURL = runDirectory.appendingPathComponent("image.provenance.json")
            XCTAssertEqual(try permissions(blobURL), 0o600)
            XCTAssertEqual(try permissions(provenanceURL), 0o600)
            let decoded = try JSONDecoder().decode(
                ProvenanceRecord.self,
                from: Data(contentsOf: provenanceURL)
            )
            XCTAssertEqual(decoded, ProvenanceRecord(context: context, evidence: evidence))
            XCTAssertEqual(
                try FileManager.default.contentsOfDirectory(atPath: runDirectory.path).sorted(),
                ["image.asset", "image.provenance.json"]
            )
        }
    }

    func testPreexistingAssetFailsExclusiveCreateAndIsUntouched() throws {
        try withStore { store, runDirectory in
            let output = runDirectory.appendingPathComponent("image.asset")
            let original = Data("preexisting".utf8)
            try original.write(to: output, options: .withoutOverwriting)
            let sink = try store.makeSink(outputName: "image.asset")

            XCTAssertThrowsError(try sink.append(png)) {
                XCTAssertEqual($0 as? ContentStoreError, .exclusiveCreate)
            }

            XCTAssertEqual(try Data(contentsOf: output), original)
            XCTAssertEqual(
                try FileManager.default.contentsOfDirectory(atPath: runDirectory.path),
                ["image.asset"]
            )
        }
    }

    func testDimensionFailureRetainsRequestedFinalAsset() throws {
        try withStore { store, runDirectory in
            let fixture = fixtureForPNG()
            let sink = try store.makeSink(outputName: "image.asset")
            try sink.append(png)
            XCTAssertThrowsError(
                try sink.finalize(
                    expected: fixture,
                    expectedLength: Int64(png.count),
                    expectedDimensions: ImageDimensions(width: 2, height: 1),
                    provenanceName: "image.provenance.json",
                    provenance: ProvenanceRecord(
                        context: context,
                        evidence: evidence(for: fixture)
                    )
                )
            ) {
                XCTAssertEqual($0 as? ContentStoreError, .dimensionMismatch)
            }
            sink.discard()
            let output = runDirectory.appendingPathComponent("image.asset")
            XCTAssertEqual(try Data(contentsOf: output), png)
            XCTAssertEqual(
                try FileManager.default.contentsOfDirectory(atPath: runDirectory.path),
                ["image.asset"]
            )
        }
    }

    func testDiscardClosesAndRetainsRequestedFinalName() throws {
        try withStore { store, runDirectory in
            let sink = try store.makeSink(outputName: "partial.asset")
            try sink.append(png)

            sink.discard()

            let output = runDirectory.appendingPathComponent("partial.asset")
            XCTAssertEqual(try Data(contentsOf: output), png)
            XCTAssertEqual(try permissions(output), 0o600)
        }
    }

    func testUnusedSinkDiscardCreatesNoArtifact() throws {
        try withStore { store, runDirectory in
            let sink = try store.makeSink(outputName: "unused.asset")

            sink.discard()

            XCTAssertEqual(
                try FileManager.default.contentsOfDirectory(atPath: runDirectory.path),
                []
            )
        }
    }

    func testRetainedPartialAssetsAreBoundedByPerRunSinkLimit() throws {
        try withStore { store, runDirectory in
            for value in 0..<PrivateRunOutputStore.maximumSinksPerRun {
                let sink = try store.makeSink(outputName: "partial-\(value).asset")
                try sink.append(Data([UInt8(value)]))
                sink.discard()
            }
            XCTAssertThrowsError(
                try store.makeSink(outputName: "partial-over-limit.asset")
            ) {
                XCTAssertEqual($0 as? ContentStoreError, .sinkLimit)
            }
            XCTAssertEqual(
                try FileManager.default.contentsOfDirectory(atPath: runDirectory.path).count,
                PrivateRunOutputStore.maximumSinksPerRun
            )
        }
    }

    func testMetadataBoundsAndFrameCountFailBeforeAcceptance() throws {
        XCTAssertThrowsError(
            try StreamingImageSink.validateMetadataDimensions(
                ImageDimensions(
                    width: PrivateRunOutputStore.pixelLimit + 1,
                    height: 1
                ),
                expectedDimensions: ImageDimensions(
                    width: PrivateRunOutputStore.pixelLimit + 1,
                    height: 1
                )
            )
        ) {
            XCTAssertEqual($0 as? ContentStoreError, .pixelLimit)
        }
        let allocationBound = Int(
            PrivateRunOutputStore.decodeAllocationLimit
                / PrivateRunOutputStore.maximumDecodedBytesPerPixel
        )
        XCTAssertThrowsError(
            try StreamingImageSink.validateMetadataDimensions(
                ImageDimensions(width: allocationBound + 1, height: 1),
                expectedDimensions: ImageDimensions(
                    width: allocationBound + 1,
                    height: 1
                )
            )
        ) {
            XCTAssertEqual($0 as? ContentStoreError, .allocationLimit)
        }

        let animated = try twoFrameGIF()
        try withStore { store, _ in
            let fixture = FixtureExpectation(
                fixtureID: "synthetic-animated-v1",
                sha256: AliasFactory.sha256Hex(animated),
                pixelWidth: 1,
                pixelHeight: 1
            )
            let sink = try store.makeSink(outputName: "animated.asset")
            try sink.append(animated)
            XCTAssertThrowsError(
                try sink.finalize(
                    expected: fixture,
                    expectedLength: Int64(animated.count),
                    expectedDimensions: ImageDimensions(width: 1, height: 1),
                    provenanceName: "animated.provenance.json",
                    provenance: ProvenanceRecord(
                        context: context,
                        evidence: evidence(for: fixture)
                    )
                )
            ) {
                XCTAssertEqual($0 as? ContentStoreError, .frameLimit)
            }
        }
    }

    func testRetainedRootDescriptorSurvivesPathReplacement() throws {
        try withTemporaryDirectory { parent in
            let run = parent.appendingPathComponent("run", isDirectory: true)
            let retained = parent.appendingPathComponent("retained", isDirectory: true)
            let store = try PrivateRunOutputStore(
                createFreshRunDirectory: run,
                capacityProvider: { _ in UInt64.max }
            )
            try FileManager.default.moveItem(at: run, to: retained)
            try FileManager.default.createDirectory(
                at: run,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )

            let fixture = fixtureForPNG()
            let sink = try store.makeSink(outputName: "image.asset")
            try sink.append(png)
            _ = try sink.finalize(
                expected: fixture,
                expectedLength: Int64(png.count),
                expectedDimensions: ImageDimensions(width: 1, height: 1),
                provenanceName: "image.provenance.json",
                provenance: ProvenanceRecord(
                    context: context,
                    evidence: evidence(for: fixture)
                )
            )

            XCTAssertTrue(
                FileManager.default.fileExists(
                    atPath: retained.appendingPathComponent("image.asset").path
                )
            )
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: run.path), [])
        }
    }

    func testFinalAssetPathReplacementFailsAndReplacementIsUntouched() throws {
        try withStore { store, runDirectory in
            let sink = try store.makeSink(outputName: "image.asset")
            try sink.append(png)
            let output = runDirectory.appendingPathComponent("image.asset")
            try FileManager.default.removeItem(at: output)
            let replacement = Data("preexisting replacement".utf8)
            try replacement.write(to: output, options: .withoutOverwriting)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: output.path
            )

            let fixture = fixtureForPNG()
            XCTAssertThrowsError(
                try sink.finalize(
                    expected: fixture,
                    expectedLength: Int64(png.count),
                    expectedDimensions: ImageDimensions(width: 1, height: 1),
                    provenanceName: "image.provenance.json",
                    provenance: ProvenanceRecord(
                        context: context,
                        evidence: evidence(for: fixture)
                    )
                )
            ) {
                XCTAssertEqual($0 as? ContentStoreError, .descriptorMismatch)
            }
            sink.discard()
            XCTAssertEqual(try Data(contentsOf: output), replacement)
            XCTAssertFalse(
                FileManager.default.fileExists(
                    atPath: runDirectory.appendingPathComponent(
                        "image.provenance.json"
                    ).path
                )
            )
        }
    }

    func testPreexistingProvenanceFailsAndBothFinalNamesAreRetained() throws {
        try withStore { store, runDirectory in
            let provenanceURL = runDirectory.appendingPathComponent(
                "image.provenance.json"
            )
            let preexisting = Data("preexisting provenance".utf8)
            try preexisting.write(to: provenanceURL, options: .withoutOverwriting)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: provenanceURL.path
            )

            let fixture = fixtureForPNG()
            let sink = try store.makeSink(outputName: "image.asset")
            try sink.append(png)
            XCTAssertThrowsError(
                try sink.finalize(
                    expected: fixture,
                    expectedLength: Int64(png.count),
                    expectedDimensions: ImageDimensions(width: 1, height: 1),
                    provenanceName: "image.provenance.json",
                    provenance: ProvenanceRecord(
                        context: context,
                        evidence: evidence(for: fixture)
                    )
                )
            ) {
                XCTAssertEqual($0 as? ContentStoreError, .provenance)
            }
            sink.discard()

            XCTAssertEqual(
                try Data(contentsOf: runDirectory.appendingPathComponent("image.asset")),
                png
            )
            XCTAssertEqual(try Data(contentsOf: provenanceURL), preexisting)
        }
    }

    func testTwoSuccessfulResourcesProduceExactlyFourFinalFiles() throws {
        try withStore { store, runDirectory in
            let fixture = fixtureForPNG()
            for value in ["local", "cloud"] {
                let sink = try store.makeSink(outputName: "\(value).asset")
                try sink.append(png)
                _ = try sink.finalize(
                    expected: fixture,
                    expectedLength: Int64(png.count),
                    expectedDimensions: ImageDimensions(width: 1, height: 1),
                    provenanceName: "\(value).provenance.json",
                    provenance: ProvenanceRecord(
                        context: context,
                        evidence: evidence(for: fixture)
                    )
                )
            }

            XCTAssertEqual(
                try FileManager.default.contentsOfDirectory(atPath: runDirectory.path).sorted(),
                [
                    "cloud.asset",
                    "cloud.provenance.json",
                    "local.asset",
                    "local.provenance.json",
                ]
            )
        }
    }

    func testReserveIncludesRemainingResourceAllowanceOnEveryAppend() throws {
        try withTemporaryDirectory { parent in
            let run = parent.appendingPathComponent("run", isDirectory: true)
            var checks = 0
            let fullRequirement = PrivateRunOutputStore.reserveFreeBytes
                + UInt64(TransferStateMachine.maximumResourceBytes)
            let store = try PrivateRunOutputStore(
                createFreshRunDirectory: run,
                capacityProvider: { _ in
                    defer { checks += 1 }
                    switch checks {
                    case 0, 1:
                        return fullRequirement
                    default:
                        return fullRequirement - 2
                    }
                }
            )
            let sink = try store.makeSink(outputName: "partial.asset")
            try sink.append(Data([0]))
            XCTAssertThrowsError(try sink.append(Data([1]))) {
                XCTAssertEqual($0 as? ContentStoreError, .insufficientSpace)
            }
            XCTAssertEqual(sink.byteCount, 1)
            XCTAssertEqual(checks, 3)
        }
    }

    func testRunDirectoryIsExclusiveAndMode0700() throws {
        try withTemporaryDirectory { parent in
            let run = parent.appendingPathComponent("fresh-run", isDirectory: true)
            _ = try PrivateRunOutputStore(createFreshRunDirectory: run)
            XCTAssertEqual(try permissions(run), 0o700)
            XCTAssertThrowsError(
                try PrivateRunOutputStore(createFreshRunDirectory: run)
            ) {
                XCTAssertEqual($0 as? ContentStoreError, .runAlreadyExists)
            }
        }
    }

    func testRootModeContinuityFailsClosed() throws {
        try withTemporaryDirectory { parent in
            let run = parent.appendingPathComponent("run", isDirectory: true)
            let store = try PrivateRunOutputStore(
                createFreshRunDirectory: run,
                capacityProvider: { _ in UInt64.max }
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o755],
                ofItemAtPath: run.path
            )
            XCTAssertThrowsError(try store.makeSink(outputName: "image.asset")) {
                XCTAssertEqual($0 as? ContentStoreError, .rootChanged)
            }
        }
    }

    private var context: LiveEvidenceContext {
        LiveEvidenceContext(
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
    }

    private func fixtureForPNG() -> FixtureExpectation {
        FixtureExpectation(
            fixtureID: "synthetic-local-v1",
            sha256: AliasFactory.sha256Hex(png),
            pixelWidth: 1,
            pixelHeight: 1
        )
    }

    private func evidence(for fixture: FixtureExpectation) -> CompletedResourceEvidence {
        CompletedResourceEvidence(
            role: .local,
            fixtureID: fixture.fixtureID,
            assetAlias: String(repeating: "3", count: 64),
            resourceAlias: String(repeating: "4", count: 64),
            blobSHA256: fixture.sha256,
            byteCount: Int64(png.count),
            pixelWidth: fixture.pixelWidth,
            pixelHeight: fixture.pixelHeight,
            progressCallbackCount: 0
        )
    }

    private func withStore(
        _ body: (PrivateRunOutputStore, URL) throws -> Void
    ) throws {
        try withTemporaryDirectory { parent in
            let run = parent.appendingPathComponent("run", isDirectory: true)
            let store = try PrivateRunOutputStore(
                createFreshRunDirectory: run,
                capacityProvider: { _ in UInt64.max }
            )
            try body(store, run)
        }
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(
            "p00-photokit-tests-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }

    private func permissions(_ url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try XCTUnwrap(attributes[.posixPermissions] as? NSNumber).intValue
    }

    private func retainedFiles(in directory: URL, prefix: String) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(atPath: directory.path)
            .filter { $0.hasPrefix(prefix) }
            .sorted()
            .map { directory.appendingPathComponent($0) }
    }

    private func twoFrameGIF() throws -> Data {
        let source = try XCTUnwrap(CGImageSourceCreateWithData(png as CFData, nil))
        let image = try XCTUnwrap(CGImageSourceCreateImageAtIndex(source, 0, nil))
        let output = NSMutableData()
        let destination = try XCTUnwrap(
            CGImageDestinationCreateWithData(
                output,
                "com.compuserve.gif" as CFString,
                2,
                nil
            )
        )
        CGImageDestinationAddImage(destination, image, nil)
        CGImageDestinationAddImage(destination, image, nil)
        XCTAssertTrue(CGImageDestinationFinalize(destination))
        return output as Data
    }
}
