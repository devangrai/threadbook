import XCTest
@testable import P00PhotoKitCore

final class ResourceSelectionTests: XCTestCase {
    private let jpeg = ResourceCandidate(
        token: "resource-a",
        kind: .originalPhoto,
        uniformTypeIdentifier: "public.jpeg"
    )

    func testSelectsOneAllowlistedOriginalStillImage() throws {
        let result = OriginalPrimaryResourcePolicy.select(
            assetKind: .image,
            isLivePhoto: false,
            candidates: [jpeg]
        )
        XCTAssertEqual(try result.get(), jpeg)
    }

    func testRejectsNonImageAndLivePhoto() {
        assertFailure(
            OriginalPrimaryResourcePolicy.select(
                assetKind: .video,
                isLivePhoto: false,
                candidates: [jpeg]
            ),
            equals: .notStillImage
        )
        assertFailure(
            OriginalPrimaryResourcePolicy.select(
                assetKind: .image,
                isLivePhoto: true,
                candidates: [jpeg]
            ),
            equals: .livePhoto
        )
    }

    func testRejectsAmbiguousAdjustedAndCompoundSets() {
        let adjustment = ResourceCandidate(
            token: "adjustment",
            kind: .adjustmentData,
            uniformTypeIdentifier: "com.apple.photos"
        )
        assertFailure(
            OriginalPrimaryResourcePolicy.select(
                assetKind: .image,
                isLivePhoto: false,
                candidates: [jpeg, adjustment]
            ),
            equals: .ambiguousResourceSet
        )
    }

    func testRejectsUnsupportedTypeAndResourceKind() {
        assertFailure(
            OriginalPrimaryResourcePolicy.select(
                assetKind: .image,
                isLivePhoto: false,
                candidates: [
                    ResourceCandidate(
                        token: "raw",
                        kind: .originalPhoto,
                        uniformTypeIdentifier: "com.adobe.raw-image"
                    ),
                ]
            ),
            equals: .unsupportedType
        )
        assertFailure(
            OriginalPrimaryResourcePolicy.select(
                assetKind: .image,
                isLivePhoto: false,
                candidates: [
                    ResourceCandidate(
                        token: "adjusted",
                        kind: .adjustedPhoto,
                        uniformTypeIdentifier: "public.jpeg"
                    ),
                ]
            ),
            equals: .unsupportedResource
        )
    }

    private func assertFailure(
        _ result: Result<ResourceCandidate, ResourceRejection>,
        equals expected: ResourceRejection,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        switch result {
        case .success:
            XCTFail("expected rejection", file: file, line: line)
        case let .failure(actual):
            XCTAssertEqual(actual, expected, file: file, line: line)
        }
    }
}
