import XCTest
@testable import WardrobePhotoKit

final class ResourceSelectionTests: XCTestCase {
    private let jpeg = ResourceCandidate(
        index: 0,
        kind: .originalPhoto,
        uniformTypeIdentifier: "public.jpeg"
    )

    func testSelectsOnlyOneAllowlistedOriginalStillImage() throws {
        let selected = try OriginalPrimaryResourcePolicy.select(
            mediaKind: .image,
            isLivePhoto: false,
            representsBurst: false,
            candidates: [jpeg]
        ).get()
        XCTAssertEqual(selected, jpeg)
        XCTAssertEqual(OriginalPrimaryResourcePolicy.revision, "original-primary-v1")
        XCTAssertEqual(
            OriginalPrimaryResourcePolicy.allowedTypes,
            ["public.jpeg", "public.png", "public.heic", "public.heif"]
        )
    }

    func testRejectsLiveBurstRawAdjustedAndCompoundResources() {
        assertFailure(isLive: true, candidates: [jpeg], expected: .livePhoto)
        assertFailure(isBurst: true, candidates: [jpeg], expected: .burst)
        assertFailure(
            candidates: [
                ResourceCandidate(
                    index: 0,
                    kind: .originalPhoto,
                    uniformTypeIdentifier: "com.adobe.raw-image"
                ),
            ],
            expected: .unsupportedType
        )
        assertFailure(
            candidates: [
                ResourceCandidate(
                    index: 0,
                    kind: .adjustedPhoto,
                    uniformTypeIdentifier: "public.jpeg"
                ),
            ],
            expected: .unsupportedResource
        )
        assertFailure(
            candidates: [
                jpeg,
                ResourceCandidate(
                    index: 1,
                    kind: .adjustmentData,
                    uniformTypeIdentifier: "com.apple.photos"
                ),
            ],
            expected: .ambiguousResourceSet
        )
    }

    private func assertFailure(
        isLive: Bool = false,
        isBurst: Bool = false,
        candidates: [ResourceCandidate],
        expected: ResourceRejection,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let result = OriginalPrimaryResourcePolicy.select(
            mediaKind: .image,
            isLivePhoto: isLive,
            representsBurst: isBurst,
            candidates: candidates
        )
        switch result {
        case .success:
            XCTFail("expected rejection", file: file, line: line)
        case let .failure(actual):
            XCTAssertEqual(actual, expected, file: file, line: line)
        }
    }
}
