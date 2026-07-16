import Foundation
import XCTest

final class NativeStaticContractTests: XCTestCase {
    func testStoreWritesDirectFinalNamesWithoutPathnameMutation() throws {
        let storeSource = try String(
            contentsOf: packageRoot.appendingPathComponent(
                "Sources/P00PhotoKitCore/PrivateRunOutputStore.swift"
            ),
            encoding: .utf8
        )
        let sourceRoot = packageRoot.appendingPathComponent("Sources")
        let sourceFiles = try XCTUnwrap(
            FileManager.default.enumerator(
                at: sourceRoot,
                includingPropertiesForKeys: nil
            )?.allObjects as? [URL]
        ).filter { $0.pathExtension == "swift" }
        let allProductionSwift = try sourceFiles
            .map { try String(contentsOf: $0, encoding: .utf8) }
            .joined(separator: "\n")

        XCTAssertFalse(allProductionSwift.contains(["unlink", "at("].joined()))
        XCTAssertFalse(allProductionSwift.contains("unlinkIfIdentityMatches"))
        XCTAssertFalse(allProductionSwift.contains(["renameatx", "_np("].joined()))
        XCTAssertFalse(allProductionSwift.contains(".staging-"))
        XCTAssertFalse(allProductionSwift.contains(".provenance-"))
        XCTAssertFalse(allProductionSwift.contains(".quarantine-"))
        XCTAssertFalse(allProductionSwift.contains("retainByQuarantining"))
        XCTAssertEqual(
            storeSource.components(
                separatedBy:
                    "O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC"
            ).count - 1,
            2
        )
        XCTAssertTrue(storeSource.contains("makeSink(outputName: String)"))
        XCTAssertTrue(storeSource.contains("name: outputName"))
        XCTAssertTrue(storeSource.contains("maximumSinksPerRun = 4"))
    }

    func testPackageScriptUsesOneFreshScratchTreeEverywhere() throws {
        let scriptURL = packageRoot.appendingPathComponent("scripts/package-app.sh")
        let script = try String(contentsOf: scriptURL, encoding: .utf8)

        XCTAssertTrue(script.contains("mktemp -d"))
        XCTAssertTrue(script.contains("wardrobe-p00-photokit-swift.XXXXXX"))
        XCTAssertTrue(script.contains("trap 'rm -rf \"$SCRATCH_ROOT\"' EXIT"))
        XCTAssertTrue(
            script.contains(
                "CLANG_MODULE_CACHE_PATH=\"$SCRATCH_ROOT/clang-module-cache\""
            )
        )
        XCTAssertTrue(
            script.contains(
                "SWIFTPM_MODULECACHE_OVERRIDE=\"$SCRATCH_ROOT/swift-module-cache\""
            )
        )
        XCTAssertEqual(
            script.components(
                separatedBy: "--scratch-path \"$SCRATCH_ROOT/build\""
            ).count - 1,
            2
        )

        let syntaxCheck = Process()
        syntaxCheck.executableURL = URL(fileURLWithPath: "/bin/bash")
        syntaxCheck.arguments = ["-n", scriptURL.path]
        try syntaxCheck.run()
        syntaxCheck.waitUntilExit()
        XCTAssertEqual(syntaxCheck.terminationStatus, 0)
    }

    private var packageRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
