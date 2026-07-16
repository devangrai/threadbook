// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "WardrobePhotoKit",
    platforms: [
        .macOS("15.0"),
    ],
    products: [
        .library(
            name: "WardrobePhotoKit",
            type: .static,
            targets: ["WardrobePhotoKit"]
        ),
        .executable(
            name: "WardrobePhotoKitLiveSmoke",
            targets: ["WardrobePhotoKitLiveSmoke"]
        ),
    ],
    targets: [
        .target(
            name: "WardrobePhotoKitObjC",
            path: "Sources/WardrobePhotoKitObjC",
            publicHeadersPath: "include"
        ),
        .target(
            name: "WardrobePhotoKit",
            dependencies: ["WardrobePhotoKitObjC"],
            path: "Sources/WardrobePhotoKit",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("Foundation"),
                .linkedFramework("ImageIO"),
                .linkedFramework("Photos"),
                .linkedFramework("PhotosUI"),
                .linkedFramework("UniformTypeIdentifiers"),
                .linkedFramework("Vision"),
            ]
        ),
        .executableTarget(
            name: "WardrobePhotoKitLiveSmoke",
            dependencies: [
                "WardrobePhotoKit",
                "WardrobePhotoKitObjC",
            ],
            path: "Sources/WardrobePhotoKitLiveSmoke"
        ),
        .testTarget(
            name: "WardrobePhotoKitTests",
            dependencies: [
                "WardrobePhotoKit",
                "WardrobePhotoKitObjC",
            ],
            path: "Tests",
            exclude: [
                "CABIHeaderTests.c",
                "RustLinkSmoke.rs",
            ],
            sources: [
                "WardrobePhotoKitTests",
            ],
            resources: [
                .copy("Fixtures"),
            ]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
