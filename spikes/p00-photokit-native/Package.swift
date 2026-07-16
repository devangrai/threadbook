// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "P00PhotoKitNative",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(name: "P00PhotoKitCore", targets: ["P00PhotoKitCore"]),
        .executable(name: "P00PhotoKitProbe", targets: ["P00PhotoKitProbe"]),
    ],
    targets: [
        .target(
            name: "P00PhotoKitCore",
            linkerSettings: [
                .linkedFramework("ImageIO"),
            ]
        ),
        .executableTarget(
            name: "P00PhotoKitProbe",
            dependencies: ["P00PhotoKitCore"],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("ImageIO"),
                .linkedFramework("Photos"),
                .linkedFramework("PhotosUI"),
            ]
        ),
        .testTarget(
            name: "P00PhotoKitCoreTests",
            dependencies: ["P00PhotoKitCore"]
        ),
    ]
)
