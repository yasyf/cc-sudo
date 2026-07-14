// swift-tools-version: 6.2
import PackageDescription

/// Logic lives in the CCSudo library; the executable target is a thin
/// ArgumentParser shell. Tests import the library, never the executable.
let package = Package(
    name: "cc-sudo",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "CCSudo", targets: ["CCSudo"]),
        .executable(name: "cc-sudo", targets: ["cc-sudo"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
    ],
    targets: [
        .target(name: "CCSudo"),
        .executableTarget(
            name: "cc-sudo",
            dependencies: [
                "CCSudo",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(name: "CCSudoTests", dependencies: ["CCSudo"]),
    ]
)
