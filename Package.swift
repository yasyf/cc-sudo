// swift-tools-version: 6.2
import PackageDescription

/// Logic lives in the CCSudo library; the executable target is a thin
/// ArgumentParser shell. Tests import the library, never the executable.
///
/// AuthKit is consumed as a LOCAL PATH dependency while the repos co-develop;
/// it swaps to the git URL + a version tag when authkit cuts its first release
/// (https://github.com/yasyf/authkit). cc-sudo uses only AuthKit's pure-Swift
/// verification helpers (Attestation, Subject, payload types) — every
/// Secure-Enclave and biometric operation stays behind the signed authkit
/// helper PROCESS, never in this binary.
let package = Package(
    name: "cc-sudo",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "CCSudo", targets: ["CCSudo"]),
        .executable(name: "cc-sudo", targets: ["cc-sudo"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk", from: "0.12.1"),
        .package(path: "/Users/yasyf/Code/authkit"),
    ],
    targets: [
        .target(
            name: "CCSudo",
            dependencies: [
                .product(name: "AuthKit", package: "authkit"),
                .product(name: "MCP", package: "swift-sdk"),
            ]
        ),
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
