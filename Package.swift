// swift-tools-version: 6.2
import PackageDescription

/// Logic lives in the CCSudo library; the executable target is a thin
/// ArgumentParser shell. Tests import the library, never the executable.
///
/// AuthKit comes from the authkit package's tagged release
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
        .package(url: "https://github.com/yasyf/authkit", from: "0.1.0"),
        .package(url: "https://github.com/yasyf/daemonkit", exact: "0.14.0"),
    ],
    targets: [
        .target(
            name: "CCSudo",
            dependencies: [
                .product(name: "AuthKit", package: "authkit"),
                .product(name: "DaemonKit", package: "daemonkit"),
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
        .testTarget(
            name: "CCSudoTests",
            dependencies: [
                "CCSudo",
                .product(name: "DaemonKit", package: "daemonkit"),
            ]
        ),
    ]
)
