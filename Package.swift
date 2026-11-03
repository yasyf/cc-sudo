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
///
/// CCSudoPhone is the wire and signed-bytes contract the phone approver app
/// (Apps/Approver) shares with the Mac; it builds for iOS as well as macOS.
let package = Package(
    name: "cc-sudo",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "CCSudo", targets: ["CCSudo"]),
        .library(name: "CCSudoPhone", targets: ["CCSudoPhone"]),
        .executable(name: "cc-sudo", targets: ["cc-sudo"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk", from: "0.12.1"),
        .package(url: "https://github.com/yasyf/authkit", from: "0.3.0"),
        .package(url: "https://github.com/yasyf/daemonkit", exact: "0.35.4"),
    ],
    targets: [
        .target(
            name: "CCSudoPhone",
            dependencies: [
                .product(name: "AuthKitSubject", package: "authkit"),
            ]
        ),
        .target(
            name: "CCSudo",
            dependencies: [
                "CCSudoPhone",
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
            dependencies: ["CCSudo", "CCSudoPhone"]
        ),
    ]
)
