@testable import CCSudo
import Foundation
import Testing

private func versionRunner(_ version: String, exitCode: Int32 = 0) -> FakeRunner {
    FakeRunner { _, _ in
        SubprocessResult(exitCode: exitCode, stdout: Data("\(version)\n".utf8), stderr: Data())
    }
}

@Test func anExactMatchIsCurrent() {
    #expect(VerifierCompatibility(client: "0.15.0", verifier: "0.15.0") == .current)
    #expect(VerifierCompatibility(client: "1.0.0-rc.1", verifier: "1.0.0-rc.1") == .current)
}

@Test func aNewerClientRunsAgainstAVerifierAtOrAboveTheFloor() {
    let behind = VerifierCompatibility(client: "0.16.0", verifier: "0.15.0", minimumVerifier: "0.15.0")
    #expect(behind == .verifierBehind)
    #expect(behind.allowsRun)
    #expect(VerifierCompatibility(client: "0.100.0", verifier: "0.20.0", minimumVerifier: "0.20.0").allowsRun)
}

@Test func aVerifierBelowTheFloorIsRefused() {
    let below = VerifierCompatibility(client: "0.16.0", verifier: "0.14.0", minimumVerifier: "0.15.0")
    #expect(below == .incompatible)
    #expect(!below.allowsRun)
}

@Test func anOlderClientIsAlwaysRefused() {
    let behind = VerifierCompatibility(client: "0.15.0", verifier: "0.16.0", minimumVerifier: "0.15.0")
    #expect(behind == .clientBehind)
    #expect(!behind.allowsRun)
    #expect(!VerifierCompatibility(client: "0.9.9", verifier: "0.15.0", minimumVerifier: "0.1.0").allowsRun)
}

@Test(arguments: [
    "", "garbage", "1", "1.2", "1.2.3.4", "1.2.", ".1.2", "1.2.3-rc.1", "1.2.3+meta", "+1.2.3", "-1.2.3",
    "١.٢.٣", "1.2.3\n", "99999999999999999999.0.0", "0.15.00", "0.016.0", "00.99.0", "1.02.0",
])
func anUnrecognizedClientVersionIsRefused(client: String) {
    #expect(!VerifierCompatibility(client: client, verifier: "0.15.0", minimumVerifier: "0.15.0").allowsRun)
}

@Test func anUnrecognizedVerifierVersionIsRefused() {
    #expect(!VerifierCompatibility(client: "0.15.0", verifier: "0.15.0-rc.1", minimumVerifier: "0.1.0").allowsRun)
}

@Test func theFloorIsAPlainReleaseThisBuildSatisfies() throws {
    let floor = try #require(ReleaseVersion(VerifierCompatibility.minimumVerifier))
    let current = try #require(ReleaseVersion(Version.current))
    #expect(floor <= current)
}

@Test func theSkewMessageNamesTheRemedyForEachSide() {
    let clientBehind = VersionSkewError(clientVersion: "0.15.0", verifierVersion: "0.16.0")
    let verifierBelowFloor = VersionSkewError(clientVersion: "0.16.0", verifierVersion: "0.14.0")
    let verifierMissing = VersionSkewError(clientVersion: "0.16.0", verifierVersion: nil)
    #expect(clientBehind.message.contains("brew upgrade cc-sudo"))
    #expect(verifierBelowFloor.message.contains("sudo cc-sudo install"))
    #expect(verifierMissing.message.contains("sudo cc-sudo install"))
}

@Test func thePreflightReadsTheInstalledVerifierWithoutSudo() async throws {
    let runner = versionRunner("0.15.0")
    let warning = try await RunClient.checkVerifier(runner: runner, clientVersion: "0.15.0")
    #expect(warning == nil)
    #expect(runner.spawns.map(\.executable) == [RunClient.verifierPath])
    #expect(runner.spawns.map(\.arguments) == [["--version"]])
}

@Test func thePreflightWarnsAndAllowsAVerifierBehindTheClient() async throws {
    let warning = try await RunClient.checkVerifier(
        runner: versionRunner(VerifierCompatibility.minimumVerifier),
        clientVersion: "999.0.0"
    )
    #expect(warning?.contains("sudo cc-sudo install") == true)
}

@Test func thePreflightThrowsOnAVerifierBelowTheFloor() async {
    await #expect(throws: VersionSkewError.self) {
        _ = try await RunClient.checkVerifier(runner: versionRunner("0.0.1"), clientVersion: "999.0.0")
    }
}

@Test func thePreflightThrowsWhenTheVerifierCannotReportAVersion() async {
    await #expect(throws: VersionSkewError.self) {
        _ = try await RunClient.checkVerifier(runner: versionRunner("", exitCode: 1), clientVersion: "999.0.0")
    }
}

@Test func aCapturedRunReportsSkewAsAVerdictWithoutReachingSudo() async throws {
    let runner = versionRunner("0.0.1")
    let run = try await RunClient.capture(argv: ["/usr/bin/true"], preflightRunner: runner)
    #expect(run.exitCode == ExitStatus.versionSkew.rawValue)
    #expect(run.verdict == "version_skew")
    #expect(run.stderr.contains("sudo cc-sudo install"))
    #expect(runner.spawns.count == 1)
}

private struct StalledRunner: ProcessRunner {
    func run(
        executable _: String,
        arguments _: [String],
        stdin _: Data?,
        environment _: [String: String]?
    ) async throws -> SubprocessResult {
        try await Task.sleep(for: .seconds(600))
        return SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
    }
}

@Test(.timeLimit(.minutes(1)))
func aStalledPreflightStaysInsideTheCapturedRunsDeadline() async {
    await #expect(throws: RunClient.RunError.self) {
        _ = try await RunClient.capture(argv: ["/usr/bin/true"], timeoutMS: 50, preflightRunner: StalledRunner())
    }
}

@Test func doctorPassesAtTheCurrentVersion() {
    let result = Doctor.verifierResult(path: "/v", installed: "0.15.0", client: "0.15.0")
    #expect(result.status == .pass)
}

@Test func doctorWarnsOnAVerifierBehindTheClient() {
    let result = Doctor.verifierResult(path: "/v", installed: VerifierCompatibility.minimumVerifier, client: "999.0.0")
    #expect(result.status == .warn)
    #expect(result.detail.contains("sudo cc-sudo install"))
}

@Test func doctorFailsOnAVerifierBelowTheFloor() {
    let result = Doctor.verifierResult(path: "/v", installed: "0.0.1", client: "999.0.0")
    #expect(result.status == .fail)
    #expect(result.detail.contains("sudo cc-sudo install"))
}
