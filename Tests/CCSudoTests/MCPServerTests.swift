@testable import CCSudo
import Foundation
import MCP
import Testing

private func server(verdict: String, exitCode: Int32) -> MCPServer {
    MCPServer { argv, _, _ in
        RunClient.CapturedRun(
            stdout: "ran \(argv.joined(separator: " "))", stderr: "", exitCode: exitCode, verdict: verdict
        )
    }
}

private func text(_ result: CallTool.Result) -> String {
    guard case let .text(text, _, _) = result.content.first else { return "" }
    return text
}

@Test func runCommandReturnsTheCapturedPayload() async throws {
    let result = await server(verdict: "approved", exitCode: 0).handleCall(
        .init(name: "run_command", arguments: ["command": .array([.string("dscacheutil"), .string("-flushcache")])])
    )
    #expect(result.isError != true)
    let payload = try JSONDecoder().decode([String: Value].self, from: Data(text(result).utf8))
    #expect(payload["stdout"] == .string("ran dscacheutil -flushcache"))
    #expect(payload["exit_code"] == .int(0))
    #expect(payload["verdict"] == .string("approved"))
}

@Test func deniedRunsAreToolErrorsWithTheDeniedVerdict() async throws {
    let result = await server(verdict: "denied", exitCode: 103).handleCall(
        .init(name: "run_command", arguments: ["command": .array([.string("reboot")])])
    )
    #expect(result.isError == true)
    let payload = try JSONDecoder().decode([String: Value].self, from: Data(text(result).utf8))
    #expect(payload["verdict"] == .string("denied"))
    #expect(payload["exit_code"] == .int(103))
}

@Test func missingCommandIsAnArgumentError() async {
    let result = await server(verdict: "approved", exitCode: 0).handleCall(
        .init(name: "run_command", arguments: [:])
    )
    #expect(result.isError == true)
}

@Test func emptyCommandIsAnArgumentError() async {
    let result = await server(verdict: "approved", exitCode: 0).handleCall(
        .init(name: "run_command", arguments: ["command": .array([])])
    )
    #expect(result.isError == true)
}

@Test func nonStringArgvElementsAreRejected() async {
    let result = await server(verdict: "approved", exitCode: 0).handleCall(
        .init(name: "run_command", arguments: ["command": .array([.string("ls"), .int(3)])])
    )
    #expect(result.isError == true)
}

@Test func unknownToolsAreRejected() async {
    let result = await server(verdict: "approved", exitCode: 0).handleCall(
        .init(name: "other_tool", arguments: [:])
    )
    #expect(result.isError == true)
}

@Test func theInvocationWrapsSudoNonInteractiveIntoTheRootVerifier() {
    let argv = RunClient.invocation(argv: ["dscacheutil", "-flushcache"], clientVersion: "9.9.9")
    #expect(argv == [
        "/usr/bin/sudo", "-n", "/Library/PrivilegedHelperTools/cc-sudo-exec",
        "exec", "--client-version", "9.9.9", "--",
        "dscacheutil", "-flushcache",
    ])
}
