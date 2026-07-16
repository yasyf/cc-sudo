import Foundation
import MCP
import os

/// MCP over stdio with one tool, `run_command`: the same consent-gated flow as
/// `cc-sudo run` (`sudo -n` into the root-owned verifier), with output
/// captured for the client. The verdict field mirrors the documented exit
/// codes so an agent can route on a denial without parsing stderr.
public struct MCPServer: Sendable {
    static let toolName = "run_command"

    let capture: @Sendable (_ argv: [String], _ cwd: String?, _ timeoutMS: Int?) async throws -> RunClient.CapturedRun

    public init(
        capture: @escaping @Sendable (
            _ argv: [String], _ cwd: String?, _ timeoutMS: Int?
        ) async throws -> RunClient.CapturedRun = { try await RunClient.capture(argv: $0, cwd: $1, timeoutMS: $2) }
    ) {
        self.capture = capture
    }

    static let tool = Tool(
        name: toolName,
        description: """
        Run a command as root after the human approves it on a native Touch ID \
        sheet showing the exact command. Denials come back with verdict \
        "denied" — do not retry them.
        """,
        inputSchema: .object([
            "type": .string("object"),
            "properties": .object([
                "command": .object([
                    "type": .string("array"),
                    "items": .object(["type": .string("string")]),
                    "description": .string("The command argv, one element per argument."),
                ]),
                "cwd": .object([
                    "type": .string("string"),
                    "description": .string("Working directory for the command."),
                ]),
                "timeout_ms": .object([
                    "type": .string("integer"),
                    "description": .string("Overall deadline including the human's approval tap."),
                ]),
            ]),
            "required": .array([.string("command")]),
        ])
    )

    /// Serves until the client disconnects.
    public func serve() async throws {
        let server = Server(
            name: "cc-sudo",
            version: Version.current,
            capabilities: .init(tools: .init(listChanged: false))
        )

        await server.withMethodHandler(ListTools.self) { _ in
            .init(tools: [Self.tool])
        }

        let handler = self
        await server.withMethodHandler(CallTool.self) { params in
            await handler.handleCall(params)
        }

        try await server.start(transport: StdioTransport())
        await server.waitUntilCompleted()
    }

    /// One run_command call: validate the arguments, drive the consent-gated
    /// run, and fold the outcome into the wire payload.
    func handleCall(_ params: CallTool.Parameters) async -> CallTool.Result {
        guard params.name == Self.toolName else {
            return failure("unknown tool \(params.name)")
        }
        guard let commandValues = params.arguments?["command"]?.arrayValue,
              case let argv = commandValues.compactMap(\.stringValue),
              argv.count == commandValues.count, !argv.isEmpty
        else {
            return failure("command must be a non-empty array of strings")
        }
        let cwd = params.arguments?["cwd"]?.stringValue
        let timeoutMS = params.arguments?["timeout_ms"]?.intValue

        do {
            let run = try await capture(argv, cwd, timeoutMS)
            let payload: [String: Value] = [
                "stdout": .string(run.stdout),
                "stderr": .string(run.stderr),
                "exit_code": .int(Int(run.exitCode)),
                "verdict": .string(run.verdict),
            ]
            let encoded = try JSONEncoder().encode(Value.object(payload))
            return .init(
                content: [.text(text: encoded.utf8Lossy, annotations: nil, _meta: nil)],
                isError: run.verdict != "approved"
            )
        } catch {
            Logger.mcp.error("run_command failed: \(String(describing: error), privacy: .public)")
            return failure(String(describing: error))
        }
    }

    private func failure(_ message: String) -> CallTool.Result {
        .init(content: [.text(text: message, annotations: nil, _meta: nil)], isError: true)
    }
}
