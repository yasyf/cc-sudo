@testable import CCSudo
import Foundation
import Testing

@Test func liveRunnerFeedsStdinAndCapturesTheChildsOutput() async throws {
    let result = try await LiveProcessRunner().run(
        executable: "/bin/cat", arguments: [], stdin: Data("fed through the pipe".utf8), environment: nil
    )
    #expect(result.exitCode == 0)
    #expect(result.stdout == Data("fed through the pipe".utf8))
    #expect(result.stderr.isEmpty)
}

@Test(.timeLimit(.minutes(1)))
func liveRunnerSurvivesAChildThatExitsWithoutReadingStdin() async {
    // Without the descriptor-local F_SETNOSIGPIPE this write is a SIGPIPE and
    // the test process dies here instead of recording a thrown EPIPE.
    let largerThanAnyPipeBuffer = Data(repeating: 0x2A, count: 1 << 20)
    await #expect(throws: (any Error).self) {
        _ = try await LiveProcessRunner().run(
            executable: "/bin/sh", arguments: ["-c", "exit 0"], stdin: largerThanAnyPipeBuffer, environment: nil
        )
    }
}
