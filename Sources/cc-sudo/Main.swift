import ArgumentParser
import CCSudo

@main
struct Root: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cc-sudo",
        abstract: "Sudo for Claude, one Touch ID tap per command.",
        version: "0.0.0-dev",
        subcommands: [Hello.self]
    )
}

struct Hello: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Print a friendly greeting."
    )

    @Argument(help: "Who to greet.")
    var name: String = "world"

    func run() async throws {
        print(helloMessage(name: name))
    }
}
