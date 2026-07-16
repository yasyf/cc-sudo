import ArgumentParser
import CCSudo
import Foundation

@main
struct Root: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cc-sudo",
        abstract: "Sudo for Claude, one Touch ID tap per command.",
        discussion: """
        Routable exit codes: 103 denied, 104 unavailable, 105 verification \
        failed, 106 version skew (run 'cc-sudo install'). An approved \
        command's own exit status passes through verbatim.
        """,
        version: Version.current,
        subcommands: [
            Run.self, Exec.self, MCP.self, Install.self, Trust.self,
            Uninstall.self, DoctorCommand.self, Hello.self,
        ]
    )
}

func exitClassifying(_ error: any Error) -> Never {
    FileHandle.standardError.write(Data("cc-sudo: \(message(for: error))\n".utf8))
    if let status = ExitStatus(classifying: error) {
        Foundation.exit(status.rawValue)
    }
    Foundation.exit(1)
}

func message(for error: any Error) -> String {
    if let skew = error as? VersionSkewError {
        return skew.message
    }
    return String(describing: error)
}

struct Run: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run a command as root after one Touch ID tap.",
        usage: "cc-sudo run -- <command> [args...]"
    )

    @Argument(parsing: .postTerminator, help: "The command to run, after '--'.")
    var command: [String]

    func run() async throws {
        guard !command.isEmpty else {
            throw ValidationError("no command given; usage: cc-sudo run -- <command> [args...]")
        }
        do {
            try RunClient.exec(argv: command)
        } catch {
            exitClassifying(error)
        }
    }
}

struct Exec: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Root-side verifier (internal; only meaningful as the root-owned copy).",
        shouldDisplay: false
    )

    @Option(name: .customLong("client-version"), help: "The invoking CLI's version.")
    var clientVersion: String

    @Argument(parsing: .postTerminator)
    var command: [String]

    func run() async throws {
        guard clientVersion == Version.current else {
            exitClassifying(VersionSkewError(clientVersion: clientVersion, verifierVersion: Version.current))
        }
        guard geteuid() == 0 else {
            throw ValidationError("exec must run as root via 'sudo -n \(RunClient.verifierPath)'")
        }
        do {
            let verifier = Verifier(dependencies: .live())
            try await verifier.authorizeAndRun(argv: command)
        } catch {
            exitClassifying(error)
        }
    }
}

struct MCP: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp",
        abstract: "Serve the run_command tool over MCP stdio."
    )

    func run() async throws {
        try await MCPServer().serve()
    }
}

struct Install: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Install the root-owned verifier, sudoers rule, and enrolled key (requires sudo)."
    )

    @Option(help: "This host's mesh identity for routed approvals (must match synckitd's self name).")
    var origin: String = OriginIdentity.defaultIdentity()

    func run() async throws {
        do {
            let helperBundle = try HelperTrust.locateBundle()
            try HelperTrust.validate(bundle: helperBundle)
            guard let console = ConsoleUser.current() else {
                throw Installer.InstallError.noConsoleUser
            }
            guard let executable = Bundle.main.executableURL else {
                throw ValidationError("cannot resolve the running executable")
            }
            let keyID = try await Installer().install(
                sourceExecutable: executable,
                originIdentity: origin,
                helperBundle: helperBundle,
                console: console
            )
            print("installed \(RunClient.verifierPath) (\(Version.current))")
            print("enrolled self key \(keyID)")
        } catch Installer.InstallError.notRoot {
            throw ValidationError("install requires root: sudo cc-sudo install")
        } catch {
            exitClassifying(error)
        }
    }
}

struct Trust: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Enroll a peer's public key for routed approvals (requires sudo; trusts ssh at enrollment time only)."
    )

    @Argument(help: "The peer's mesh host name.")
    var peer: String

    func run() async throws {
        do {
            let keyID = try await PeerTrust().trust(peer: peer)
            print("enrolled peer \(peer) key \(keyID)")
        } catch PeerTrust.PeerTrustError.notRoot {
            throw ValidationError("trust requires root: sudo cc-sudo trust \(peer)")
        } catch {
            exitClassifying(error)
        }
    }
}

struct Uninstall: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Remove the verifier, sudoers rule, and trust store (requires sudo)."
    )

    func run() async throws {
        do {
            try Installer().uninstall()
            print("removed \(RunClient.verifierPath), \(Installer.sudoersPath), /etc/cc-sudo")
        } catch Installer.InstallError.notRoot {
            throw ValidationError("uninstall requires root: sudo cc-sudo uninstall")
        }
    }
}

struct DoctorCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Check every link of the trust chain."
    )

    @Flag(name: .customLong("probe-prompt"), help: "Fire a real consent sheet to probe the asuser path (root + a tap).")
    var probePrompt = false

    func run() async throws {
        let results = await Doctor().checks(probePrompt: probePrompt)
        for result in results {
            print("[\(result.status.rawValue)] \(result.name): \(result.detail)")
        }
        if results.contains(where: { $0.status == .fail }) {
            Foundation.exit(1)
        }
    }
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
