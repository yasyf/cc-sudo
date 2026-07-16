import Foundation

/// Which consent transport the verifier will lead with. The asuser question
/// the spike left open (does the sheet render for an SSH-descended sudo
/// child?) is settled at runtime, not compile time: the local helper answers
/// `unavailable` when it cannot prompt, and the strategy falls back to the
/// synckitd socket. Doctor reports the same selection.
public enum PromptStrategy: Sendable, Equatable {
    /// Local helper spawn first, synckitd socket on unavailable/screen-locked.
    case localThenSynckit(console: ConsoleUser)
    /// Straight to the synckitd socket (no console user, or the invoker is not
    /// the console user — v1 requires invoker == console user for local prompts).
    case synckitOnly

    public static func select(
        console: ConsoleUser? = ConsoleUser.current(),
        invokerUID: uid_t? = Self.sudoInvokerUID()
    ) -> PromptStrategy {
        guard let console, let invokerUID, console.uid == invokerUID else {
            return .synckitOnly
        }
        return .localThenSynckit(console: console)
    }

    /// The invoking (pre-sudo) user, from sudo's SUDO_UID.
    public static func sudoInvokerUID(environment: [String: String] = ProcessInfo.processInfo.environment) -> uid_t? {
        guard let raw = environment["SUDO_UID"], let uid = UInt32(raw) else { return nil }
        return uid
    }

    /// The home directory whose synckitd socket serves this request: the
    /// console user's when present, else the invoking user's.
    public static func socketHome(
        console: ConsoleUser? = ConsoleUser.current(),
        invokerUID: uid_t? = Self.sudoInvokerUID()
    ) -> URL? {
        if let home = console?.homeDirectory {
            return home
        }
        guard let invokerUID, let passwd = getpwuid(invokerUID), let dir = passwd.pointee.pw_dir else {
            return nil
        }
        return URL(filePath: String(cString: dir), directoryHint: .isDirectory)
    }
}

public extension Verifier.Dependencies {
    /// Production wiring for the root-owned verifier: real nonce, real pin,
    /// the strategy-selected consent sources, the root-owned trust store and
    /// origin identity, and a real exec.
    static func live() -> Verifier.Dependencies {
        Verifier.Dependencies(
            generateNonce: { try Nonce.generate() },
            pinHelper: { try HelperTrust.pinnedHelperBinary() },
            consentSource: { pinnedHelper in
                let synckit = SynckitConsentSource(
                    client: SynckitClient(socketPath: liveSocketPath()),
                    selfIdentity: (try? OriginIdentity.read()) ?? OriginIdentity.defaultIdentity()
                )
                switch PromptStrategy.select() {
                case let .localThenSynckit(console):
                    return FallbackConsentSource(
                        primary: LocalHelper(helperBinary: pinnedHelper, consoleUser: console),
                        fallback: synckit
                    )
                case .synckitOnly:
                    return synckit
                }
            },
            selfKey: { try TrustStore().selfKey() },
            peerKey: { host in try TrustStore().peerKey(host: host) },
            originIdentity: { try OriginIdentity.read() },
            execute: { argv in try Execution.replaceProcess(argv: argv) }
        )
    }

    internal static func liveSocketPath() -> String {
        guard let home = PromptStrategy.socketHome() else {
            // No console user and no SUDO_UID home: point at a path that will
            // fail closed as unavailable.
            return "/var/empty/.config/synckit/rpc.sock"
        }
        return SynckitClient.socketPath(home: home)
    }
}
