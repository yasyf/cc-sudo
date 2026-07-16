/// The version stamped into every build. The brew-installed CLI passes it to
/// the root-owned verifier copy (`exec --client-version`), which hard-fails on
/// any mismatch with its own value — so a `brew upgrade` that outruns
/// `cc-sudo install` is a loud, routable error, never a silent skew.
public enum Version {
    public static let current = "0.2.0"
}
