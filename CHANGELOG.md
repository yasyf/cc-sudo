# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-21

### Changed
- Synckit consent now uses the exact persistent DaemonKit v1 session protocol; legacy newline-delimited requests are gone.
- The root verifier delegates only the same-user Synckit transport to a privilege-dropped bridge, while signed-attestation verification and command authorization remain root-owned.

### Fixed
- DaemonKit-backed Synckit sessions close deterministically and cannot terminate the verifier on a closed-peer write.

## [0.2.0] - 2026-07-16

### Added
- `cc-sudo run -- <cmd>` runs a command as root after one Touch ID tap on a sheet showing the exact argv, with stdio inherited and the command's exit status passed through.
- A root-owned verifier at `/Library/PrivilegedHelperTools/cc-sudo-exec` enforces the Secure-Enclave attestation flow of fresh nonce, authkit designated-requirement pin, signature verification against enrolled keys, then exec of the exact approved argv.
- Consent reaches the helper through a local `launchctl asuser` spawn, falling back to the synckitd socket for SSH sessions and locked Macs; routed peer approvals verify against enrolled peer keys and never fall back to unsigned.
- `cc-sudo install` lays down the verifier copy, sudoers rule, enrolled SE key, and origin identity; `cc-sudo trust <peer>` enrolls a peer key; `cc-sudo uninstall` removes it all; `cc-sudo doctor` checks the whole trust chain and offers a `--probe-prompt` asuser probe.
- `cc-sudo mcp` serves a `run_command` tool over stdio that returns `{stdout, stderr, exit_code, verdict}`.
- Exit codes 103 denied, 104 unavailable, 105 verification failed, and 106 version skew are documented for agents to route on.

## [0.1.0] - 2026-07-14

### Added
- Initial scaffolding: the `CCSudo` library, the `cc-sudo` CLI skeleton with a `hello` smoke command, CI, and the Homebrew cask release pipeline.

[0.3.0]: https://github.com/yasyf/cc-sudo/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yasyf/cc-sudo/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yasyf/cc-sudo/releases/tag/v0.1.0
