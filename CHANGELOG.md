# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/yasyf/cc-sudo/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yasyf/cc-sudo/releases/tag/v0.1.0
