# ![cc-sudo](docs/assets/readme-banner.webp)

**Sudo for Claude, one Touch ID tap per command.** cc-sudo puts an agent's privileged commands in front of you as native macOS Touch ID prompts — a tap runs the command, anything else cancels it.

[![Release](https://img.shields.io/github/v/release/yasyf/cc-sudo?sort=semver)](https://github.com/yasyf/cc-sudo/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/yasyf/cc-sudo/ci.yml?branch=main&label=ci)](https://github.com/yasyf/cc-sudo/actions/workflows/ci.yml)
[![License: PolyForm-Noncommercial-1.0.0](https://img.shields.io/badge/License-PolyForm--Noncommercial--1.0.0-blue.svg)](https://github.com/yasyf/cc-sudo/blob/main/LICENSE)

## Get started

```bash
brew install yasyf/tap/cc-sudo
cc-sudo hello
```

<img src="docs/assets/demo.png" alt="Terminal running 'cc-sudo hello' — it prints 'Hello, world! This is cc-sudo.'" width="700">

Driving with an agent? Paste this:

```text
Install cc-sudo (`brew install yasyf/tap/cc-sudo`), run `cc-sudo hello` to
verify the install, then read `cc-sudo --help` for the current command
surface. Repo: https://github.com/yasyf/cc-sudo
```

---

## Use cases

cc-sudo is a skeleton today — `hello` is the whole command surface. The flows below are what it's being built for.

### Give an agent one privileged command, not root

An agent that needs a single `dscacheutil -flushcache` shouldn't get a standing sudo grant or a NOPASSWD rule. The target flow:

```bash
cc-sudo run -- dscacheutil -flushcache
```

The exact command comes to the foreground in a native Touch ID prompt. A tap runs it and hands stdout, stderr, and the exit code back to the caller; a denial returns a clean non-zero exit the agent can route around instead of stalling on a password it will never have.

### Keep your password out of the transcript

Typing your password into an agent-driven terminal leaves it sitting in the session transcript. With cc-sudo the approval happens in a system prompt the agent never sees. Touch ID replaces the password entirely, and nothing secret enters the conversation.

## Commands

| Command | What it does |
|---|---|
| `cc-sudo hello [name]` | Print a greeting — the install smoke test. |

The full flag surface lives in `cc-sudo --help`.

## Development

Build with `swift build`, test with `swift test`; conventions live in [AGENTS.md](AGENTS.md).

Status: pre-alpha — the CLI skeleton ships, the Touch ID sudo flow is under construction.

Licensed under [PolyForm-Noncommercial-1.0.0](LICENSE).
