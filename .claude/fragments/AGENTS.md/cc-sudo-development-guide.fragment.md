# cc-sudo Development Guide

Sudo for Claude, one Touch ID tap per command. Distributed via Homebrew: `brew install yasyf/tap/cc-sudo`.

## Repository Structure

```
cc-sudo/
├── Package.swift               # SPM manifest — targets, products, dependencies
├── Sources/
│   ├── CCSudo/        # the library — all logic lives here
│   └── cc-sudo/       # the executable — a thin ArgumentParser shell
├── Tests/CCSudoTests/ # Swift Testing (@Test / #expect) against the library
├── .github/                    # GitHub Actions workflows
├── AGENTS.md                   # This file — shared conventions
└── README.md                   # Project overview
```
