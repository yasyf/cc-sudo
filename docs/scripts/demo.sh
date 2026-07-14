#!/usr/bin/env bash
# Regenerate docs/assets/demo.png — a real run of the README's get-started command.
set -euo pipefail
cd "$(dirname "$0")/../.."

swift build >/dev/null
out="$(PATH=".build/debug:$PATH" cc-sudo hello)"
printf '$ cc-sudo hello\n%s\n' "$out" |
  freeze --language console --output docs/assets/demo.png
