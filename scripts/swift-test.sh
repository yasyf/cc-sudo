#!/bin/bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

mkdir -p .build
(cd Tests/SynckitFixture && CGO_ENABLED=0 go build -o "$root/.build/synckit-fixture" .)
export CC_SUDO_SYNCKIT_FIXTURE="$root/.build/synckit-fixture"

exec swift test "$@"
