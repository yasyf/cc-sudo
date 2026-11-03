#!/bin/bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

mkdir -p .build
(cd Tests/SynckitFixture && CGO_ENABLED=0 go build -o "$root/.build/synckit-fixture" .)
export CC_SUDO_SYNCKIT_FIXTURE="$root/.build/synckit-fixture"

# swift test has stalled on CI with every test parked and no output; sample
# the test processes' stacks before failing so the stall names its cause.
swift test "$@" &
pid=$!
for _ in $(seq 1 "${CC_SUDO_TEST_STALL_SECONDS:-300}"); do
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid"
        exit
    fi
    sleep 1
done
echo "::error::swift test still running after ${CC_SUDO_TEST_STALL_SECONDS:-300}s; sampling the test processes" >&2
for test_pid in $(pgrep -f 'swiftpm-testing-helper|xctest|cc-sudoPackageTests'); do
    sample "$test_pid" 3 2>&1 | head -400 >&2 || true
done
kill "$pid"
exit 1
