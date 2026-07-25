#!/bin/bash
set -euo pipefail

readonly synckit_version="0.35.2"
readonly state_fingerprint="2dc96a8a0930930535e711cbab04af029573c9b95318206f8a8fbad87677ca38"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "/private/tmp/cc-sudo-synckit-interop.XXXXXX")"
scratch="$(cd "$scratch" && pwd -P)"
config="$scratch/config"
home="$scratch/home"
socket="$config/synckit/rpc.sock"
daemon_pid=""

cleanup() {
    if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
        kill -TERM "$daemon_pid"
        wait "$daemon_pid" || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT

mkdir -p "$scratch/bin" "$config/synckit" "$home"
module_dir="$(go mod download -json "github.com/yasyf/synckit@v${synckit_version}" | jq -er .Dir)"
(
    cd "$module_dir"
    go build -ldflags "-X main.version=${synckit_version}" -o "$scratch/bin/synckitd" ./cmd/synckitd
)

reported="$("$scratch/bin/synckitd" --version)"
[[ "$reported" == "synckitd version ${synckit_version}" ]] || {
    echo "unexpected synckitd version: $reported" >&2
    exit 1
}

printf '%s\n' \
    "{\"schema\":{\"identity\":\"synckit-state-v1\",\"version\":1,\"fingerprint\":\"${state_fingerprint}\"},\"host_registry\":{\"self\":\"\",\"hosts\":[]},\"synckit\":{}}" \
    > "$config/synckit/state.json"

XDG_CONFIG_HOME="$config" HOME="$home" "$scratch/bin/synckitd" serve > "$scratch/synckitd.log" 2>&1 &
daemon_pid="$!"

for _ in {1..100}; do
    [[ -S "$socket" ]] && break
    kill -0 "$daemon_pid" 2>/dev/null || {
        sed -n '1,120p' "$scratch/synckitd.log" >&2
        exit 1
    }
    sleep 0.05
done
[[ -S "$socket" ]] || {
    sed -n '1,120p' "$scratch/synckitd.log" >&2
    echo "synckitd did not publish $socket" >&2
    exit 1
}

cd "$root"
CC_SUDO_SYNCKITD_SOCKET="$socket" \
    swift test --filter SynckitClientTests.publishedRuntimeHandshakeIsExact
