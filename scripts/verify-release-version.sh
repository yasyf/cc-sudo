#!/bin/bash
set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
    echo "usage: $0 <cc-sudo-binary> [v<release-version>]" >&2
    exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$1"
expected="$(tr -d '\r\n' < "$root/VERSION")"

if [[ "$#" -eq 2 ]]; then
    tagged="${2#v}"
    if [[ "$tagged" != "$expected" ]]; then
        echo "release tag version mismatch: tag=$tagged VERSION=$expected" >&2
        exit 1
    fi
fi

actual="$("$binary" --version)"
if [[ "$actual" != "$expected" ]]; then
    echo "built executable version mismatch: binary=$actual VERSION=$expected" >&2
    exit 1
fi

echo "release version verified: $actual"
