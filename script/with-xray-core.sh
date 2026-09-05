#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO:-go}
XRAY_REPLACEMENT='github.com/xtls/xray-core@v1.260711.0'
XRAY_FORK='github.com/wyx2685/xray-core@v0.0.0-20260713170150-b17a88f9b46d'
XRAY_CACHE="$($GO_BIN env GOMODCACHE)/github.com/wyx2685/xray-core@v0.0.0-20260713170150-b17a88f9b46d"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/znode-xray.XXXXXX")
CORE_DIR="$TMP_ROOT/xray-core"
MODFILE="$TMP_ROOT/znode.mod"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT HUP INT TERM

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <go command> [arguments...]" >&2
    exit 2
fi

"$GO_BIN" mod download "$XRAY_FORK"
if [ ! -d "$XRAY_CACHE" ]; then
    echo "verified Xray fork was not found in the Go module cache: $XRAY_CACHE" >&2
    exit 1
fi

mkdir -p "$CORE_DIR"
cp -R "$XRAY_CACHE/." "$CORE_DIR/"
chmod -R u+w "$CORE_DIR"

for patch_file in "$ROOT"/patches/xray-core/*.patch; do
    patch --batch --forward -p1 -d "$CORE_DIR" < "$patch_file"
done

cp "$ROOT/go.mod" "$MODFILE"
cp "$ROOT/go.sum" "$TMP_ROOT/znode.sum"
"$GO_BIN" mod edit -modfile="$MODFILE" -dropreplace="$XRAY_REPLACEMENT"
"$GO_BIN" mod edit -modfile="$MODFILE" -replace="$XRAY_REPLACEMENT=$CORE_DIR"

if [ -n "${GOFLAGS:-}" ]; then
    GOFLAGS="$GOFLAGS -modfile=$MODFILE"
else
    GOFLAGS="-modfile=$MODFILE"
fi
export GOFLAGS

cd "$ROOT"
"$@"
