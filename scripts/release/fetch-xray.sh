#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

here=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
readonly here
# Resolved from the script's canonical directory.
# shellcheck disable=SC1091
source "${here}/XRAY.env"

[[ $# -eq 2 ]] || {
    printf 'Usage: %s ARCH OUTPUT_ZIP\n' "$0" >&2
    exit 2
}
readonly architecture=$1
readonly output=$2
case $architecture in
    amd64)
        readonly asset=$XRAY_AMD64_ASSET
        readonly expected_sha256=$XRAY_AMD64_SHA256
        ;;
    arm64)
        readonly asset=$XRAY_ARM64_ASSET
        readonly expected_sha256=$XRAY_ARM64_SHA256
        ;;
    *)
        printf 'unsupported Xray architecture: %s\n' "$architecture" >&2
        exit 2
        ;;
esac

[[ $XRAY_RELEASE_BASE == "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}" ]] || {
    printf 'Xray release URL is not tied to the pinned version\n' >&2
    exit 1
}
[[ $expected_sha256 =~ ^[0-9a-f]{64}$ ]] || {
    printf 'invalid pinned Xray SHA256\n' >&2
    exit 1
}
for command in cp curl sha256sum unzip; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

output_directory=$(unset CDPATH; cd -- "$(dirname -- "$output")" && pwd)
readonly output_directory
output_path=${output_directory}/$(basename -- "$output")
readonly output_path
temporary_output=$(mktemp "${output_directory}/.xray.XXXXXX")
cleanup() {
    rm -f -- "$temporary_output"
}
trap cleanup EXIT

if [[ -n ${V3NODE_XRAY_ARCHIVE:-} ]]; then
    [[ -f $V3NODE_XRAY_ARCHIVE && ! -L $V3NODE_XRAY_ARCHIVE ]] || {
        printf 'local Xray input is not a regular file\n' >&2
        exit 1
    }
    cp -- "$V3NODE_XRAY_ARCHIVE" "$temporary_output"
else
    curl \
        --proto '=https' \
        --tlsv1.2 \
        --fail \
        --location \
        --silent \
        --show-error \
        --retry 3 \
        --retry-all-errors \
        --connect-timeout 15 \
        --max-time 300 \
        --output "$temporary_output" \
        "${XRAY_RELEASE_BASE}/${asset}"
fi
printf '%s  %s\n' "$expected_sha256" "$temporary_output" | sha256sum --check --strict --status
unzip -tq "$temporary_output" >/dev/null
unzip -Z1 "$temporary_output" | grep -Fx 'xray' >/dev/null || {
    printf 'verified Xray archive does not contain the xray binary\n' >&2
    exit 1
}
install -m 0644 -- "$temporary_output" "$output_path"
