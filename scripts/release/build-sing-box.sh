#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

here=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
readonly here
project_root=$(unset CDPATH; cd -- "${here}/../.." && pwd)
readonly project_root
# Resolved from the script's canonical directory.
# shellcheck disable=SC1091
source "${project_root}/engine-patches/sing-box/UPSTREAM.env"

[[ $# -eq 2 ]] || {
    printf 'Usage: %s ARCH OUTPUT_BINARY\n' "$0" >&2
    exit 2
}
readonly architecture=$1
readonly output=$2
case $architecture in
    amd64|arm64) ;;
    *)
        printf 'unsupported sing-box architecture: %s\n' "$architecture" >&2
        exit 2
        ;;
esac

output_directory=$(unset CDPATH; cd -- "$(dirname -- "$output")" && pwd)
readonly output_directory
output_path=${output_directory}/$(basename -- "$output")
readonly output_path
work_directory=$(mktemp -d "${output_directory}/.sing-box-build.XXXXXX")
cleanup() {
    rm -rf -- "$work_directory"
}
trap cleanup EXIT

bash "${here}/fetch-sing-box-source.sh" --apply-patch "${work_directory}/source"
# Release binaries are built from the same linked-source vendor layout shipped
# in Corresponding Source. Optional modules behind disabled sing-box build tags
# are not part of the binary and are intentionally not downloaded or bundled.
GOTOOLCHAIN=local go run -mod=readonly \
    "${project_root}/scripts/release/linked_vendor.go" \
    --source "${work_directory}/source" \
    --tags "$SING_BOX_BUILD_TAGS"
TARGET_GOOS=linux TARGET_GOARCH="$architecture" \
    bash "${project_root}/engine-patches/sing-box/build.sh" \
    "${work_directory}/source" \
    "$output_path"
