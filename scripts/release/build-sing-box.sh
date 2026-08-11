#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

here=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
readonly here
project_root=$(unset CDPATH; cd -- "${here}/../.." && pwd)
readonly project_root

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

bash "${here}/fetch-sing-box-source.sh" "${work_directory}/source"
# Release binaries are built from the same vendored dependency layout shipped
# in Corresponding Source. Besides enabling a fully offline rebuild, this keeps
# Go's embedded module build information bit-for-bit consistent.
(
    cd "${work_directory}/source"
    GOTOOLCHAIN=local go mod download
    GOTOOLCHAIN=local go mod verify
    GOTOOLCHAIN=local go mod vendor
)
TARGET_GOOS=linux TARGET_GOARCH="$architecture" \
    bash "${project_root}/engine-patches/sing-box/build.sh" \
    "${work_directory}/source" \
    "$output_path"
