#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

[[ $# -eq 5 ]] || {
    printf 'Usage: %s VERSION COMMIT SOURCE_DATE_EPOCH ARCH OUTPUT\n' "$0" >&2
    exit 2
}

readonly version=$1
readonly commit=$2
readonly source_date_epoch=$3
readonly architecture=$4
readonly output=$5

[[ $version =~ ^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$ ]] || {
    printf 'invalid release version: %s\n' "$version" >&2
    exit 2
}
[[ $commit =~ ^[0-9a-f]{40}$ ]] || {
    printf 'commit must be a full lowercase Git SHA-1\n' >&2
    exit 2
}
[[ $source_date_epoch =~ ^[0-9]+$ ]] || {
    printf 'SOURCE_DATE_EPOCH must be a non-negative integer\n' >&2
    exit 2
}
case $architecture in
    amd64|arm64) ;;
    *)
        printf 'unsupported controller architecture: %s\n' "$architecture" >&2
        exit 2
        ;;
esac

for command in cmp date go install mktemp; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

built_at=$(date --utc --date="@${source_date_epoch}" '+%Y-%m-%dT%H:%M:%SZ')
readonly built_at
output_directory=$(unset CDPATH; cd -- "$(dirname -- "$output")" && pwd)
readonly output_directory
output_path=${output_directory}/$(basename -- "$output")
readonly output_path
temporary_output=$(mktemp "${output_directory}/.v3node.XXXXXX")
verification_output=$(mktemp "${output_directory}/.v3node-verify.XXXXXX")
cleanup() {
    rm -f -- "$temporary_output" "$verification_output"
}
trap cleanup EXIT

GOTOOLCHAIN=local go mod verify

build_controller() {
    local destination=$1
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH="$architecture" \
    GOTOOLCHAIN=local \
    go build \
        -mod=readonly \
        -buildvcs=false \
        -trimpath \
        -ldflags "-s -w -buildid= -X=main.version=${version} -X=main.commit=${commit} -X=main.builtAt=${built_at}" \
        -o "$destination" \
        ./cmd/v3node
}

build_controller "$temporary_output"
build_controller "$verification_output"
cmp --silent -- "$temporary_output" "$verification_output" || {
    printf 'controller build is not reproducible within this runner\n' >&2
    exit 1
}
install -m 0755 -- "$temporary_output" "$output_path"
