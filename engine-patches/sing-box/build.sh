#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

here=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
readonly here
# Resolved from the script's canonical directory.
# shellcheck disable=SC1091
source "${here}/UPSTREAM.env"
patch_files=(
    "${here}/0001-expose-authenticated-user.patch"
    "${here}/0002-bounded-user-rate-limit.patch"
)
readonly patch_files

[[ $# -eq 2 ]] || {
    printf 'Usage: %s SOURCE_DIRECTORY OUTPUT_BINARY\n' "$0" >&2
    exit 2
}
readonly source_directory=$1
readonly output_binary=$2
command -v go >/dev/null 2>&1 || {
    printf 'Go is required\n' >&2
    exit 1
}
readonly target_goos=${TARGET_GOOS:-linux}
readonly target_goarch=${TARGET_GOARCH:-$(go env GOARCH)}

case $target_goos in
    linux) ;;
    *)
        printf 'unsupported target operating system: %s\n' "$target_goos" >&2
        exit 2
        ;;
esac
case $target_goarch in
    amd64|arm64) ;;
    *)
        printf 'unsupported target architecture: %s\n' "$target_goarch" >&2
        exit 2
        ;;
esac

[[ -f "${source_directory}/go.mod" ]] || {
    printf 'sing-box source directory is invalid\n' >&2
    exit 1
}
command -v patch >/dev/null 2>&1 || {
    printf 'patch is required\n' >&2
    exit 1
}

output_directory=$(unset CDPATH; cd -- "$(dirname -- "$output_binary")" && pwd)
readonly output_directory
output_path=${output_directory}/$(basename -- "$output_binary")
readonly output_path
module_mode='readonly'
if [[ -f ${source_directory}/vendor/modules.txt ]]; then
    module_mode=vendor
fi
readonly module_mode
temporary_output=$(mktemp "${output_directory}/.sing-box.XXXXXX")
verification_output=$(mktemp "${output_directory}/.sing-box-verify.XXXXXX")
cleanup() {
    rm -f -- "$temporary_output" "$verification_output"
}
trap cleanup EXIT

(
    cd "$source_directory"
    grep -Fqx 'module github.com/sagernet/sing-box' go.mod || {
        printf 'unexpected sing-box module path\n' >&2
        exit 1
    }
    for patch_file in "${patch_files[@]}"; do
        if patch --batch --forward --dry-run -p1 \
            <"$patch_file" >/dev/null 2>&1; then
            patch --batch --forward -p1 <"$patch_file"
        elif patch --batch --reverse --dry-run -p1 \
            <"$patch_file" >/dev/null 2>&1; then
            printf 'sing-box source already contains %s\n' "$(basename -- "$patch_file")"
        else
            printf 'sing-box patch does not apply cleanly: %s\n' "$(basename -- "$patch_file")" >&2
            exit 1
        fi
    done
    if [[ $module_mode == 'readonly' ]]; then
        GOTOOLCHAIN=local go mod verify
    fi
    if [[ $(go env GOOS) == "$target_goos" ]]; then
        env -u GOOS -u GOARCH CGO_ENABLED=0 GOTOOLCHAIN=local go test \
            -mod="$module_mode" \
            -tags "$SING_BOX_BUILD_TAGS" \
            ./experimental/clashapi/trafficontrol \
            ./experimental/v3node
    else
        printf 'cross-host build: runtime patch tests are validated separately\n'
    fi

    shared_ldflags=$(<release/LDFLAGS)
    readonly shared_ldflags
    [[ -n $shared_ldflags ]] || {
        printf 'upstream shared linker flags are missing\n' >&2
        exit 1
    }

    build_engine() {
        local destination=$1
        CGO_ENABLED=0 \
        GOOS="$target_goos" \
        GOARCH="$target_goarch" \
        GOTOOLCHAIN=local \
        go build \
            -mod="$module_mode" \
            -buildvcs=false \
            -trimpath \
            -tags "$SING_BOX_BUILD_TAGS" \
            -ldflags "-X=github.com/sagernet/sing-box/constant.Version=${SING_BOX_VERSION} ${shared_ldflags} -s -w -buildid=" \
            -o "$destination" \
            ./cmd/sing-box
    }

    build_engine "$temporary_output"
    build_engine "$verification_output"
)

cmp --silent -- "$temporary_output" "$verification_output" || {
    printf 'sing-box build is not reproducible within this runner\n' >&2
    exit 1
}
install -m 0755 -- "$temporary_output" "$output_path"
