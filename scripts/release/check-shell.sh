#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

here=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
readonly here
project_root=$(unset CDPATH; cd -- "${here}/../.." && pwd)
readonly project_root

for command in awk bash cmp diff mktemp shellcheck; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

readonly -a scripts=(
    "${project_root}/deploy/v3node-tune"
    "${project_root}"/deploy/*.sh
    "${project_root}"/engine-patches/sing-box/*.sh
    "${project_root}"/scripts/release/*.sh
)

shellcheck -x "${scripts[@]}"
bash -n "${scripts[@]}"

temporary_directory=$(mktemp -d)
cleanup() {
    rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

extract_heredoc() {
    local marker=$1 source_file=$2 destination=$3
    awk -v marker="$marker" '
        {
            line = $0
            sub(/\r$/, "", line)
        }
        !capturing && index(line, "<<") && index(line, marker) {
            found++
            capturing = 1
            next
        }
        capturing && line == marker {
            closed++
            capturing = 0
            next
        }
        capturing {
            print line
        }
        END {
            if (found != 1 || closed != 1 || capturing) {
                exit 1
            }
        }
    ' "$source_file" >"$destination"
}

readonly -a embedded_assets=(
    "UNIT_EOF|deploy/v3node.service|data"
    "CONFIG_EOF|config.example.json|data"
    "EDGE_LICENSE_EOF|engine-patches/sing-box/UPSTREAM_LICENSE|data"
    "TUNE_EOF|deploy/v3node-tune|script"
    "UNINSTALL_EOF|deploy/uninstall.sh|script"
)

for asset in "${embedded_assets[@]}"; do
    IFS='|' read -r marker source kind <<<"$asset"
    embedded_file=${temporary_directory}/${marker}
    source_file=${project_root}/${source}
    extract_heredoc "$marker" "${project_root}/deploy/install.sh" "$embedded_file"
    if ! cmp --silent -- "$source_file" "$embedded_file"; then
        printf 'embedded %s is out of sync with %s\n' "$marker" "$source" >&2
        diff -u -- "$source_file" "$embedded_file" >&2 || true
        exit 1
    fi
    if [[ $kind == script ]]; then
        shellcheck -s bash "$embedded_file"
        bash -n "$embedded_file"
    fi
done

read_setting() {
    local file=$1 prefix=$2 key=$3
    awk -v setting="${prefix}${key}=" '
        index($0, setting) == 1 {
            count++
            value = substr($0, length(setting) + 1)
        }
        END {
            if (count != 1) {
                exit 1
            }
            if (value ~ /^".*"$/) {
                value = substr(value, 2, length(value) - 2)
            }
            print value
        }
    ' "$file"
}

assert_same_setting() {
    local left_file=$1 left_prefix=$2 right_file=$3 right_prefix=$4 key=$5 left_value right_value
    left_value=$(read_setting "$left_file" "$left_prefix" "$key")
    right_value=$(read_setting "$right_file" "$right_prefix" "$key")
    [[ $left_value == "$right_value" ]] || {
        printf '%s differs between %s and %s\n' "$key" "$left_file" "$right_file" >&2
        exit 1
    }
}

readonly installer=${project_root}/deploy/install.sh
readonly manifest=${project_root}/deploy/release-manifest.env
readonly sing_box_env=${project_root}/engine-patches/sing-box/UPSTREAM.env
readonly xray_env=${project_root}/scripts/release/XRAY.env

for key in \
    V3NODE_VERSION \
    V3NODE_AMD64_ASSET \
    V3NODE_ARM64_ASSET \
    V3NODE_AMD64_SHA256 \
    V3NODE_ARM64_SHA256 \
    SING_BOX_VERSION \
    SING_BOX_COMMIT \
    SING_BOX_BUILD_TAGS \
    SING_BOX_AMD64_ASSET \
    SING_BOX_ARM64_ASSET \
    SING_BOX_AMD64_SHA256 \
    SING_BOX_ARM64_SHA256 \
    XRAY_VERSION \
    XRAY_COMMIT \
    XRAY_AMD64_ASSET \
    XRAY_ARM64_ASSET \
    XRAY_AMD64_SHA256 \
    XRAY_ARM64_SHA256; do
    assert_same_setting "$installer" 'readonly ' "$manifest" '' "$key"
done

for key in \
    SING_BOX_VERSION \
    SING_BOX_COMMIT \
    SING_BOX_SOURCE_SHA256 \
    SING_BOX_BUILD_TAGS; do
    assert_same_setting "$sing_box_env" '' "$manifest" '' "$key"
done
for key in \
    XRAY_VERSION \
    XRAY_COMMIT \
    XRAY_RELEASE_BASE \
    XRAY_AMD64_ASSET \
    XRAY_ARM64_ASSET \
    XRAY_AMD64_SHA256 \
    XRAY_ARM64_SHA256; do
    assert_same_setting "$xray_env" '' "$manifest" '' "$key"
done

patchset=$(read_setting "$manifest" '' SING_BOX_PATCHSET)
IFS=',' read -r -a patch_files <<<"$patchset"
[[ ${#patch_files[@]} -gt 0 ]] || {
    printf 'release manifest has an empty sing-box patchset\n' >&2
    exit 1
}
for patch_file in "${patch_files[@]}"; do
    [[ $patch_file != /* && $patch_file != *'..'* && -f ${project_root}/${patch_file} ]] || {
        printf 'release manifest references an invalid sing-box patch: %s\n' "$patch_file" >&2
        exit 1
    }
done
