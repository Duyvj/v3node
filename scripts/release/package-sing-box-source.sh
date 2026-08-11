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
# Resolved from the script's canonical directory.
# shellcheck disable=SC1091
source "${project_root}/scripts/release/TOOLCHAIN.env"

[[ $# -eq 2 ]] || {
    printf 'Usage: %s SOURCE_DATE_EPOCH OUTPUT_ARCHIVE\n' "$0" >&2
    exit 2
}
readonly source_date_epoch=$1
readonly output=$2
[[ $source_date_epoch =~ ^[0-9]+$ ]] || {
    printf 'SOURCE_DATE_EPOCH must be a non-negative integer\n' >&2
    exit 2
}

for command in find go gzip install mktemp sha256sum tar; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

output_directory=$(unset CDPATH; cd -- "$(dirname -- "$output")" && pwd)
readonly output_directory
output_path=${output_directory}/$(basename -- "$output")
readonly output_path
readonly archive_root=v3node-edge-${SING_BOX_VERSION}-p2-source
work_directory=$(mktemp -d "${output_directory}/.sing-box-package.XXXXXX")
temporary_output=$(mktemp "${output_directory}/.sing-box-source.XXXXXX")
cleanup() {
    rm -rf -- "$work_directory"
    rm -f -- "$temporary_output"
}
trap cleanup EXIT

bash "${here}/fetch-sing-box-source.sh" --apply-patch "${work_directory}/${archive_root}"
readonly source_directory=${work_directory}/${archive_root}
GOTOOLCHAIN=local go run -mod=readonly \
    "${project_root}/scripts/release/linked_vendor.go" \
    --source "$source_directory" \
    --tags "$SING_BOX_BUILD_TAGS"
[[ -f ${source_directory}/vendor/modules.txt ]] || {
    printf 'vendored module manifest was not created\n' >&2
    exit 1
}
mkdir "${source_directory}/V3NODE-PATCHES"
install -m 0644 \
    "${project_root}/engine-patches/sing-box/0001-expose-authenticated-user.patch" \
    "${source_directory}/V3NODE-PATCHES/0001-expose-authenticated-user.patch"
install -m 0644 \
    "${project_root}/engine-patches/sing-box/0002-bounded-user-rate-limit.patch" \
    "${source_directory}/V3NODE-PATCHES/0002-bounded-user-rate-limit.patch"
install -m 0644 \
    "${project_root}/engine-patches/sing-box/UPSTREAM.env" \
    "${source_directory}/V3NODE-PATCHES/UPSTREAM.env"
install -m 0644 \
    "${project_root}/engine-patches/sing-box/README.md" \
    "${source_directory}/V3NODE-PATCHES/README.md"
install -m 0644 \
    "${project_root}/engine-patches/sing-box/UPSTREAM_LICENSE" \
    "${source_directory}/V3NODE-PATCHES/UPSTREAM_LICENSE"
install -m 0644 \
    "${project_root}/LICENSES/GPL-3.0.txt" \
    "${source_directory}/V3NODE-PATCHES/GPL-3.0.txt"
install -m 0644 \
    "${project_root}/scripts/release/TOOLCHAIN.env" \
    "${source_directory}/V3NODE-PATCHES/TOOLCHAIN.env"
install -m 0755 \
    "${project_root}/engine-patches/sing-box/build.sh" \
    "${source_directory}/V3NODE-PATCHES/build.sh"
install -m 0644 \
    "${project_root}/scripts/release/linked_vendor.go" \
    "${source_directory}/V3NODE-PATCHES/linked_vendor.go"
patch_one_sha256=$(sha256sum "${project_root}/engine-patches/sing-box/0001-expose-authenticated-user.patch" | awk '{print $1}')
readonly patch_one_sha256
patch_two_sha256=$(sha256sum "${project_root}/engine-patches/sing-box/0002-bounded-user-rate-limit.patch" | awk '{print $1}')
readonly patch_two_sha256
linked_vendor_sha256=$(sha256sum "${project_root}/scripts/release/linked_vendor.go" | awk '{print $1}')
readonly linked_vendor_sha256
{
    printf 'Upstream: https://github.com/SagerNet/sing-box\n'
    printf 'Version: %s\n' "$SING_BOX_VERSION"
    printf 'Commit: %s\n' "$SING_BOX_COMMIT"
    printf 'Source URL: %s\n' "$SING_BOX_SOURCE_URL"
    printf 'Upstream source SHA256: %s\n' "$SING_BOX_SOURCE_SHA256"
    printf 'Patch 0001 SHA256: %s\n' "$patch_one_sha256"
    printf 'Patch 0002 SHA256: %s\n' "$patch_two_sha256"
    printf 'Linked vendor builder SHA256: %s\n' "$linked_vendor_sha256"
    printf 'Build tags: %s\n' "$SING_BOX_BUILD_TAGS"
    printf 'Release Go version: %s\n' "$V3NODE_RELEASE_GO_VERSION"
    printf 'Module source: vendor/ (exact linux/amd64+arm64 release dependency closure)\n'
} >"${source_directory}/V3NODE-BUILD-METADATA.txt"

find "$source_directory" -type d -exec chmod 0755 {} +
find "$source_directory" -type f -perm /111 -exec chmod 0755 {} +
find "$source_directory" -type f ! -perm /111 -exec chmod 0644 {} +

tar \
    --sort=name \
    --format=gnu \
    --mtime="@${source_date_epoch}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$work_directory" \
    -cf - \
    "$archive_root" | gzip -9 -n >"$temporary_output"
install -m 0644 -- "$temporary_output" "$output_path"
