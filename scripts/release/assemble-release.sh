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
source "${project_root}/scripts/release/XRAY.env"

[[ $# -eq 2 ]] || {
    printf 'Usage: %s VERSION DIST_DIRECTORY\n' "$0" >&2
    exit 2
}
readonly version=$1
readonly dist=$2
[[ $version =~ ^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$ ]] || {
    printf 'invalid release version: %s\n' "$version" >&2
    exit 2
}
[[ -d $dist && ! -L $dist ]] || {
    printf 'distribution directory is invalid\n' >&2
    exit 1
}
dist_path=$(unset CDPATH; cd -- "$dist" && pwd)
readonly dist_path

readonly controller_amd64=${dist_path}/v3node-linux-amd64
readonly controller_arm64=${dist_path}/v3node-linux-arm64
readonly sing_box_amd64=${dist_path}/v3node-edge-${SING_BOX_VERSION}-p1-linux-amd64
readonly sing_box_arm64=${dist_path}/v3node-edge-${SING_BOX_VERSION}-p1-linux-arm64
readonly sing_box_source=${dist_path}/v3node-edge-${SING_BOX_VERSION}-p1-source.tar.gz
for file in \
    "$controller_amd64" \
    "$controller_arm64" \
    "$sing_box_amd64" \
    "$sing_box_arm64" \
    "$sing_box_source"; do
    [[ -f $file && ! -L $file ]] || {
        printf 'required release artifact is missing: %s\n' "$(basename -- "$file")" >&2
        exit 1
    }
done

expected_files=$(printf '%s\n' \
    "$(basename -- "$controller_amd64")" \
    "$(basename -- "$controller_arm64")" \
    "$(basename -- "$sing_box_amd64")" \
    "$(basename -- "$sing_box_arm64")" \
    "$(basename -- "$sing_box_source")" \
    | LC_ALL=C sort)
actual_entries=$(find "$dist_path" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
[[ $actual_entries == "$expected_files" ]] || {
    printf 'distribution directory contains missing or unexpected files\n' >&2
    diff -u <(printf '%s\n' "$expected_files") <(printf '%s\n' "$actual_entries") >&2 || true
    exit 1
}
chmod 0755 "$controller_amd64" "$controller_arm64" "$sing_box_amd64" "$sing_box_arm64"
chmod 0644 "$sing_box_source"

controller_amd64_sha=$(sha256sum "$controller_amd64" | awk '{print $1}')
readonly controller_amd64_sha
controller_arm64_sha=$(sha256sum "$controller_arm64" | awk '{print $1}')
readonly controller_arm64_sha
sing_box_amd64_sha=$(sha256sum "$sing_box_amd64" | awk '{print $1}')
readonly sing_box_amd64_sha
sing_box_arm64_sha=$(sha256sum "$sing_box_arm64" | awk '{print $1}')
readonly sing_box_arm64_sha

replace_readonly() {
    local file=$1 key=$2 value=$3 count
    count=$(grep -Ec "^readonly ${key}=.*$" "$file")
    [[ $count -eq 1 ]] || {
        printf 'expected exactly one readonly %s setting in %s\n' "$key" "$file" >&2
        exit 1
    }
    sed -i -E "s|^readonly ${key}=.*$|readonly ${key}=${value}|" "$file"
}

replace_manifest() {
    local file=$1 key=$2 value=$3 count
    count=$(grep -Ec "^${key}=.*$" "$file")
    [[ $count -eq 1 ]] || {
        printf 'expected exactly one %s setting in %s\n' "$key" "$file" >&2
        exit 1
    }
    sed -i -E "s|^${key}=.*$|${key}=${value}|" "$file"
}

install -m 0755 "${project_root}/deploy/install.sh" "${dist_path}/install.sh"
replace_readonly "${dist_path}/install.sh" V3NODE_VERSION "$version"
replace_readonly "${dist_path}/install.sh" V3NODE_AMD64_SHA256 "$controller_amd64_sha"
replace_readonly "${dist_path}/install.sh" V3NODE_ARM64_SHA256 "$controller_arm64_sha"
replace_readonly "${dist_path}/install.sh" SING_BOX_AMD64_SHA256 "$sing_box_amd64_sha"
replace_readonly "${dist_path}/install.sh" SING_BOX_ARM64_SHA256 "$sing_box_arm64_sha"

install -m 0644 "${project_root}/deploy/release-manifest.env" "${dist_path}/release-manifest.env"
replace_manifest "${dist_path}/release-manifest.env" V3NODE_VERSION "$version"
replace_manifest "${dist_path}/release-manifest.env" V3NODE_AMD64_SHA256 "$controller_amd64_sha"
replace_manifest "${dist_path}/release-manifest.env" V3NODE_ARM64_SHA256 "$controller_arm64_sha"
replace_manifest "${dist_path}/release-manifest.env" SING_BOX_AMD64_SHA256 "$sing_box_amd64_sha"
replace_manifest "${dist_path}/release-manifest.env" SING_BOX_ARM64_SHA256 "$sing_box_arm64_sha"

assert_readonly() {
    local file=$1 key=$2 value=$3
    grep -Fqx "readonly ${key}=${value}" "$file" \
        || grep -Fqx "readonly ${key}=\"${value}\"" "$file" \
        || {
            printf '%s does not pin tested value for %s\n' "$file" "$key" >&2
            exit 1
        }
}

assert_manifest() {
    local file=$1 key=$2 value=$3
    grep -Fqx "${key}=${value}" "$file" || {
        printf '%s does not pin tested value for %s\n' "$file" "$key" >&2
        exit 1
    }
}

assert_readonly "${dist_path}/install.sh" V3NODE_VERSION "$version"
assert_manifest "${dist_path}/release-manifest.env" V3NODE_VERSION "$version"
assert_readonly "${dist_path}/install.sh" V3NODE_AMD64_SHA256 "$controller_amd64_sha"
assert_manifest "${dist_path}/release-manifest.env" V3NODE_AMD64_SHA256 "$controller_amd64_sha"
assert_readonly "${dist_path}/install.sh" V3NODE_ARM64_SHA256 "$controller_arm64_sha"
assert_manifest "${dist_path}/release-manifest.env" V3NODE_ARM64_SHA256 "$controller_arm64_sha"
assert_readonly "${dist_path}/install.sh" SING_BOX_AMD64_SHA256 "$sing_box_amd64_sha"
assert_manifest "${dist_path}/release-manifest.env" SING_BOX_AMD64_SHA256 "$sing_box_amd64_sha"
assert_readonly "${dist_path}/install.sh" SING_BOX_ARM64_SHA256 "$sing_box_arm64_sha"
assert_manifest "${dist_path}/release-manifest.env" SING_BOX_ARM64_SHA256 "$sing_box_arm64_sha"

assert_readonly \
    "${dist_path}/install.sh" \
    V3NODE_AMD64_ASSET \
    "$(basename -- "$controller_amd64")"
assert_manifest \
    "${dist_path}/release-manifest.env" \
    V3NODE_AMD64_ASSET \
    "$(basename -- "$controller_amd64")"
assert_readonly \
    "${dist_path}/install.sh" \
    V3NODE_ARM64_ASSET \
    "$(basename -- "$controller_arm64")"
assert_manifest \
    "${dist_path}/release-manifest.env" \
    V3NODE_ARM64_ASSET \
    "$(basename -- "$controller_arm64")"

for key in \
    SING_BOX_VERSION \
    SING_BOX_COMMIT \
    SING_BOX_BUILD_TAGS; do
    assert_readonly "${dist_path}/install.sh" "$key" "${!key}"
    assert_manifest "${dist_path}/release-manifest.env" "$key" "${!key}"
done
assert_readonly \
    "${dist_path}/install.sh" \
    SING_BOX_AMD64_ASSET \
    "$(basename -- "$sing_box_amd64")"
assert_manifest \
    "${dist_path}/release-manifest.env" \
    SING_BOX_AMD64_ASSET \
    "$(basename -- "$sing_box_amd64")"
assert_readonly \
    "${dist_path}/install.sh" \
    SING_BOX_ARM64_ASSET \
    "$(basename -- "$sing_box_arm64")"
assert_manifest \
    "${dist_path}/release-manifest.env" \
    SING_BOX_ARM64_ASSET \
    "$(basename -- "$sing_box_arm64")"
assert_manifest \
    "${dist_path}/release-manifest.env" \
    SING_BOX_SOURCE_SHA256 \
    "$SING_BOX_SOURCE_SHA256"
assert_manifest \
    "${dist_path}/release-manifest.env" \
    SING_BOX_PATCHSET \
    engine-patches/sing-box/0001-expose-authenticated-user.patch

for key in \
    XRAY_VERSION \
    XRAY_COMMIT \
    XRAY_AMD64_ASSET \
    XRAY_ARM64_ASSET \
    XRAY_AMD64_SHA256 \
    XRAY_ARM64_SHA256; do
    assert_readonly "${dist_path}/install.sh" "$key" "${!key}"
    assert_manifest "${dist_path}/release-manifest.env" "$key" "${!key}"
done
assert_manifest \
    "${dist_path}/release-manifest.env" \
    XRAY_RELEASE_BASE \
    "$XRAY_RELEASE_BASE"

grep -Fqx \
    "readonly V3NODE_RELEASE_BASE=\"https://github.com/Duyvj/v3node/releases/download/v\${V3NODE_VERSION}\"" \
    "${dist_path}/install.sh" || {
    printf 'generated installer has an unexpected controller release URL\n' >&2
    exit 1
}
grep -Fqx "readonly SING_BOX_RELEASE_BASE=\$V3NODE_RELEASE_BASE" \
    "${dist_path}/install.sh" || {
    printf 'generated installer does not source edge assets from its release\n' >&2
    exit 1
}
grep -Fqx \
    "readonly XRAY_RELEASE_BASE=\"https://github.com/XTLS/Xray-core/releases/download/v\${XRAY_VERSION}\"" \
    "${dist_path}/install.sh" || {
    printf 'generated installer has an unexpected Xray release URL\n' >&2
    exit 1
}

if grep -Eq 'UNPUBLISHED|UNVERIFIED|REPLACE_WITH' "${dist_path}/install.sh" "${dist_path}/release-manifest.env"; then
    printf 'generated release metadata still contains an unpublished placeholder\n' >&2
    exit 1
fi
bash -n "${dist_path}/install.sh"

for legal_file in LICENSE THIRD_PARTY_NOTICES.md; do
    [[ -f ${project_root}/${legal_file} ]] || {
        printf 'required legal file is missing: %s\n' "$legal_file" >&2
        exit 1
    }
    install -m 0644 "${project_root}/${legal_file}" "${dist_path}/${legal_file}"
done

(
    cd "$dist_path"
    checksum_file=$(mktemp .SHA256SUMS.XXXXXX)
    trap 'rm -f -- "$checksum_file"' EXIT
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' \
        | grep -Ev '^[.]SHA256SUMS[.]' \
        | LC_ALL=C sort \
        | xargs -r sha256sum -- \
        >"$checksum_file"
    mv -- "$checksum_file" SHA256SUMS
    trap - EXIT
    sha256sum --check --strict SHA256SUMS
)
