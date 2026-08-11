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

apply_patch=false
if [[ ${1:-} == --apply-patch ]]; then
    apply_patch=true
    shift
fi
[[ $# -eq 1 ]] || {
    printf 'Usage: %s [--apply-patch] DESTINATION_DIRECTORY\n' "$0" >&2
    exit 2
}
readonly destination=$1

[[ $SING_BOX_COMMIT =~ ^[0-9a-f]{40}$ ]] || {
    printf 'invalid pinned sing-box commit\n' >&2
    exit 1
}
[[ $SING_BOX_SOURCE_SHA256 =~ ^[0-9a-f]{64}$ ]] || {
    printf 'invalid pinned sing-box source SHA256\n' >&2
    exit 1
}
[[ $SING_BOX_SOURCE_URL == "https://codeload.github.com/SagerNet/sing-box/tar.gz/${SING_BOX_COMMIT}" ]] || {
    printf 'sing-box source URL is not tied to the pinned commit\n' >&2
    exit 1
}
[[ ! -e $destination ]] || {
    printf 'destination already exists: %s\n' "$destination" >&2
    exit 1
}

for command in cp curl patch sha256sum tar; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

destination_parent=$(unset CDPATH; cd -- "$(dirname -- "$destination")" && pwd)
readonly destination_parent
destination_path=${destination_parent}/$(basename -- "$destination")
readonly destination_path
work_directory=$(mktemp -d "${destination_parent}/.sing-box-source.XXXXXX")
cleanup() {
    rm -rf -- "$work_directory"
}
trap cleanup EXIT

readonly archive=${work_directory}/upstream.tar.gz
if [[ -n ${V3NODE_SING_BOX_SOURCE_ARCHIVE:-} ]]; then
    [[ -f $V3NODE_SING_BOX_SOURCE_ARCHIVE && ! -L $V3NODE_SING_BOX_SOURCE_ARCHIVE ]] || {
        printf 'local sing-box source input is not a regular file\n' >&2
        exit 1
    }
    cp -- "$V3NODE_SING_BOX_SOURCE_ARCHIVE" "$archive"
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
        --output "$archive" \
        "$SING_BOX_SOURCE_URL"
fi
printf '%s  %s\n' "$SING_BOX_SOURCE_SHA256" "$archive" | sha256sum --check --strict --status

readonly expected_root=sing-box-${SING_BOX_COMMIT}
while IFS= read -r entry; do
    [[ -n $entry ]] || continue
    case $entry in
        /*|../*|*/../*|*/..)
            printf 'unsafe path in sing-box source archive: %s\n' "$entry" >&2
            exit 1
            ;;
    esac
    [[ ${entry%%/*} == "$expected_root" ]] || {
        printf 'unexpected root in sing-box source archive: %s\n' "$entry" >&2
        exit 1
    }
done < <(tar -tzf "$archive")

mkdir "${work_directory}/extract"
tar -xzf "$archive" --no-same-owner --no-same-permissions -C "${work_directory}/extract"
readonly source_directory=${work_directory}/extract/${expected_root}
[[ -d $source_directory ]] || {
    printf 'pinned sing-box source root is missing\n' >&2
    exit 1
}
grep -Fqx 'module github.com/sagernet/sing-box' "${source_directory}/go.mod" || {
    printf 'unexpected module in sing-box source archive\n' >&2
    exit 1
}
[[ -f ${source_directory}/LICENSE ]] || {
    printf 'upstream sing-box LICENSE is missing\n' >&2
    exit 1
}

if [[ $apply_patch == true ]]; then
    for patch_file in \
        "${project_root}/engine-patches/sing-box/0001-expose-authenticated-user.patch" \
        "${project_root}/engine-patches/sing-box/0002-bounded-user-rate-limit.patch"; do
        patch --batch --forward -d "$source_directory" -p1 <"$patch_file"
    done
fi

mv -- "$source_directory" "$destination_path"
trap - EXIT
rm -rf -- "$work_directory"
