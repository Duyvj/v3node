#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077

# This branch bootstrap stays small and pins a reviewed release. The release
# installer carries the architecture-specific artifact hashes and rollback
# logic; never execute an unverified second-stage script.
readonly V3NODE_BOOTSTRAP_VERSION=0.3.0-beta.2
readonly RELEASE_BASE="https://github.com/Duyvj/v3node/releases/download/v${V3NODE_BOOTSTRAP_VERSION}"

work_directory=

log() {
    printf 'v3node-bootstrap: %s\n' "$*"
}

die() {
    log "ERROR: $*" >&2
    exit 1
}

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n ${work_directory:-} && -d $work_directory ]]; then
        rm -rf --one-file-system -- "$work_directory"
    fi
    exit "$status"
}
trap cleanup EXIT

fetch() {
    local url=$1 destination=$2
    case $url in
        https://github.com/Duyvj/v3node/releases/download/v${V3NODE_BOOTSTRAP_VERSION}/*) ;;
        *) die "refusing unexpected download URL: ${url}" ;;
    esac
    if command -v curl >/dev/null 2>&1; then
        curl \
            --proto '=https' \
            --tlsv1.2 \
            --fail \
            --location \
            --silent \
            --show-error \
            --retry 3 \
            --connect-timeout 15 \
            --max-time 300 \
            --output "$destination" \
            "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget \
            --quiet \
            --https-only \
            --secure-protocol=TLSv1_2 \
            --timeout=30 \
            --tries=3 \
            --output-document="$destination" \
            "$url"
    else
        die 'curl or wget is required'
    fi
}

main() {
    local expected actual install_bytes checksum_bytes
    command -v bash >/dev/null 2>&1 || die 'bash is required'
    command -v sha256sum >/dev/null 2>&1 || die 'sha256sum is required'
    command -v awk >/dev/null 2>&1 || die 'awk is required'
    command -v stat >/dev/null 2>&1 || die 'stat is required'

    work_directory=$(mktemp -d /tmp/v3node-bootstrap.XXXXXX)
    chmod 0700 "$work_directory"
    fetch "${RELEASE_BASE}/install.sh" "$work_directory/install.sh"
    fetch "${RELEASE_BASE}/SHA256SUMS" "$work_directory/SHA256SUMS"

    install_bytes=$(stat --format='%s' -- "$work_directory/install.sh")
    checksum_bytes=$(stat --format='%s' -- "$work_directory/SHA256SUMS")
    (( install_bytes > 0 && install_bytes <= 2097152 )) || die 'release installer has an invalid size'
    (( checksum_bytes > 0 && checksum_bytes <= 1048576 )) || die 'release checksum file has an invalid size'

    expected=$(awk '
        $2 == "install.sh" {
            count++
            digest = $1
        }
        END {
            if (count != 1) {
                exit 1
            }
            print digest
        }
    ' "$work_directory/SHA256SUMS") || die 'release checksum file has no unique install.sh entry'
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die 'release installer checksum is invalid'
    actual=$(sha256sum "$work_directory/install.sh" | awk '{print $1}')
    [[ $actual == "$expected" ]] || die 'release installer checksum mismatch'

    chmod 0700 "$work_directory/install.sh"
    log "verified v${V3NODE_BOOTSTRAP_VERSION}; starting release installer"
    env -u BASH_ENV -u ENV bash --noprofile --norc "$work_directory/install.sh" "$@"
}

main "$@"
