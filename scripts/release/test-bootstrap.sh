#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# The test script doubles as the harmless downloaded installer. Keeping the
# fixture here makes its checksum deterministic and avoids maintaining another
# executable file solely for this test.
if [[ ${V3NODE_BOOTSTRAP_FIXTURE_MODE:-0} == 1 ]]; then
    : "${V3NODE_BOOTSTRAP_ARGUMENT_CAPTURE:?argument capture is required}"
    printf '%s\0' "$@" >"$V3NODE_BOOTSTRAP_ARGUMENT_CAPTURE"
    exit 0
fi

here=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
readonly here
project_root=$(unset CDPATH; cd -- "${here}/../.." && pwd)
readonly project_root
readonly bootstrap=${project_root}/script/install.sh

for required_command in awk bash cmp cp grep mktemp sha256sum; do
    command -v "$required_command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$required_command" >&2
        exit 1
    }
done

temporary_directory=$(mktemp -d)
cleanup() {
    rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

readonly fixture_installer=${project_root}/scripts/release/test-bootstrap.sh
readonly fixture_checksums=${temporary_directory}/SHA256SUMS
fixture_digest=$(sha256sum "$fixture_installer" | awk '{print $1}')
readonly fixture_digest
# Match GNU sha256sum's default text-mode format used by assemble-release.sh.
printf '%s  install.sh\n' "$fixture_digest" >"$fixture_checksums"

export V3NODE_BOOTSTRAP_FIXTURE_INSTALLER=$fixture_installer
export V3NODE_BOOTSTRAP_FIXTURE_CHECKSUMS=$fixture_checksums
export V3NODE_BOOTSTRAP_FIXTURE_MODE=1
unset V3NODE_BOOTSTRAP_CORRUPT_INSTALLER

# This function is exported into the bootstrap's Bash process. The preflight
# below fails before the bootstrap is called if Bash cannot import it, which
# guarantees that this test never falls through to a real network client.
# shellcheck disable=SC2317,SC2329
curl() {
    local destination='' url='' source='' argument=''
    while (( $# > 0 )); do
        argument=$1
        case $argument in
            --output)
                (( $# >= 2 )) || return 64
                destination=$2
                shift 2
                ;;
            https://*)
                url=$argument
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    [[ -n $destination && -n $url ]] || return 64
    case $url in
        */install.sh) source=$V3NODE_BOOTSTRAP_FIXTURE_INSTALLER ;;
        */SHA256SUMS) source=$V3NODE_BOOTSTRAP_FIXTURE_CHECKSUMS ;;
        *) return 65 ;;
    esac

    printf '%s\0' "$url" >>"$V3NODE_BOOTSTRAP_URL_CAPTURE"
    command cp -- "$source" "$destination"
    if [[ $url == */install.sh && ${V3NODE_BOOTSTRAP_CORRUPT_INSTALLER:-0} == 1 ]]; then
        printf '\n# checksum-test-corruption\n' >>"$destination"
    fi
}
export -f curl

# The command substitution is intentionally evaluated by the child Bash.
# shellcheck disable=SC2016
env -u BASH_ENV -u ENV bash --noprofile --norc -c \
    "[[ \$(type -t curl) == function ]]" || {
    printf 'Bash cannot import the offline curl fixture\n' >&2
    exit 1
}

readonly -a original_arguments=(
    '--api-host'
    'https://panel.example.com/path?first=one&second=two'
    '--node-id'
    '73'
    '--api-key'
    'key with spaces * ? [literal]'
    ''
    $'line one\nline two'
)
readonly expected_arguments=${temporary_directory}/expected.arguments
readonly actual_arguments=${temporary_directory}/actual.arguments
readonly expected_urls=${temporary_directory}/expected.urls
readonly actual_urls=${temporary_directory}/actual.urls
export V3NODE_BOOTSTRAP_ARGUMENT_CAPTURE=$actual_arguments
export V3NODE_BOOTSTRAP_URL_CAPTURE=$actual_urls

printf '%s\0' "${original_arguments[@]}" >"$expected_arguments"
bootstrap_version=$(awk -F= '
    $1 == "readonly V3NODE_BOOTSTRAP_VERSION" {
        count++
        version = $2
    }
    END {
        if (count != 1 || version == "") {
            exit 1
        }
        print version
    }
' "$bootstrap")
readonly bootstrap_version
readonly release_base="https://github.com/Duyvj/v3node/releases/download/v${bootstrap_version}"
printf '%s\0%s\0' \
    "${release_base}/install.sh" \
    "${release_base}/SHA256SUMS" >"$expected_urls"

bash "$bootstrap" "${original_arguments[@]}" >/dev/null
cmp --silent -- "$expected_arguments" "$actual_arguments" || {
    printf 'bootstrap did not preserve installer arguments byte-for-byte\n' >&2
    exit 1
}
cmp --silent -- "$expected_urls" "$actual_urls" || {
    printf 'bootstrap requested unexpected release URLs\n' >&2
    exit 1
}

readonly corrupt_arguments=${temporary_directory}/corrupt.arguments
readonly corrupt_stderr=${temporary_directory}/corrupt.stderr
export V3NODE_BOOTSTRAP_ARGUMENT_CAPTURE=$corrupt_arguments
export V3NODE_BOOTSTRAP_URL_CAPTURE=${temporary_directory}/corrupt.urls
export V3NODE_BOOTSTRAP_CORRUPT_INSTALLER=1
if bash "$bootstrap" "${original_arguments[@]}" \
    >"${temporary_directory}/corrupt.stdout" 2>"$corrupt_stderr"; then
    printf 'bootstrap accepted an installer with a mismatched checksum\n' >&2
    exit 1
fi
grep -Fq 'release installer checksum mismatch' "$corrupt_stderr" || {
    printf 'bootstrap corruption test failed for an unexpected reason\n' >&2
    exit 1
}
[[ ! -e $corrupt_arguments ]] || {
    printf 'bootstrap executed an installer with a mismatched checksum\n' >&2
    exit 1
}

printf 'bootstrap checksum and argument-forwarding tests passed\n'
