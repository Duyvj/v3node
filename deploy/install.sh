#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

readonly V3NODE_VERSION=0.1.0
readonly V3NODE_RELEASE_BASE="https://github.com/Duyvj/v3node/releases/download/v${V3NODE_VERSION}"
readonly V3NODE_AMD64_ASSET=v3node-linux-amd64
readonly V3NODE_ARM64_ASSET=v3node-linux-arm64
readonly V3NODE_AMD64_SHA256=UNPUBLISHED_REPLACE_WITH_64_HEX_SHA256
readonly V3NODE_ARM64_SHA256=UNPUBLISHED_REPLACE_WITH_64_HEX_SHA256

readonly SING_BOX_VERSION=1.13.18
readonly SING_BOX_COMMIT=45ca32dcb966f07f97fc888fe8586e359dbe8405
readonly SING_BOX_BUILD_TAGS=with_quic,with_grpc,with_v2ray_api,with_clash_api,with_utls
readonly SING_BOX_RELEASE_BASE=$V3NODE_RELEASE_BASE
readonly SING_BOX_AMD64_ASSET=v3node-edge-1.13.18-p2-linux-amd64
readonly SING_BOX_ARM64_ASSET=v3node-edge-1.13.18-p2-linux-arm64
readonly SING_BOX_AMD64_SHA256=UNPUBLISHED_REPLACE_WITH_64_HEX_SHA256
readonly SING_BOX_ARM64_SHA256=UNPUBLISHED_REPLACE_WITH_64_HEX_SHA256

readonly XRAY_VERSION=26.3.27
readonly XRAY_COMMIT=d2758a0
readonly XRAY_RELEASE_BASE="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}"
readonly XRAY_AMD64_ASSET=Xray-linux-64.zip
readonly XRAY_ARM64_ASSET=Xray-linux-arm64-v8a.zip
readonly XRAY_AMD64_SHA256=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
readonly XRAY_ARM64_SHA256=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c

readonly SERVICE=v3node.service
readonly UNIT_FILE=/etc/systemd/system/v3node.service
readonly ENABLE_LINK=/etc/systemd/system/multi-user.target.wants/v3node.service
readonly CONFIG_DIR=/etc/v3node
readonly CONFIG_FILE=${CONFIG_DIR}/config.json
readonly STATE_DIR=/var/lib/v3node
readonly RUN_DIR=/run/v3node
readonly META_DIR=/var/lib/v3node-install
readonly LIB_DIR=/usr/local/lib/v3node
readonly DOC_DIR=/usr/share/doc/v3node
readonly BACKUP_ROOT=/var/backups/v3node

config_source=
token_source=
panel_url=
panel_node_id=
api_key=
local_v3node_file=
local_v3node_sha256=
local_sing_box_file=
local_sing_box_sha256=
local_xray_archive=
local_xray_sha256=
no_start=false
stage_dir=
install_backup=
transaction_active=false
rollback_attempted=false
was_active=false

log() {
    printf 'v3node-install: %s\n' "$*"
}

die() {
    log "ERROR: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: install.sh [options]

  --config FILE             Install FILE as /etc/v3node/config.json.
                            Existing configuration is otherwise preserved.
  --token-file FILE         Install FILE as /etc/v3node/panel.token with
                            root:v3node ownership and mode 0640.
  --panel-url URL           Generate config.json for this panel URL.
  --api-host URL            Compatibility alias for --panel-url.
  --node-id ID              Positive node ID used with --panel-url.
                            Requires --api-key or --token-file and conflicts
                            with --config.
  --api-key KEY             Compatibility alternative to --token-file.
                            WARNING: KEY remains in shell history/process argv;
                            --token-file is recommended for production.
  --v3node-file FILE        Use a local controller binary instead of the
                            versioned release asset.
  --v3node-sha256 SHA256    Required SHA256 for --v3node-file.
  --sing-box-file FILE      Use a project-built sing-box 1.13.18-p2 binary.
  --sing-box-sha256 SHA256  Required SHA256 for --sing-box-file.
  --xray-archive FILE       Use a local official Xray ZIP archive.
  --xray-sha256 SHA256      Required SHA256 for --xray-archive.
  --no-start                Install files but do not enable or start service.
  -h, --help                Show this help.

Supported hosts: Debian 12+, Ubuntu 22.04+, amd64 and arm64, with systemd.
Downloaded assets are accepted only after exact SHA256 verification.
EOF
}

cleanup() {
    local status=$1
    trap - EXIT
    set +e
    if (( status != 0 )) && [[ ${transaction_active:-false} == true && ${rollback_attempted:-false} == false ]]; then
        rollback_failed_installation
    fi
    if [[ -n ${stage_dir:-} && -d ${stage_dir} ]]; then
        rm -rf --one-file-system -- "$stage_dir"
    fi
    exit "$status"
}
trap 'cleanup $?' EXIT

while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            [[ $# -ge 2 ]] || die '--config requires a file'
            config_source=$2
            shift 2
            ;;
        --token-file)
            [[ $# -ge 2 ]] || die '--token-file requires a file'
            token_source=$2
            shift 2
            ;;
        --panel-url|--api-host)
            [[ $# -ge 2 ]] || die "$1 requires a URL"
            panel_url=$2
            shift 2
            ;;
        --node-id)
            [[ $# -ge 2 ]] || die '--node-id requires an integer'
            panel_node_id=$2
            shift 2
            ;;
        --api-key)
            [[ $# -ge 2 ]] || die '--api-key requires a value'
            api_key=$2
            shift 2
            ;;
        --v3node-file)
            [[ $# -ge 2 ]] || die '--v3node-file requires a file'
            local_v3node_file=$2
            shift 2
            ;;
        --v3node-sha256)
            [[ $# -ge 2 ]] || die '--v3node-sha256 requires a digest'
            local_v3node_sha256=${2,,}
            shift 2
            ;;
        --sing-box-file)
            [[ $# -ge 2 ]] || die '--sing-box-file requires a file'
            local_sing_box_file=$2
            shift 2
            ;;
        --sing-box-sha256)
            [[ $# -ge 2 ]] || die '--sing-box-sha256 requires a digest'
            local_sing_box_sha256=${2,,}
            shift 2
            ;;
        --xray-archive)
            [[ $# -ge 2 ]] || die '--xray-archive requires a file'
            local_xray_archive=$2
            shift 2
            ;;
        --xray-sha256)
            [[ $# -ge 2 ]] || die '--xray-sha256 requires a digest'
            local_xray_sha256=${2,,}
            shift 2
            ;;
        --no-start)
            no_start=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown option: $1"
            ;;
    esac
done

is_sha256() {
    [[ $1 =~ ^[0-9a-f]{64}$ ]]
}

require_supported_host() {
    local major version_id
    [[ ${EUID} -eq 0 ]] || die 'run as root'
    [[ $(uname -s) == Linux ]] || die 'Linux is required'
    [[ -r /etc/os-release ]] || die '/etc/os-release is required'
    # /etc/os-release is an operating-system-owned data file.
    # shellcheck disable=SC1091
    source /etc/os-release
    version_id=${VERSION_ID:-}
    major=${version_id%%.*}
    [[ $major =~ ^[0-9]+$ ]] || die 'operating-system version is missing or invalid'
    case ${ID:-}:${major} in
        debian:*) (( major >= 12 )) || die 'Debian 12 or newer is required' ;;
        ubuntu:*) (( major >= 22 )) || die 'Ubuntu 22.04 or newer is required' ;;
        *) die 'only Debian 12+ and Ubuntu 22.04+ are supported' ;;
    esac
    command -v systemctl >/dev/null 2>&1 || die 'systemd/systemctl is required'
    [[ -d /run/systemd/system ]] || die 'systemd must be the active service manager'
}

select_architecture() {
    case $(uname -m) in
        x86_64|amd64)
            arch=amd64
            v3node_asset=$V3NODE_AMD64_ASSET
            v3node_sha256=$V3NODE_AMD64_SHA256
            sing_box_asset=$SING_BOX_AMD64_ASSET
            sing_box_sha256=$SING_BOX_AMD64_SHA256
            xray_asset=$XRAY_AMD64_ASSET
            xray_sha256=$XRAY_AMD64_SHA256
            ;;
        aarch64|arm64)
            arch=arm64
            v3node_asset=$V3NODE_ARM64_ASSET
            v3node_sha256=$V3NODE_ARM64_SHA256
            sing_box_asset=$SING_BOX_ARM64_ASSET
            sing_box_sha256=$SING_BOX_ARM64_SHA256
            xray_asset=$XRAY_ARM64_ASSET
            xray_sha256=$XRAY_ARM64_SHA256
            ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

ensure_dependencies() {
    local missing=false command
    for command in cp curl sha256sum stat install mktemp flock getent id useradd groupadd unzip runuser; do
        command -v "$command" >/dev/null 2>&1 || missing=true
    done
    [[ -r /etc/ssl/certs/ca-certificates.crt ]] || missing=true
    if [[ ${missing} == true ]]; then
        log 'installing required base packages'
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends ca-certificates curl coreutils util-linux passwd unzip
    fi
    for command in cp curl sha256sum stat install mktemp flock getent id useradd groupadd unzip runuser; do
        command -v "$command" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
    done
}

verify_sha256() {
    local file=$1 expected=${2,,} actual
    is_sha256 "$expected" || die "invalid or unpublished SHA256 for $(basename "$file")"
    actual=$(sha256sum -- "$file")
    actual=${actual%% *}
    [[ ${actual,,} == "$expected" ]] || die "SHA256 mismatch for $(basename "$file")"
}

fetch() {
    local url=$1 destination=$2
    [[ $url == https://* ]] || die 'refusing a non-HTTPS download URL'
    case $url in
        *'/raw/'*|*'raw.githubusercontent.com/'*|*'/latest/'*)
            die "refusing an unpinned download URL: ${url}"
            ;;
    esac
    curl \
        --proto '=https' \
        --tlsv1.2 \
        --fail \
        --location \
        --silent \
        --show-error \
        --retry 3 \
        --retry-delay 2 \
        --connect-timeout 10 \
        --max-time 300 \
        --output "$destination" \
        "$url"
}

snapshot_regular_input() {
    local source=$1 destination=$2 description=$3 mode=$4
    [[ -f $source && ! -L $source ]] || die "${description} must reference a regular file"
    cp --archive --no-dereference -- "$source" "$destination"
    [[ -f $destination && ! -L $destination ]] || die "${description} changed while it was being staged"
    chmod "$mode" "$destination"
}

verify_sing_box_features() {
    local binary=$1 output line tags='' tag rate_probe
    local -a required_tags
    output=$("$binary" version) || die 'verified sing-box binary cannot run on this host'
    grep -Fqx "sing-box version ${SING_BOX_VERSION}" <<<"$output" || die "sing-box binary is not version ${SING_BOX_VERSION}"
    grep -Eq "^Environment: go[0-9]+([.][0-9]+)+ linux/${arch}$" <<<"$output" || die 'sing-box binary has an unexpected operating system or architecture'
    while IFS= read -r line; do
        if [[ $line == Tags:* ]]; then
            tags=${line#Tags:}
            tags=${tags//[[:space:]]/}
            break
        fi
    done <<<"$output"
    [[ -n $tags ]] || die 'sing-box binary did not report build tags'
    IFS=',' read -r -a required_tags <<<"$SING_BOX_BUILD_TAGS"
    for tag in "${required_tags[@]}"; do
        [[ ,$tags, == *,$tag,* ]] || die "sing-box binary is missing required build tag: ${tag}"
    done
    rate_probe=$(mktemp "${stage_dir}/sing-box-rate-probe.XXXXXX.json")
    cat >"$rate_probe" <<'RATE_PROBE_EOF'
{"log":{"level":"error"},"inbounds":[{"type":"mixed","tag":"probe-in","listen":"127.0.0.1","listen_port":65535}],"outbounds":[{"type":"direct","tag":"probe-out"}],"route":{"final":"probe-out"},"experimental":{"v3node":{"user_rates":{"probe-user":125000}}}}
RATE_PROBE_EOF
    "$binary" check -c "$rate_probe" >/dev/null 2>&1 || die 'sing-box binary is missing the v3node bounded rate-policy patch'
    rm -f -- "$rate_probe"
}

verify_xray_features() {
    local binary=$1 output
    output=$("$binary" version) || die 'verified Xray binary cannot run on this host'
    grep -Fq "Xray ${XRAY_VERSION} " <<<"$output" || die "Xray binary is not version ${XRAY_VERSION}"
    grep -Fq " ${XRAY_COMMIT} " <<<"$output" || die "Xray binary is not commit ${XRAY_COMMIT}"
    grep -Fq " linux/${arch})" <<<"$output" || die 'Xray binary has an unexpected operating system or architecture'
}

stage_inputs() {
    local bytes controller_version
    stage_dir=$(mktemp -d /tmp/v3node-install.XXXXXX)
    chmod 0700 "$stage_dir"

    if [[ -n ${config_source} ]]; then
        snapshot_regular_input "$config_source" "$stage_dir/config.json" '--config' 0600
        bytes=$(stat --format='%s' -- "$stage_dir/config.json")
        (( bytes <= 1048576 )) || die 'local configuration exceeds 1 MiB'
    fi

    if [[ -n ${api_key} ]]; then
        printf '%s' "$api_key" >"$stage_dir/panel.token"
        chmod 0600 "$stage_dir/panel.token"
        api_key=
        token_source=$stage_dir/panel.token
        bytes=$(stat --format='%s' -- "$stage_dir/panel.token")
        (( bytes > 0 && bytes <= 16384 )) || die '--api-key must contain between 1 byte and 16 KiB'
    elif [[ -n ${token_source} ]]; then
        snapshot_regular_input "$token_source" "$stage_dir/panel.token" '--token-file' 0600
        bytes=$(stat --format='%s' -- "$stage_dir/panel.token")
        (( bytes > 0 && bytes <= 16384 )) || die 'panel token file must contain between 1 byte and 16 KiB'
    fi

    if [[ -n ${local_v3node_file} ]]; then
        [[ -n ${local_v3node_sha256} ]] || die '--v3node-file requires --v3node-sha256'
        is_sha256 "$local_v3node_sha256" || die '--v3node-sha256 must be exactly 64 hexadecimal characters'
        snapshot_regular_input "$local_v3node_file" "$stage_dir/v3node" '--v3node-file' 0755
        verify_sha256 "$stage_dir/v3node" "$local_v3node_sha256"
    else
        [[ -z ${local_v3node_sha256} ]] || die '--v3node-sha256 is only valid with --v3node-file'
        is_sha256 "$v3node_sha256" || die 'this release is not published: embedded v3node SHA256 is still a placeholder'
        fetch "${V3NODE_RELEASE_BASE}/${v3node_asset}" "$stage_dir/v3node"
        verify_sha256 "$stage_dir/v3node" "$v3node_sha256"
        chmod 0755 "$stage_dir/v3node"
    fi
    controller_version=$("$stage_dir/v3node" version) || die 'verified v3node binary cannot run on this host'
    if [[ -z ${local_v3node_file} && $controller_version != "v3node ${V3NODE_VERSION} "* ]]; then
        die "controller binary does not report release version ${V3NODE_VERSION}"
    fi
    if [[ -n ${panel_url} ]]; then
        "$stage_dir/v3node" generate \
            --config "$stage_dir/config.json" \
            --panel-url "$panel_url" \
            --node-id "$panel_node_id" \
            --token-file "${CONFIG_DIR}/panel.token" \
            --skip-ownership \
            || die 'could not generate configuration from --panel-url and --node-id'
        chmod 0600 "$stage_dir/config.json"
        config_source=$stage_dir/config.json
    fi

    if [[ -n ${local_sing_box_file} ]]; then
        [[ -n ${local_sing_box_sha256} ]] || die '--sing-box-file requires --sing-box-sha256'
        is_sha256 "$local_sing_box_sha256" || die '--sing-box-sha256 must be exactly 64 hexadecimal characters'
        snapshot_regular_input "$local_sing_box_file" "$stage_dir/sing-box" '--sing-box-file' 0755
        verify_sha256 "$stage_dir/sing-box" "$local_sing_box_sha256"
    else
        [[ -z ${local_sing_box_sha256} ]] || die '--sing-box-sha256 is only valid with --sing-box-file'
        is_sha256 "$sing_box_sha256" || die 'this release is not published: embedded sing-box SHA256 is still a placeholder'
        log "downloading feature-verified sing-box ${SING_BOX_VERSION} for ${arch}"
        fetch "${SING_BOX_RELEASE_BASE}/${sing_box_asset}" "$stage_dir/sing-box"
        verify_sha256 "$stage_dir/sing-box" "$sing_box_sha256"
        chmod 0755 "$stage_dir/sing-box"
    fi
    verify_sing_box_features "$stage_dir/sing-box"

    if [[ -n ${local_xray_archive} ]]; then
        [[ -n ${local_xray_sha256} ]] || die '--xray-archive requires --xray-sha256'
        is_sha256 "$local_xray_sha256" || die '--xray-sha256 must be exactly 64 hexadecimal characters'
        snapshot_regular_input "$local_xray_archive" "$stage_dir/xray.zip" '--xray-archive' 0600
        verify_sha256 "$stage_dir/xray.zip" "$local_xray_sha256"
    else
        [[ -z ${local_xray_sha256} ]] || die '--xray-sha256 is only valid with --xray-archive'
        is_sha256 "$xray_sha256" || die 'embedded Xray SHA256 is invalid'
        log "downloading official Xray ${XRAY_VERSION} for ${arch}"
        fetch "${XRAY_RELEASE_BASE}/${xray_asset}" "$stage_dir/xray.zip"
        verify_sha256 "$stage_dir/xray.zip" "$xray_sha256"
    fi
    local member
    for member in xray geoip.dat geosite.dat LICENSE; do
        [[ $(unzip -Z1 "$stage_dir/xray.zip" | grep -Fxc "$member") -eq 1 ]] || die "Xray archive does not contain exactly one root ${member}"
        unzip -p "$stage_dir/xray.zip" "$member" >"$stage_dir/xray-${member}"
    done
    mv -- "$stage_dir/xray-xray" "$stage_dir/xray"
    chmod 0755 "$stage_dir/xray"
    verify_xray_features "$stage_dir/xray"
}

validate_managed_directory() {
    local path=$1
    [[ ! -L $path ]] || die "refusing symlinked managed directory: ${path}"
    [[ ! -e $path || -d $path ]] || die "managed directory path is not a directory: ${path}"
}

create_service_account() {
    local passwd_entry group_entry uid gid primary_gid home shell members member account_name account_gid group_ids
    local -a member_list account_gids
    validate_managed_directory "$META_DIR"
    install -d -m 0700 -o root -g root "$META_DIR"
    if ! getent group v3node >/dev/null; then
        groupadd --system v3node
        : >"$META_DIR/created-group"
        chmod 0600 "$META_DIR/created-group"
    fi
    group_entry=$(getent group v3node)
    IFS=: read -r _ _ gid members <<<"$group_entry"
    if [[ ! $gid =~ ^[0-9]+$ ]] || (( gid <= 0 || gid >= 1000 )); then
        die 'existing v3node group is not a system group'
    fi
    if [[ -n $members ]]; then
        IFS=',' read -r -a member_list <<<"$members"
        for member in "${member_list[@]}"; do
            [[ $member == v3node ]] || die 'existing v3node group has an unexpected member'
        done
    fi
    while IFS=: read -r account_name _ _ account_gid _ _ _; do
        if [[ $account_gid == "$gid" && $account_name != v3node ]]; then
            die 'existing v3node group is the primary group of another account'
        fi
    done < <(getent passwd)
    if getent passwd v3node >/dev/null; then
        passwd_entry=$(getent passwd v3node)
        IFS=: read -r _ _ uid primary_gid _ home shell <<<"$passwd_entry"
        if [[ ! $uid =~ ^[0-9]+$ ]] || (( uid <= 0 || uid >= 1000 )); then
            die 'existing v3node account is not a system account'
        fi
        [[ $primary_gid == "$gid" ]] || die 'existing v3node account does not use the v3node primary group'
        [[ $home == "$STATE_DIR" ]] || die 'existing v3node account has an unexpected home directory'
        [[ $shell == /usr/sbin/nologin || $shell == /sbin/nologin || $shell == /bin/false ]] || die 'existing v3node account has an interactive shell'
        group_ids=$(id -G v3node) || die 'could not inspect existing v3node account groups'
        IFS=' ' read -r -a account_gids <<<"$group_ids"
        for account_gid in "${account_gids[@]}"; do
            [[ $account_gid == "$gid" ]] || die 'existing v3node account belongs to an unexpected supplementary group'
        done
    else
        shell=/usr/sbin/nologin
        [[ -x $shell ]] || shell=/sbin/nologin
        useradd --system --gid v3node --home-dir "$STATE_DIR" --no-create-home --shell "$shell" v3node
        : >"$META_DIR/created-user"
        chmod 0600 "$META_DIR/created-user"
    fi
}

write_unit() {
    cat >"$stage_dir/v3node.service" <<'UNIT_EOF'
[Unit]
Description=v3node node controller
Documentation=https://github.com/Duyvj/v3node
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=v3node
Group=v3node
UMask=0027
WorkingDirectory=/var/lib/v3node
ExecStart=/usr/local/bin/v3node run --config /etc/v3node/config.json
Environment=XRAY_LOCATION_ASSET=/usr/local/lib/v3node
Restart=on-failure
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=30s
KillMode=mixed
KillSignal=SIGTERM

# Capacity accounting without a hard RAM cap. Input and retained-state bounds
# are enforced by v3node; the data plane is not throttled when traffic grows.
MemoryAccounting=true
CPUAccounting=true
TasksAccounting=true
TasksMax=16384
LimitNOFILE=1048576

# The controller and its engine need Internet access and may bind low ports,
# but they do not need root or network-administration capabilities.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Filesystem and kernel hardening. Persistent writes are limited to StateDirectory.
StateDirectory=v3node
StateDirectoryMode=0750
RuntimeDirectory=v3node
RuntimeDirectoryMode=0750
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
# The controller uses sysinfo(2) when this hides /proc/meminfo.
ProtectProc=invisible
ProcSubset=pid
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RemoveIPC=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

StandardOutput=journal
StandardError=journal
SyslogIdentifier=v3node

[Install]
WantedBy=multi-user.target
UNIT_EOF
}

write_example_config() {
    cat >"$stage_dir/config.example.json" <<'CONFIG_EOF'
{
  "panel": {
    "url": "https://panel.example.com",
    "node_id": 1,
    "token_file": "/etc/v3node/panel.token",
    "allow_insecure_http": false
  },
  "engine": {
    "backend": "auto",
    "sing_box_binary": "/usr/local/lib/v3node/edge-engine",
    "xray_binary": "/usr/local/lib/v3node/xray",
    "state_dir": "/var/lib/v3node",
    "stats_listen": "127.0.0.1:10085",
    "clash_listen": "127.0.0.1:10086",
    "check_timeout": "10s",
    "stop_timeout": "20s"
  },
  "runtime": {
    "log_level": "warn",
    "http_timeout": "15s",
    "stats_interval": "5s",
    "pull_interval_min": "15s",
    "pull_interval_max": "1h",
    "push_interval_min": "15s",
    "push_interval_max": "1h",
    "max_config_bytes": 2097152,
    "max_user_response_bytes": 33554432,
    "max_users": 100000,
    "max_online_ips": 200000,
    "max_ips_per_user": 1024,
    "online_ip_ttl": "3m",
    "max_panel_payload_bytes": 33554432,
    "max_stats_response_bytes": 67108864
  },
  "network": {
    "dns_servers": [],
    "address_strategy": "auto",
    "block_private": false
  }
}
CONFIG_EOF
}

write_engine_notice() {
    cat >"$stage_dir/NOTICE-edge-engine" <<EOF
v3node edge engine ${SING_BOX_VERSION}-p2

This separately executed data-plane binary is built from upstream source at:
https://github.com/SagerNet/sing-box/commit/${SING_BOX_COMMIT}

The exact Corresponding Source, project patch, vendored linked module source,
build instructions and license for this binary are published alongside it at:
${V3NODE_RELEASE_BASE}/v3node-edge-${SING_BOX_VERSION}-p2-source.tar.gz

The controller is not endorsed by or associated with the upstream project.
EOF
    cat >"$stage_dir/LICENSE-edge-engine" <<'EDGE_LICENSE_EOF'
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
EDGE_LICENSE_EOF
    cat >"$stage_dir/NOTICE-Xray" <<EOF
Xray ${XRAY_VERSION} is an unmodified, separately executed compatibility engine.
Source and upstream notices: https://github.com/XTLS/Xray-core/tree/v${XRAY_VERSION}
This controller is not endorsed by or associated with the upstream project.
EOF
}

write_tuning_helper() {
    cat >"$stage_dir/v3node-tune" <<'TUNE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/sbin:/usr/bin:/sbin:/bin

readonly SYSCTL_FILE=/etc/sysctl.d/90-v3node.conf
readonly META_DIR=/var/lib/v3node-install
readonly SNAPSHOT_FILE=${META_DIR}/tuning-before.txt
readonly MARKER='# Managed by v3node-tune; remove with: v3node-tune remove'

log() {
    printf 'v3node-tune: %s\n' "$*"
}

die() {
    log "ERROR: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: v3node-tune status|apply|remove

  status  Show relevant live kernel settings without changing them.
  apply   Opt in to the balanced v3node network profile.
  remove  Delete only the managed profile and reload underlying sysctl files.
EOF
}

require_root() {
    [[ ${EUID} -eq 0 ]] || die 'run as root'
}

proc_path() {
    local key=$1
    printf '/proc/sys/%s\n' "${key//./\/}"
}

is_supported() {
    [[ -e $(proc_path "$1") ]]
}

show_key() {
    local key=$1
    if is_supported "$key"; then
        printf '%-43s %s\n' "$key" "$(sysctl -n "$key" 2>/dev/null || printf unavailable)"
    fi
}

status() {
    local key
    for key in \
        net.core.default_qdisc \
        net.core.somaxconn \
        net.core.netdev_max_backlog \
        net.core.rmem_max \
        net.core.wmem_max \
        net.ipv4.tcp_available_congestion_control \
        net.ipv4.tcp_congestion_control \
        net.ipv4.tcp_fastopen \
        net.ipv4.tcp_mtu_probing \
        net.ipv4.tcp_max_syn_backlog \
        net.ipv4.tcp_rmem \
        net.ipv4.tcp_wmem; do
        show_key "$key"
    done
    if [[ -f ${SYSCTL_FILE} ]]; then
        if head -n 1 "$SYSCTL_FILE" | grep -Fqx "$MARKER"; then
            log "managed profile: ${SYSCTL_FILE}"
        else
            log "WARNING: ${SYSCTL_FILE} exists but is not managed by v3node-tune"
        fi
    else
        log 'managed profile: not installed'
    fi
}

append_if_supported() {
    local file=$1 key=$2 value=$3
    if is_supported "$key"; then
        printf '%s = %s\n' "$key" "$value" >>"$file"
    fi
}

enable_bbr_if_available() {
    local available
    is_supported net.ipv4.tcp_available_congestion_control || return 1
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    if ! grep -qw bbr <<<"$available" && command -v modprobe >/dev/null 2>&1; then
        modprobe tcp_bbr 2>/dev/null || true
        available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    fi
    grep -qw bbr <<<"$available"
}

apply_profile() {
    local tmp previous had_previous=false
    require_root
    command -v sysctl >/dev/null 2>&1 || die 'sysctl is required'
    [[ ! -L ${SYSCTL_FILE} ]] || die "refusing symlinked managed profile: ${SYSCTL_FILE}"

    if [[ -e ${SYSCTL_FILE} ]] && ! head -n 1 "$SYSCTL_FILE" | grep -Fqx "$MARKER"; then
        die "refusing to overwrite unmanaged ${SYSCTL_FILE}"
    fi

    [[ ! -L ${META_DIR} && ( ! -e ${META_DIR} || -d ${META_DIR} ) ]] || die "refusing unsafe metadata directory: ${META_DIR}"
    install -d -m 0700 -o root -g root "$META_DIR"
    if [[ ! -e ${SYSCTL_FILE} && ! -e ${SNAPSHOT_FILE} ]]; then
        status >"$SNAPSHOT_FILE"
        chmod 0600 "$SNAPSHOT_FILE"
    fi

    tmp=$(mktemp /etc/sysctl.d/.90-v3node.conf.XXXXXX)
    previous=$(mktemp /etc/sysctl.d/.90-v3node.previous.XXXXXX)
    trap 'rm -f -- "${tmp:-}" "${previous:-}"' EXIT
    if [[ -e ${SYSCTL_FILE} ]]; then
        cp -a -- "$SYSCTL_FILE" "$previous"
        had_previous=true
    fi
    printf '%s\n' "$MARKER" >"$tmp"
    printf '%s\n' '# Balanced queues and autotuning ceilings; no firewall, route, DNS, or swap changes.' >>"$tmp"

    append_if_supported "$tmp" net.core.somaxconn 4096
    append_if_supported "$tmp" net.core.netdev_max_backlog 8192
    append_if_supported "$tmp" net.core.rmem_max 8388608
    append_if_supported "$tmp" net.core.wmem_max 8388608
    append_if_supported "$tmp" net.ipv4.tcp_max_syn_backlog 8192
    append_if_supported "$tmp" net.ipv4.tcp_fastopen 3
    append_if_supported "$tmp" net.ipv4.tcp_mtu_probing 1
    append_if_supported "$tmp" net.ipv4.tcp_rmem '4096 131072 8388608'
    append_if_supported "$tmp" net.ipv4.tcp_wmem '4096 65536 8388608'

    if enable_bbr_if_available; then
        append_if_supported "$tmp" net.core.default_qdisc fq
        append_if_supported "$tmp" net.ipv4.tcp_congestion_control bbr
    else
        log 'BBR is unavailable on this kernel; congestion control is unchanged'
    fi

    chown root:root "$tmp"
    chmod 0644 "$tmp"
    mv -fT -- "$tmp" "$SYSCTL_FILE"
    if ! sysctl -p "$SYSCTL_FILE" >/dev/null; then
        if [[ ${had_previous} == true ]]; then
            mv -fT -- "$previous" "$SYSCTL_FILE"
            sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
        else
            rm -f -- "$SYSCTL_FILE"
            sysctl --system >/dev/null 2>&1 || true
        fi
        die 'one or more managed values failed; the previous sysctl profile was restored'
    fi
    rm -f -- "$previous"
    trap - EXIT
    log "applied ${SYSCTL_FILE}"
    status
}

remove_profile() {
    require_root
    command -v sysctl >/dev/null 2>&1 || die 'sysctl is required'
    [[ ! -L ${SYSCTL_FILE} ]] || die "refusing symlinked managed profile: ${SYSCTL_FILE}"
    if [[ ! -e ${SYSCTL_FILE} ]]; then
        log 'managed profile is already absent'
        return
    fi
    head -n 1 "$SYSCTL_FILE" | grep -Fqx "$MARKER" || die "refusing to remove unmanaged ${SYSCTL_FILE}"
    rm -f -- "$SYSCTL_FILE"
    if ! sysctl --system >/dev/null; then
        die 'profile was removed, but the host reported an error while reloading sysctl files'
    fi
    log 'removed managed profile and reloaded underlying host settings'
}

case ${1:-} in
    status|--status)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        status
        ;;
    apply|--apply)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        apply_profile
        ;;
    remove|--remove)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        remove_profile
        ;;
    -h|--help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
TUNE_EOF
}

write_uninstaller() {
    cat >"$stage_dir/v3node-uninstall" <<'UNINSTALL_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 027

readonly SERVICE=v3node.service
readonly UNIT_FILE=/etc/systemd/system/v3node.service
readonly ENABLE_LINK=/etc/systemd/system/multi-user.target.wants/v3node.service
readonly CONFIG_DIR=/etc/v3node
readonly STATE_DIR=/var/lib/v3node
readonly RUN_DIR=/run/v3node
readonly LIB_DIR=/usr/local/lib/v3node
readonly META_DIR=/var/lib/v3node-install
readonly BACKUP_DIR=/var/backups/v3node
readonly DOC_DIR=/usr/share/doc/v3node
readonly USER_MARKER=${META_DIR}/created-user
readonly GROUP_MARKER=${META_DIR}/created-group
readonly TUNING_FILE=/etc/sysctl.d/90-v3node.conf
readonly TUNING_MARKER='# Managed by v3node-tune; remove with: v3node-tune remove'

purge=false
remove_tuning=false
preserve_tuning_helper=false

log() {
    printf 'v3node-uninstall: %s\n' "$*"
}

die() {
    log "ERROR: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: v3node-uninstall [--purge] [--remove-tuning]

By default, configuration, credentials, state, backups, the service account,
and opt-in host tuning are preserved.

  --purge          Also remove /etc/v3node, /var/lib/v3node, /run/v3node,
                   /var/backups/v3node, and an installer-created account.
  --remove-tuning  Remove only the v3node-managed sysctl profile and reload
                   the host's remaining sysctl files.
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --purge) purge=true ;;
        --remove-tuning) remove_tuning=true ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
done

[[ ${EUID} -eq 0 ]] || die 'run as root'

if [[ ${remove_tuning} == true && -L ${TUNING_FILE} ]]; then
    die "refusing to remove symlinked tuning profile: ${TUNING_FILE}"
fi
if [[ ${remove_tuning} == true && -e ${TUNING_FILE} ]]; then
    head -n 1 "$TUNING_FILE" | grep -Fqx "$TUNING_MARKER" || die "refusing to remove unmanaged ${TUNING_FILE}"
fi
[[ ! -L ${DOC_DIR} && ( ! -e ${DOC_DIR} || -d ${DOC_DIR} ) ]] || die "refusing unsafe documentation directory: ${DOC_DIR}"
[[ ! -L ${LIB_DIR} && ( ! -e ${LIB_DIR} || -d ${LIB_DIR} ) ]] || die "refusing unsafe library directory: ${LIB_DIR}"
for managed_file in \
    "$UNIT_FILE" \
    "$ENABLE_LINK" \
    /usr/local/bin/v3node \
    /usr/local/sbin/v3node-uninstall \
    /usr/local/sbin/v3node-tune \
    "${DOC_DIR}/config.example.json" \
    "${DOC_DIR}/LICENSE-Xray" \
    "${DOC_DIR}/NOTICE-Xray" \
    "${DOC_DIR}/LICENSE-edge-engine" \
    "${DOC_DIR}/NOTICE-edge-engine" \
    "${LIB_DIR}/edge-engine" \
    "${LIB_DIR}/xray" \
    "${LIB_DIR}/geoip.dat" \
    "${LIB_DIR}/geosite.dat" \
    "${LIB_DIR}/v3node-tune"; do
    if [[ -e $managed_file || -L $managed_file ]] && [[ ! -f $managed_file && ! -L $managed_file ]]; then
        die "refusing non-file managed path: ${managed_file}"
    fi
done

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    if systemctl is-active --quiet "$SERVICE"; then
        die "could not stop ${SERVICE}"
    fi
    systemctl disable "$SERVICE" >/dev/null 2>&1 || true
fi

if [[ ${remove_tuning} == true && -e ${TUNING_FILE} ]]; then
    rm -f -- "$TUNING_FILE"
    if command -v sysctl >/dev/null 2>&1; then
        sysctl --system >/dev/null || log 'WARNING: host reported an error while reloading remaining sysctl files'
    fi
fi
if [[ ${remove_tuning} == false && -e ${TUNING_FILE} ]] && head -n 1 "$TUNING_FILE" | grep -Fqx "$TUNING_MARKER"; then
    preserve_tuning_helper=true
fi

rm -f -- "$UNIT_FILE" "$ENABLE_LINK"
rm -f -- /usr/local/bin/v3node
rm -f -- /usr/local/sbin/v3node-uninstall
if [[ ${preserve_tuning_helper} == false ]]; then
    rm -f -- /usr/local/sbin/v3node-tune
fi
rm -f -- "${DOC_DIR}/config.example.json" "${DOC_DIR}/LICENSE-Xray" "${DOC_DIR}/NOTICE-Xray" "${DOC_DIR}/LICENSE-edge-engine" "${DOC_DIR}/NOTICE-edge-engine"
rmdir --ignore-fail-on-non-empty "$DOC_DIR" 2>/dev/null || true

if [[ -d ${LIB_DIR} && ! -L ${LIB_DIR} ]]; then
    rm -f -- "${LIB_DIR}/edge-engine" "${LIB_DIR}/xray" "${LIB_DIR}/geoip.dat" "${LIB_DIR}/geosite.dat" "${LIB_DIR}/v3node-tune"
    rmdir --ignore-fail-on-non-empty "$LIB_DIR" 2>/dev/null || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
fi

if [[ ${purge} == true ]]; then
    remove_account=false
    remove_group=false
    account_entry=
    account_uid=
    account_home=
    account_shell=
    group_entry=
    group_gid=
    group_members=
    [[ -f ${USER_MARKER} ]] && remove_account=true
    [[ -f ${GROUP_MARKER} ]] && remove_group=true

    for path in "$CONFIG_DIR" "$STATE_DIR" "$RUN_DIR" "$BACKUP_DIR"; do
        case $path in
            /etc/v3node|/var/lib/v3node|/run/v3node|/var/backups/v3node) ;;
            *) die "internal path safety check failed: ${path}" ;;
        esac
        rm -rf --one-file-system -- "$path"
    done

    if [[ ${remove_account} == true ]] && account_entry=$(getent passwd v3node); then
        IFS=: read -r _ _ account_uid _ _ account_home account_shell <<<"$account_entry"
        if [[ $account_uid =~ ^[0-9]+$ ]] && (( account_uid > 0 && account_uid < 1000 )) && [[ $account_home == "$STATE_DIR" && ( $account_shell == /usr/sbin/nologin || $account_shell == /sbin/nologin || $account_shell == /bin/false ) ]]; then
            userdel v3node || log 'WARNING: could not remove the v3node account'
        else
            log 'WARNING: preserved modified v3node account (unexpected home or shell)'
        fi
    fi
    if [[ ${remove_group} == true ]] && group_entry=$(getent group v3node); then
        IFS=: read -r _ _ group_gid group_members <<<"$group_entry"
        if [[ $group_gid =~ ^[0-9]+$ ]] && (( group_gid > 0 && group_gid < 1000 )) && [[ -z $group_members ]]; then
            groupdel v3node 2>/dev/null || log 'WARNING: preserved v3node group because it is still in use'
        else
            log 'WARNING: preserved v3node group because it has additional members'
        fi
    fi
    rm -rf --one-file-system -- "$META_DIR"
else
    log 'preserved configuration, state, backups, and the service account'
fi

if [[ ${remove_tuning} == false && -e ${TUNING_FILE} ]]; then
    log "preserved opt-in tuning at ${TUNING_FILE}"
    [[ ${preserve_tuning_helper} == true ]] && log 'preserved /usr/local/sbin/v3node-tune so the profile can be removed later'
fi

log 'uninstall complete'
UNINSTALL_EOF
}

prepare_managed_directory() {
    local path=$1 mode=$2 owner=$3 group=$4
    validate_managed_directory "$path"
    install -d -m "$mode" -o "$owner" -g "$group" "$path"
}

backup_managed_file() {
    local target=$1 name=$2
    if [[ -e $target || -L $target ]]; then
        [[ -f $target || -L $target ]] || die "managed file path is not a regular file or symlink: ${target}"
        cp --archive --no-dereference -- "$target" "$install_backup/$name"
    fi
}

restore_managed_file() {
    local target=$1 name=$2 directory base temporary
    directory=${target%/*}
    base=${target##*/}
    temporary=${directory}/.${base}.rollback.$$
    if [[ -e $install_backup/$name || -L $install_backup/$name ]]; then
        [[ ! -e $temporary && ! -L $temporary ]] || return 1
        cp --archive --no-dereference -- "$install_backup/$name" "$temporary" || return 1
        if ! mv -fT -- "$temporary" "$target"; then
            rm -f -- "$temporary"
            return 1
        fi
    else
        rm -f -- "$target" || return 1
    fi
}

install_file_atomic() {
    local source=$1 target=$2 mode=$3 owner=$4 group=$5 directory base temporary
    directory=${target%/*}
    base=${target##*/}
    temporary=${directory}/.${base}.new.$$
    [[ ! -e $temporary && ! -L $temporary ]] || die "temporary install path already exists: ${temporary}"
    if ! install -m "$mode" -o "$owner" -g "$group" "$source" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if ! mv -fT -- "$temporary" "$target"; then
        rm -f -- "$temporary"
        return 1
    fi
}

backup_existing_installation() {
    local timestamp
    prepare_managed_directory "$BACKUP_ROOT" 0700 root root
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    install_backup=$(mktemp -d "${BACKUP_ROOT}/${timestamp}-XXXXXX")
    chown root:root "$install_backup"
    chmod 0700 "$install_backup"

    backup_managed_file /usr/local/bin/v3node v3node
    backup_managed_file "$LIB_DIR/edge-engine" edge-engine
    backup_managed_file "$LIB_DIR/xray" xray
    backup_managed_file "$LIB_DIR/geoip.dat" geoip.dat
    backup_managed_file "$LIB_DIR/geosite.dat" geosite.dat
    backup_managed_file "$LIB_DIR/v3node-tune" lib-v3node-tune
    backup_managed_file "$UNIT_FILE" v3node.service
    backup_managed_file "$ENABLE_LINK" v3node.enable-link
    backup_managed_file /usr/local/sbin/v3node-tune sbin-v3node-tune
    backup_managed_file /usr/local/sbin/v3node-uninstall v3node-uninstall
    backup_managed_file "$DOC_DIR/config.example.json" config.example.json
    backup_managed_file "$DOC_DIR/LICENSE-Xray" LICENSE-Xray
    backup_managed_file "$DOC_DIR/NOTICE-Xray" NOTICE-Xray
    backup_managed_file "$DOC_DIR/LICENSE-edge-engine" LICENSE-edge-engine
    backup_managed_file "$DOC_DIR/NOTICE-edge-engine" NOTICE-edge-engine
    if [[ -n ${config_source} ]]; then
        backup_managed_file "$CONFIG_FILE" config.json
    fi
    if [[ -n ${token_source} ]]; then
        backup_managed_file "${CONFIG_DIR}/panel.token" panel.token
    fi
    log "created recovery checkpoint at ${install_backup}"
}

restore_previous_installation() {
    local failed=false
    [[ -n ${install_backup} && -d ${install_backup} && ! -L ${install_backup} ]] || return 1
    log "restoring previous installation from ${install_backup}"

    restore_managed_file /usr/local/bin/v3node v3node || failed=true
    restore_managed_file "$LIB_DIR/edge-engine" edge-engine || failed=true
    restore_managed_file "$LIB_DIR/xray" xray || failed=true
    restore_managed_file "$LIB_DIR/geoip.dat" geoip.dat || failed=true
    restore_managed_file "$LIB_DIR/geosite.dat" geosite.dat || failed=true
    restore_managed_file "$LIB_DIR/v3node-tune" lib-v3node-tune || failed=true
    restore_managed_file "$UNIT_FILE" v3node.service || failed=true
    restore_managed_file "$ENABLE_LINK" v3node.enable-link || failed=true
    restore_managed_file /usr/local/sbin/v3node-tune sbin-v3node-tune || failed=true
    restore_managed_file /usr/local/sbin/v3node-uninstall v3node-uninstall || failed=true
    restore_managed_file "$DOC_DIR/config.example.json" config.example.json || failed=true
    restore_managed_file "$DOC_DIR/LICENSE-Xray" LICENSE-Xray || failed=true
    restore_managed_file "$DOC_DIR/NOTICE-Xray" NOTICE-Xray || failed=true
    restore_managed_file "$DOC_DIR/LICENSE-edge-engine" LICENSE-edge-engine || failed=true
    restore_managed_file "$DOC_DIR/NOTICE-edge-engine" NOTICE-edge-engine || failed=true
    if [[ -n ${config_source} ]]; then
        restore_managed_file "$CONFIG_FILE" config.json || failed=true
    fi
    if [[ -n ${token_source} ]]; then
        restore_managed_file "${CONFIG_DIR}/panel.token" panel.token || failed=true
    fi
    systemctl daemon-reload || failed=true
    [[ $failed == false ]]
}

rollback_failed_installation() {
    rollback_attempted=true
    transaction_active=false
    log 'installation failed; attempting automatic rollback' >&2
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    if restore_previous_installation; then
        if [[ ${was_active} == true ]]; then
            if systemctl start "$SERVICE"; then
                log 'previous active installation was restored and restarted' >&2
            else
                log 'ERROR: previous files were restored, but the service could not be restarted' >&2
            fi
        else
            systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
            log 'previous stopped state and managed files were restored' >&2
        fi
    else
        log "ERROR: automatic rollback was incomplete; recovery files remain at ${install_backup}" >&2
    fi
}

install_staged_files() {
    write_unit
    write_example_config
    write_engine_notice
    write_tuning_helper
    write_uninstaller

    prepare_managed_directory "$CONFIG_DIR" 0750 root v3node
    prepare_managed_directory "$STATE_DIR" 0750 v3node v3node
    prepare_managed_directory "$RUN_DIR" 0750 v3node v3node
    prepare_managed_directory "$LIB_DIR" 0755 root root
    prepare_managed_directory "$DOC_DIR" 0755 root root

    install_file_atomic "$stage_dir/v3node" /usr/local/bin/v3node 0755 root root
    install_file_atomic "$stage_dir/sing-box" "$LIB_DIR/edge-engine" 0755 root root
    install_file_atomic "$stage_dir/xray" "$LIB_DIR/xray" 0755 root root
    install_file_atomic "$stage_dir/xray-geoip.dat" "$LIB_DIR/geoip.dat" 0644 root root
    install_file_atomic "$stage_dir/xray-geosite.dat" "$LIB_DIR/geosite.dat" 0644 root root
    install_file_atomic "$stage_dir/v3node-tune" "$LIB_DIR/v3node-tune" 0755 root root
    install_file_atomic "$stage_dir/v3node.service" "$UNIT_FILE" 0644 root root
    install_file_atomic "$stage_dir/v3node-tune" /usr/local/sbin/v3node-tune 0755 root root
    install_file_atomic "$stage_dir/v3node-uninstall" /usr/local/sbin/v3node-uninstall 0755 root root
    install_file_atomic "$stage_dir/config.example.json" "$DOC_DIR/config.example.json" 0644 root root
    install_file_atomic "$stage_dir/xray-LICENSE" "$DOC_DIR/LICENSE-Xray" 0644 root root
    install_file_atomic "$stage_dir/NOTICE-Xray" "$DOC_DIR/NOTICE-Xray" 0644 root root
    install_file_atomic "$stage_dir/LICENSE-edge-engine" "$DOC_DIR/LICENSE-edge-engine" 0644 root root
    install_file_atomic "$stage_dir/NOTICE-edge-engine" "$DOC_DIR/NOTICE-edge-engine" 0644 root root

    if [[ -n ${config_source} ]]; then
        install_file_atomic "$stage_dir/config.json" "$CONFIG_FILE" 0640 root v3node
    fi
    if [[ -n ${token_source} ]]; then
        install_file_atomic "$stage_dir/panel.token" "${CONFIG_DIR}/panel.token" 0640 root v3node
    fi
}

main() {
    local managed_directory
    require_supported_host
    select_architecture

    if [[ -z ${local_v3node_file} ]]; then
        is_sha256 "$v3node_sha256" || die 'this source tree has no published controller checksums; build a release or use --v3node-file with --v3node-sha256'
    fi
    if [[ -n ${local_v3node_file} && -z ${local_v3node_sha256} ]]; then
        die '--v3node-file requires --v3node-sha256'
    fi
    if [[ -z ${local_v3node_file} && -n ${local_v3node_sha256} ]]; then
        die '--v3node-sha256 is only valid with --v3node-file'
    fi
    if [[ -n ${local_v3node_file} ]]; then
        is_sha256 "$local_v3node_sha256" || die '--v3node-sha256 must be exactly 64 hexadecimal characters'
        [[ -f ${local_v3node_file} && ! -L ${local_v3node_file} ]] || die '--v3node-file must reference a regular file'
    fi
    if [[ -z ${local_sing_box_file} ]]; then
        is_sha256 "$sing_box_sha256" || die 'this source tree has no published sing-box checksums; build the pinned engine or use --sing-box-file with --sing-box-sha256'
    elif [[ -z ${local_sing_box_sha256} ]]; then
        die '--sing-box-file requires --sing-box-sha256'
    else
        is_sha256 "$local_sing_box_sha256" || die '--sing-box-sha256 must be exactly 64 hexadecimal characters'
        [[ -f ${local_sing_box_file} && ! -L ${local_sing_box_file} ]] || die '--sing-box-file must reference a regular file'
    fi
    if [[ -z ${local_sing_box_file} && -n ${local_sing_box_sha256} ]]; then
        die '--sing-box-sha256 is only valid with --sing-box-file'
    fi
    if [[ -n ${local_xray_archive} && -z ${local_xray_sha256} ]]; then
        die '--xray-archive requires --xray-sha256'
    fi
    if [[ -z ${local_xray_archive} && -n ${local_xray_sha256} ]]; then
        die '--xray-sha256 is only valid with --xray-archive'
    fi
    if [[ -n ${local_xray_archive} ]]; then
        is_sha256 "$local_xray_sha256" || die '--xray-sha256 must be exactly 64 hexadecimal characters'
        [[ -f ${local_xray_archive} && ! -L ${local_xray_archive} ]] || die '--xray-archive must reference a regular file'
    fi
    if [[ -n ${config_source} ]]; then
        [[ -f ${config_source} && ! -L ${config_source} ]] || die '--config must reference a regular file'
    fi
    if [[ -n ${token_source} ]]; then
        [[ -f ${token_source} && ! -L ${token_source} ]] || die '--token-file must reference a regular file'
    fi
    [[ -z ${api_key} || -z ${token_source} ]] || die '--api-key conflicts with --token-file'
    if [[ -n ${panel_url} || -n ${panel_node_id} || -n ${api_key} ]]; then
        [[ -n ${panel_url} && -n ${panel_node_id} ]] || die '--api-host/--panel-url and --node-id must be used together'
        [[ ${panel_node_id} =~ ^[1-9][0-9]*$ ]] || die '--node-id must be a positive integer'
        [[ -z ${config_source} ]] || die '--api-host/--panel-url conflicts with --config'
        [[ -n ${token_source} || -n ${api_key} ]] || die '--api-host/--panel-url requires --api-key or --token-file'
    fi
    for managed_directory in "$CONFIG_DIR" "$STATE_DIR" "$RUN_DIR" "$META_DIR" "$LIB_DIR" "$DOC_DIR" "$BACKUP_ROOT"; do
        validate_managed_directory "$managed_directory"
    done

    ensure_dependencies
    exec 9>/run/lock/v3node-install.lock
    flock -n 9 || die 'another v3node installation is running'
    stage_inputs
    create_service_account

    if systemctl is-active --quiet "$SERVICE"; then
        was_active=true
    fi
    backup_existing_installation
    transaction_active=true
    if [[ ${was_active} == true ]]; then
        systemctl stop "$SERVICE"
    fi

    install_staged_files
    systemctl daemon-reload

    if [[ ${no_start} == true ]]; then
        log 'files installed; service was not started because --no-start was supplied'
    elif [[ -f ${CONFIG_FILE} ]]; then
        if ! runuser -u v3node -- /usr/local/bin/v3node check --config "$CONFIG_FILE" --timeout 30s; then
            die 'node validation failed; automatic rollback will restore the previous state'
        fi
        systemctl enable "$SERVICE" >/dev/null
        if ! systemctl restart "$SERVICE"; then
            journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
            die 'service failed to start; automatic rollback will restore the previous state'
        fi
        log 'service enabled and started'
    else
        log "files installed; create ${CONFIG_FILE}, then run: systemctl enable --now ${SERVICE}"
    fi
    transaction_active=false

    log "installed v3node ${V3NODE_VERSION} with sing-box ${SING_BOX_VERSION} and Xray ${XRAY_VERSION}"
    log "expected sing-box source commit: ${SING_BOX_COMMIT}"
    log 'host tuning was not changed; inspect it with: v3node-tune status'
}

main
