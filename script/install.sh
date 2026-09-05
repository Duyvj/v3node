#!/bin/bash

set -o pipefail
umask 077

# This installer runs as root. Resolve every helper from operating-system
# directories only and prevent child Bash/dynamic-loader processes from
# inheriting attacker-selected startup code from the invoking shell.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH OPENSSL_CONF

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Lỗi:${plain} Phải chạy script này bằng tài khoản root!\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "alpine"; then
    release="alpine"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux"; then
    release="centos"
elif cat /proc/version | grep -Eqi "arch"; then
    release="arch"
else
    echo -e "${red}Không xác định được phiên bản hệ điều hành, vui lòng liên hệ tác giả script!${plain}\n" && exit 1
fi

########################
# Phân tích tham số
########################
VERSION_ARG=""
API_HOST_ARG=""
NODE_ID_ARG=""
API_KEY_ARG=""
AGENT_ID_ARG=""
AGENT_TOKEN_ARG=""
AGENT_TOKEN_STDIN=false
POLL_INTERVAL_ARG="15"
DISABLE_EXECUTE_WAS_SET=false
if [[ -n "${DISABLE_EXECUTE+x}" ]]; then
    DISABLE_EXECUTE_WAS_SET=true
fi
DISABLE_EXECUTE="${DISABLE_EXECUTE:-}"
RELEASE_REPO_ARG="${V3NODE_RELEASE_REPO:-${ZNODE_RELEASE_REPO:-Duyvj/v3node}}"
RELEASE_BRANCH_ARG="${V3NODE_RELEASE_BRANCH:-${ZNODE_RELEASE_BRANCH:-main}}"
ZNODE_OPERATION_LOCK_FILE="/run/znode-operation.lock"
ZNODE_OPERATION_LOCK_DIRECTORY="${ZNODE_OPERATION_LOCK_FILE}.d"
ZNODE_OPERATION_LOCK_BACKEND=""

acquire_znode_operation_lock() {
    local owner="" stale_directory lock_parent
    if [[ -n "$ZNODE_OPERATION_LOCK_BACKEND" ]]; then
        return 0
    fi

    lock_parent="${ZNODE_OPERATION_LOCK_DIRECTORY%/*}"
    mkdir -p "$lock_parent" || return 1
    if ! mkdir "$ZNODE_OPERATION_LOCK_DIRECTORY" 2>/dev/null; then
        if [[ -r "$ZNODE_OPERATION_LOCK_DIRECTORY/pid" ]]; then
            owner=$(sed -n '1p' "$ZNODE_OPERATION_LOCK_DIRECTORY/pid")
        fi
        if [[ "$owner" =~ ^[0-9]+$ ]] && kill -0 "$owner" 2>/dev/null; then
            echo -e "${red}Một thao tác cài đặt/rollback ZNode khác đang chạy; hãy thử lại sau.${plain}"
            return 1
        fi
        if [[ ! "$owner" =~ ^[0-9]+$ ]]; then
            echo -e "${red}Khóa thao tác ZNode không có chủ sở hữu hợp lệ; hãy kiểm tra $ZNODE_OPERATION_LOCK_DIRECTORY thủ công.${plain}"
            return 1
        fi
        stale_directory="${ZNODE_OPERATION_LOCK_DIRECTORY}.stale.$$"
        mv "$ZNODE_OPERATION_LOCK_DIRECTORY" "$stale_directory" 2>/dev/null || return 1
        if ! mkdir "$ZNODE_OPERATION_LOCK_DIRECTORY" 2>/dev/null; then
            rm -rf "$stale_directory"
            return 1
        fi
        rm -rf "$stale_directory"
    fi
    printf '%s\n' "$$" > "$ZNODE_OPERATION_LOCK_DIRECTORY/pid" || {
        rm -rf "$ZNODE_OPERATION_LOCK_DIRECTORY"
        return 1
    }
    ZNODE_OPERATION_LOCK_BACKEND="mkdir"
}

release_znode_operation_lock() {
    local owner=""
    if [[ "$ZNODE_OPERATION_LOCK_BACKEND" == "mkdir" ]]; then
        [[ -r "$ZNODE_OPERATION_LOCK_DIRECTORY/pid" ]] \
            && owner=$(sed -n '1p' "$ZNODE_OPERATION_LOCK_DIRECTORY/pid")
        if [[ "$owner" == "$$" ]]; then
            rm -rf "$ZNODE_OPERATION_LOCK_DIRECTORY"
        fi
    fi
    ZNODE_OPERATION_LOCK_BACKEND=""
}

validate_geodata() {
    local release_directory="${1:-/usr/local/znode}"
    local file

    for file in geoip.dat geosite.dat; do
        if [[ ! -s "$release_directory/$file" ]] || [[ $(wc -c < "$release_directory/$file") -lt 1024 ]]; then
            echo -e "${red}Gói phát hành đã xác minh không chứa $file hợp lệ; từ chối trộn dữ liệu ngoài release.${plain}"
            return 1
        fi
    done
}

install_geodata() (
    local release_directory="${1:-/usr/local/znode}"
    local destination="/etc/znode"
    local transaction_directory file restore_file

    validate_geodata "$release_directory" || return 1
    mkdir -p "$destination"
    transaction_directory=$(mktemp -d "$destination/.geodata.XXXXXX") || return 1
    trap 'rm -rf "$transaction_directory"' EXIT

    # Stage both new files and backups on the destination filesystem. Each
    # rename is atomic; if either commit fails, restore the complete old pair.
    for file in geoip.dat geosite.dat; do
        install -m 0644 "$release_directory/$file" "$transaction_directory/new-$file" || return 1
        if [[ -e "$destination/$file" ]]; then
            cp -p "$destination/$file" "$transaction_directory/old-$file" || return 1
        else
            : > "$transaction_directory/no-old-$file"
        fi
    done
    for file in geoip.dat geosite.dat; do
        if ! mv -f "$transaction_directory/new-$file" "$destination/$file"; then
            for restore_file in geoip.dat geosite.dat; do
                if [[ -e "$transaction_directory/old-$restore_file" ]]; then
                    mv -f "$transaction_directory/old-$restore_file" "$destination/$restore_file" || true
                elif [[ -e "$transaction_directory/no-old-$restore_file" ]]; then
                    rm -f "$destination/$restore_file"
                fi
            done
            return 1
        fi
    done
    echo -e "${green}Đã cài geoip.dat và geosite.dat vào $destination.${plain}"
)

install_log_cleanup() {
    local cleanup_script="/usr/local/znode/cleanup-logs.sh"
    local schedule_dir="/etc/cron.daily"
    [[ x"${release}" == x"alpine" ]] && schedule_dir="/etc/periodic/daily"
    mkdir -p /usr/local/znode "$schedule_dir" /var/log/znode
    cat > "$cleanup_script" <<'EOF'
#!/bin/sh
# Keep ZNode file logs from growing without touching other services.
set -u

truncate_log() {
    case "$1" in
        /var/log/*|/usr/local/znode/*)
            [ -f "$1" ] && : > "$1" 2>/dev/null || true
            ;;
    esac
}

for log_file in /var/log/znode.log /var/log/znode-maintenance.log /var/log/znode/*.log; do
    [ -e "$log_file" ] && truncate_log "$log_file"
done

if [ -r /etc/znode/config.json ]; then
    output=$(sed -n 's/.*"Output"[[:space:]]*:[[:space:]]*"\([^"\\]*\)".*/\1/p' /etc/znode/config.json | sed -n '1p')
    [ -n "$output" ] && truncate_log "$output"
fi

find /var/log/znode -type f -name '*.log' -mtime +1 -delete 2>/dev/null || true
EOF
    chmod 700 "$cleanup_script"
    cat > "$schedule_dir/znode-log-cleanup" <<EOF
#!/bin/sh
exec "$cleanup_script"
EOF
    chmod 755 "$schedule_dir/znode-log-cleanup"
}

# Upgrade legacy defaults that either starved video buffers or held the first
# UDP/QUIC packets for content sniffing. TCP/TLS domain routing remains active.
migrate_tiktok_compat_profile() {
    local config_file="/etc/znode/config.json"
    local temporary
    [[ -f "$config_file" ]] || return 0
    if ! grep -Eq '"Handshake"[[:space:]]*:[[:space:]]*4([[:space:]]*,)|"ConnIdle"[[:space:]]*:[[:space:]]*30([[:space:]]*,)|"BufferSize"[[:space:]]*:[[:space:]]*16([[:space:]]*,)|"DisableUDPContentSniffing"[[:space:]]*:[[:space:]]*false' "$config_file"; then
        return 0
    fi
    temporary=$(mktemp "${config_file}.XXXXXX") || return 1

    sed -E \
        -e 's/"Handshake"[[:space:]]*:[[:space:]]*4[[:space:]]*,/"Handshake": 15,/' \
        -e 's/"ConnIdle"[[:space:]]*:[[:space:]]*30[[:space:]]*,/"ConnIdle": 120,/' \
        -e 's/"BufferSize"[[:space:]]*:[[:space:]]*16[[:space:]]*,/"BufferSize": 128,/' \
        -e 's/"DisableUDPContentSniffing"[[:space:]]*:[[:space:]]*false/"DisableUDPContentSniffing": true/' \
        "$config_file" > "$temporary"

    chmod 600 "$temporary"
    mv -f "$temporary" "$config_file"
    echo -e "${green}Đã nâng cấu hình UDP/QUIC để ổn định TikTok và video.${plain}"
}

secure_znode_config_permissions() {
    local config_file="/etc/znode/config.json"
    [[ -e "$config_file" ]] || return 0
    if [[ -L "$config_file" ]] || [[ ! -f "$config_file" ]]; then
        echo -e "${red}Từ chối cấu hình ZNode không phải regular file.${plain}"
        return 1
    fi
    chown root:root "$config_file" && chmod 600 "$config_file"
}

ensure_instance_secret() {
    local secret_file="/etc/znode/instance-secret"
    local temporary secret
    mkdir -p /etc/znode || return 1
    if [[ -e "$secret_file" ]]; then
        if [[ -L "$secret_file" || ! -f "$secret_file" ]]; then
            echo -e "${red}Từ chối instance secret không phải regular file.${plain}"
            return 1
        fi
        secret=$(tr -d '\r\n' < "$secret_file")
        if [[ ! "$secret" =~ ^[a-f0-9]{64}$ ]]; then
            echo -e "${red}Instance secret hiện tại không hợp lệ; không tự ghi đè khóa định danh VPS.${plain}"
            return 1
        fi
        chown root:root "$secret_file" && chmod 600 "$secret_file"
        return $?
    fi
    temporary=$(mktemp /etc/znode/.instance-secret.XXXXXX) || return 1
    secret=$(openssl rand -hex 32 2>/dev/null) || {
        rm -f "$temporary"
        return 1
    }
    if [[ ! "$secret" =~ ^[a-f0-9]{64}$ ]] \
        || ! printf '%s\n' "$secret" > "$temporary" \
        || ! chown root:root "$temporary" \
        || ! chmod 600 "$temporary" \
        || ! mv -f "$temporary" "$secret_file"; then
        rm -f "$temporary"
        return 1
    fi
}

# Bind every installed runtime to ZBoard. Existing ZNode configs are upgraded
# in place, while an explicit incompatible type is never overwritten.
ensure_zboard_config_type() {
    local config_file="/etc/znode/config.json"
    local temporary
    [[ -f "$config_file" ]] || return 0

    if grep -Eqi '"type"[[:space:]]*:' "$config_file"; then
        if grep -Eqi '"type"[[:space:]]*:[[:space:]]*"(v2node|zboard|v2board)"' "$config_file"; then
            secure_znode_config_permissions
            return $?
        fi
        echo -e "${red}Cấu hình có type không tương thích; yêu cầu type=v2node hoặc zboard.${plain}"
        return 1
    fi

    temporary=$(mktemp "${config_file}.XXXXXX") || return 1
    if ! awk '
        BEGIN { inserted = 0 }
        !inserted {
            position = index($0, "{")
            if (position > 0) {
                print substr($0, 1, position)
                print "    \"type\": \"v2node\","
                remainder = substr($0, position + 1)
                if (length(remainder) > 0) print remainder
                inserted = 1
                next
            }
        }
        { print }
        END { if (!inserted) exit 2 }
    ' "$config_file" > "$temporary"; then
        rm -f "$temporary"
        echo -e "${red}Không thể thêm type=v2node vào cấu hình hiện tại.${plain}"
        return 1
    fi
    if ! grep -Eqi '"type"[[:space:]]*:[[:space:]]*"(v2node|zboard|v2board)"' "$temporary"; then
        rm -f "$temporary"
        echo -e "${red}Không thể xác nhận type=v2node trong cấu hình mới.${plain}"
        return 1
    fi
    chmod 600 "$temporary"
    mv -f "$temporary" "$config_file"
    secure_znode_config_permissions || return 1
    echo -e "${green}Đã khóa cấu hình với type=v2node.${plain}"
}

reject_legacy_v2node_config() {
    return 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --api-host)
                API_HOST_ARG="$2"; shift 2 ;;
            --node-id)
                NODE_ID_ARG="$2"; shift 2 ;;
            --api-key)
                API_KEY_ARG="$2"; shift 2 ;;
            --agent-id)
                AGENT_ID_ARG="$2"; shift 2 ;;
            --agent-token)
                echo -e "${red}--agent-token is disabled because command-line secrets leak through process lists and shell history. Use --agent-token-stdin.${plain}"
                exit 1 ;;
            --agent-token-stdin)
                AGENT_TOKEN_STDIN=true; shift ;;
            --poll-interval)
                POLL_INTERVAL_ARG="$2"; shift 2 ;;
            --release-repo)
                RELEASE_REPO_ARG="$2"; shift 2 ;;
            --release-branch)
                RELEASE_BRANCH_ARG="$2"; shift 2 ;;
            -h|--help)
                echo "Agent: $0 [version] --api-host URL --agent-id ID --agent-token-stdin [--poll-interval SEC] [--release-repo OWNER/REPO]"
                exit 0 ;;
            --*)
                echo "Tham số không xác định: $1"; exit 1 ;;
            *)
                # Tương thích với tham số vị trí đầu tiên dùng làm phiên bản
                if [[ -z "$VERSION_ARG" ]]; then
                    VERSION_ARG="$1"; shift
                else
                    shift
                fi ;;
        esac
    done
}

validate_terminal_service_setting() {
    local saved=""
    if [[ "$DISABLE_EXECUTE_WAS_SET" != true && -f /etc/znode/terminal.env && ! -L /etc/znode/terminal.env ]]; then
        saved=$(sed -n 's/^DISABLE_EXECUTE=\([01]\)$/\1/p' /etc/znode/terminal.env | head -n 1)
        if [[ "$saved" == "0" || "$saved" == "1" ]]; then
            DISABLE_EXECUTE="$saved"
        fi
    fi
    DISABLE_EXECUTE="${DISABLE_EXECUTE:-0}"
    if [[ "$DISABLE_EXECUTE" != "0" && "$DISABLE_EXECUTE" != "1" ]]; then
        echo -e "${red}DISABLE_EXECUTE must be 0 or 1.${plain}"
        exit 1
    fi
}

load_agent_token() {
    if [[ "$AGENT_TOKEN_STDIN" != true ]]; then
        return 0
    fi
    if [[ -n "$AGENT_TOKEN_ARG" ]]; then
        echo -e "${red}Use only one of --agent-token or --agent-token-stdin.${plain}"
        exit 1
    fi
    if ! IFS= read -r AGENT_TOKEN_ARG || [[ -z "$AGENT_TOKEN_ARG" ]]; then
        echo -e "${red}Could not read the Agent token from standard input.${plain}"
        exit 1
    fi
}

validate_release_source() {
    if [[ ! "$RELEASE_REPO_ARG" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
        echo -e "${red}Invalid --release-repo; expected OWNER/REPO.${plain}"
        exit 1
    fi
    if [[ ! "$RELEASE_BRANCH_ARG" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] \
        || [[ "$RELEASE_BRANCH_ARG" == *..* ]] || [[ "$RELEASE_BRANCH_ARG" == *//* ]]; then
        echo -e "${red}Invalid --release-branch.${plain}"
        exit 1
    fi
}

https_api_origin() {
    local api_host="$1"
    local remainder authority host port normalized_host port_number

    if [[ ! "$api_host" =~ ^https:// ]] \
        || [[ "$api_host" == *\?* ]] \
        || [[ "$api_host" == *\#* ]] \
        || [[ "$api_host" == *\"* ]] \
        || [[ "$api_host" == *\\* ]] \
        || [[ "$api_host" =~ [[:space:]] ]]; then
        return 1
    fi

    remainder="${api_host#https://}"
    authority="${remainder%%/*}"
    if [[ -z "$authority" || "$authority" == *@* ]] \
        || [[ ! "$authority" =~ ^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(:([0-9]{1,5}))?$ ]]; then
        return 1
    fi

    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[3]}"
    if [[ -n "$port" ]]; then
        port_number=$((10#$port))
        if (( port_number < 1 || port_number > 65535 )); then
            return 1
        fi
    fi

    normalized_host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')
    if [[ -z "$port" || "$port_number" -eq 443 ]]; then
        printf 'https://%s\n' "$normalized_host"
    else
        printf 'https://%s:%d\n' "$normalized_host" "$port_number"
    fi
}

validate_https_api_host() {
    https_api_origin "$1" >/dev/null
}

validate_agent_args() {
    if [[ -n "$NODE_ID_ARG" && -n "$API_KEY_ARG" ]]; then
        if [[ -z "$AGENT_ID_ARG" ]]; then
            AGENT_ID_ARG="v2node-${NODE_ID_ARG}"
        fi
        if [[ -z "$AGENT_TOKEN_ARG" ]]; then
            AGENT_TOKEN_ARG="${API_KEY_ARG}"
        fi
    fi
    if [[ -z "$AGENT_ID_ARG" && -z "$AGENT_TOKEN_ARG" ]]; then
        if [[ -r /etc/znode/config.json ]] \
            && grep -Eq '"AgentID"[[:space:]]*:[[:space:]]*"[^"]+"' /etc/znode/config.json \
            && grep -Eq '"AgentToken"[[:space:]]*:[[:space:]]*"[^"]+"' /etc/znode/config.json; then
            return 0
        fi
        echo -e "${red}A new ZNode install requires the per-VPS Agent command generated by ZBoard.${plain}"
        exit 1
    fi
    if [[ -z "$API_HOST_ARG" || -z "$AGENT_ID_ARG" || -z "$AGENT_TOKEN_ARG" ]]; then
        echo -e "${red}Agent install requires --api-host, --agent-id and a token from --agent-token-stdin.${plain}"
        exit 1
    fi
    if ! validate_https_api_host "$API_HOST_ARG"; then
        echo -e "${red}Invalid --api-host; expected an HTTPS URL without quotes, backslashes or spaces.${plain}"
        exit 1
    fi
    if [[ ! "$AGENT_ID_ARG" =~ ^[A-Za-z0-9._~-]+$ ]]; then
        echo -e "${red}Invalid agent ID format.${plain}"
        exit 1
    fi
    if [[ ! "$AGENT_TOKEN_ARG" =~ ^[A-Za-z0-9._~-]+$ ]]; then
        echo -e "${red}Invalid agent token format.${plain}"
        exit 1
    fi
    if [[ ! "$POLL_INTERVAL_ARG" =~ ^[0-9]+$ ]] || (( POLL_INTERVAL_ARG < 5 || POLL_INTERVAL_ARG > 3600 )); then
        echo -e "${red}Invalid --poll-interval; expected 5..3600 seconds.${plain}"
        exit 1
    fi
}

rewrite_agent_token() {
    local input_file="$1"
    local output_file="$2"
    local new_token="$3"
    local updated_token line
    local replaced_count=0
    local unsafe_token_line=false

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^([[:space:]]*)\"AgentToken\"[[:space:]]*:[[:space:]]*\"[^\"]*\"([[:space:]]*)(,?)([[:space:]]*)$ ]]; then
            printf '%s"AgentToken": "%s"%s%s%s\n' \
                "${BASH_REMATCH[1]}" "$new_token" \
                "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"
            ((replaced_count += 1))
        elif [[ "$line" =~ ^[[:space:]]*\"AgentToken\"[[:space:]]*: ]]; then
            printf '%s\n' "$line"
            unsafe_token_line=true
        else
            printf '%s\n' "$line"
        fi
    done < "$input_file" > "$output_file"

    updated_token=$(sed -n 's/^[[:space:]]*"AgentToken"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$output_file" | head -n 1)
    [[ "$unsafe_token_line" != true && "$replaced_count" -eq 1 && "$updated_token" == "$new_token" ]]
}

validate_existing_agent_binding() {
    if [[ ! -f /etc/znode/config.json ]]; then
        return 0
    fi

    local existing_agent_id existing_api_host normalized_existing_host normalized_supplied_host
    existing_agent_id=$(sed -n 's/^[[:space:]]*"AgentID"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/znode/config.json | head -n 1)
    if [[ -z "$existing_agent_id" ]]; then
        echo -e "${red}This VPS already has a manual znode config. Back it up and remove /etc/znode/config.json before enrolling an agent.${plain}"
        exit 1
    fi

    existing_api_host=$(sed -n 's/^[[:space:]]*"ApiHost"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/znode/config.json | head -n 1)
    if ! validate_https_api_host "$existing_api_host"; then
        echo -e "${red}Existing Agent.ApiHost is missing or does not use HTTPS; refusing to install or rotate credentials until the config is migrated.${plain}"
        exit 1
    fi

    if [[ -z "$AGENT_ID_ARG" ]]; then
        return 0
    fi
    if [[ "$existing_agent_id" != "$AGENT_ID_ARG" ]]; then
        echo -e "${red}This VPS is already enrolled as agent ${existing_agent_id}; refusing to replace it with ${AGENT_ID_ARG}.${plain}"
        exit 1
    fi

    normalized_existing_host=$(https_api_origin "$existing_api_host") || exit 1
    normalized_supplied_host=$(https_api_origin "$API_HOST_ARG") || exit 1
    if [[ "$normalized_existing_host" != "$normalized_supplied_host" ]]; then
        echo -e "${red}This VPS is bound to a different ApiHost; refusing to rotate its token or retarget the panel automatically.${plain}"
        exit 1
    fi

    if [[ ! "$AGENT_TOKEN_ARG" =~ ^[A-Za-z0-9._~-]+$ ]]; then
        echo -e "${red}Invalid agent token format.${plain}"
        exit 1
    fi
    local existing_agent_token
    existing_agent_token=$(sed -n 's/^[[:space:]]*"AgentToken"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/znode/config.json | head -n 1)
    if [[ -z "$existing_agent_token" ]]; then
        echo -e "${red}Existing agent config has no AgentToken; refusing to edit it automatically.${plain}"
        exit 1
    fi
    if [[ "$existing_agent_token" != "$AGENT_TOKEN_ARG" ]]; then
        local updated_config
        updated_config=$(mktemp /etc/znode/config.json.XXXXXX) || exit 1
        if ! rewrite_agent_token /etc/znode/config.json "$updated_config" "$AGENT_TOKEN_ARG"; then
            rm -f "$updated_config"
            echo -e "${red}Could not update AgentToken safely.${plain}"
            exit 1
        fi
        if ! chmod 600 "$updated_config" || ! mv -f "$updated_config" /etc/znode/config.json; then
            rm -f "$updated_config"
            echo -e "${red}Could not commit the AgentToken update safely.${plain}"
            exit 1
        fi
        echo -e "${green}Updated the token for existing agent ${existing_agent_id}.${plain}"
    fi

    echo -e "${green}This VPS is already enrolled with the selected agent; keeping its identity and other settings.${plain}"
}

arch=$(uname -m)

if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
    arch="arm64-v8a"
elif [[ $arch == "s390x" ]]; then
    arch="s390x"
else
    arch="64"
    echo -e "${red}Không xác định được kiến trúc, sử dụng kiến trúc mặc định: ${arch}${plain}"
fi

if [ "$(getconf WORD_BIT)" != '32' ] && [ "$(getconf LONG_BIT)" != '64' ] ; then
    echo "Phần mềm không hỗ trợ hệ điều hành 32-bit (x86). Vui lòng sử dụng hệ điều hành 64-bit (x86_64); nếu phát hiện sai, hãy liên hệ tác giả."
    exit 2
fi

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}Vui lòng sử dụng CentOS 7 hoặc phiên bản mới hơn!${plain}\n" && exit 1
    fi
    if [[ ${os_version} -eq 7 ]]; then
        echo -e "${red}Lưu ý: CentOS 7 không hỗ trợ giao thức Hysteria 1/2!${plain}\n"
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}Vui lòng sử dụng Ubuntu 16 hoặc phiên bản mới hơn!${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}Vui lòng sử dụng Debian 8 hoặc phiên bản mới hơn!${plain}\n" && exit 1
    fi
fi

install_base() {
    # Kiểm tra và cài gói theo lô để giảm số lần gọi hệ thống
    need_install_apt() {
        local packages=("$@")
        local missing=()

        # Kiểm tra theo lô các gói đã cài
        local installed_list=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | sort)

        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done

        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "Đang cài các gói còn thiếu: ${missing[*]}"
            apt-get update -y >/dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" >/dev/null 2>&1
        fi
    }

    need_install_yum() {
        local packages=("$@")
        local missing=()

        # Kiểm tra theo lô các gói đã cài
        local installed_list=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort)

        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done

        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "Đang cài các gói còn thiếu: ${missing[*]}"
            yum install -y "${missing[@]}" >/dev/null 2>&1
        fi
    }

    need_install_apk() {
        local packages=("$@")
        local missing=()

        # Kiểm tra theo lô các gói đã cài
        local installed_list=$(apk info 2>/dev/null | sort)

        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done

        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "Đang cài các gói còn thiếu: ${missing[*]}"
            apk add --no-cache "${missing[@]}" >/dev/null 2>&1
        fi
    }

    # Cài tất cả gói bắt buộc trong một lượt
    if [[ x"${release}" == x"centos" ]]; then
        # Kiểm tra và cài epel-release
        if ! rpm -q epel-release >/dev/null 2>&1; then
            echo "Đang cài kho EPEL..."
            yum install -y epel-release >/dev/null 2>&1
        fi
        need_install_yum wget curl unzip tar cronie socat ca-certificates openssl pv nano
        update-ca-trust force-enable >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"alpine" ]]; then
        need_install_apk wget curl unzip tar socat ca-certificates openssl pv nano
        update-ca-certificates >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"debian" ]]; then
        need_install_apt wget curl unzip tar cron socat ca-certificates openssl pv nano
        update-ca-certificates >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"ubuntu" ]]; then
        need_install_apt wget curl unzip tar cron socat ca-certificates openssl pv nano
        update-ca-certificates >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"arch" ]]; then
        echo "Đang cập nhật cơ sở dữ liệu gói..."
        pacman -Sy --noconfirm >/dev/null 2>&1
        # --needed sẽ bỏ qua các gói đã cài
        echo "Đang cài các gói bắt buộc..."
        pacman -S --noconfirm --needed wget curl unzip tar cronie socat ca-certificates openssl pv nano >/dev/null 2>&1
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /usr/local/znode/znode ]]; then
        return 2
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        temp=$(service znode status | awk '{print $3}')
        if [[ x"${temp}" == x"started" ]]; then
            return 0
        else
            return 1
        fi
    else
        temp=$(systemctl status znode | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
        if [[ x"${temp}" == x"running" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

generate_znode_agent_config() {
        local api_host="$1"
        local agent_id="$2"
        local agent_token="$3"
	local poll_interval="$4"
	local agent_instance_id config_file temporary_config
	agent_instance_id=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)
	if [[ -z "$agent_instance_id" ]]; then
		agent_instance_id="$(hostname)-$(date +%s)"
	fi

        config_file="/etc/znode/config.json"
        mkdir -p /etc/znode >/dev/null 2>&1 || return 1
        temporary_config=$(mktemp /etc/znode/config.json.XXXXXX) || return 1
        if ! cat > "$temporary_config" <<EOF
{
    "type": "v2node",
    "Log": {
        "Level": "warning",
        "Output": "",
        "Access": "none"
    },
    "ResourceConfig": {
        "Profile": "standard",
        "DisableSniffing": true,
        "PeriodicMemoryReleaseInterval": 30
    },
    "ConnectionConfig": {
        "Handshake": 15,
        "ConnIdle": 120,
        "UplinkOnly": 2,
        "DownlinkOnly": 4,
        "BufferSize": 128,
        "DisableUDPContentSniffing": true,
        "MaxConnectionsPerUser": 128,
        "MaxConnections": 32768
    },
    "Agent": {
        "Enable": true,
        "ApiHost": "${api_host}",
        "AgentID": "${agent_id}",
		"AgentInstanceID": "${agent_instance_id}",
        "AgentToken": "${agent_token}",
        "PollInterval": ${poll_interval},
        "GlobalDeviceLimitConfig": {
            "Enable": true,
            "SyncEnabled": true,
            "SyncChannel": "v2board:device-sync",
            "RedisNetwork": "tcp",
            "RedisAddr": "127.0.0.1:6379",
            "RedisDB": 0,
            "Timeout": 2,
            "Expiry": 120,
            "RefreshInterval": 40,
            "MaxIPsPerUser": 256,
            "KeyPrefix": "znode:device",
            "FailClosed": false
        }
    },
    "Nodes": []
}
EOF
        then
            rm -f "$temporary_config"
            return 1
        fi
        if ! chmod 600 "$temporary_config" || ! mv -f "$temporary_config" "$config_file"; then
            rm -f "$temporary_config"
            return 1
        fi
        echo -e "${green}Znode agent config generated; assigned nodes will be synchronized automatically.${plain}"
        if [[ x"${release}" == x"alpine" ]]; then
            service znode restart
        else
            systemctl restart znode
        fi
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            echo -e "${green}znode agent started successfully.${plain}"
            return 0
        else
            echo -e "${red}znode agent may have failed to start; run: znode log${plain}"
            return 1
        fi
}

sha256_file() {
    openssl dgst -sha256 "$1" 2>/dev/null | awk '{print tolower($NF)}'
}

write_runtime_checksum() {
    local directory="$1"
    local digest
    [[ -x "$directory/znode" ]] || return 1
    digest=$(sha256_file "$directory/znode")
    [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || return 1
    printf '%s  znode\n' "$digest" > "$directory/.znode.sha256"
    chmod 600 "$directory/.znode.sha256"
}

verify_runtime_checksum() {
    local directory="$1"
    local expected actual
    [[ -x "$directory/znode" && -r "$directory/.znode.sha256" ]] || return 1
    expected=$(awk 'NR==1 {print tolower($1)}' "$directory/.znode.sha256")
    actual=$(sha256_file "$directory/znode")
    [[ "$expected" =~ ^[a-f0-9]{64}$ ]] \
        && [[ "$actual" =~ ^[a-f0-9]{64}$ ]] \
        && [[ "$expected" == "$actual" ]]
}

runtime_supports_terminal() {
    local directory="$1"
    [[ -x "$directory/znode" ]] && "$directory/znode" terminal --help >/dev/null 2>&1
}

remove_terminal_service() {
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update del znode-terminal default >/dev/null 2>&1 || true
        service znode-terminal stop >/dev/null 2>&1 || true
        rm -f /etc/init.d/znode-terminal
    else
        systemctl disable --now znode-terminal >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/znode-terminal.service
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed znode-terminal >/dev/null 2>&1 || true
    fi
}

start_terminal_service() {
    if [[ "$DISABLE_EXECUTE" == "1" ]]; then
        return 0
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        service znode-terminal restart >/dev/null 2>&1 || return 1
        sleep 1
        service znode-terminal status >/dev/null 2>&1
    else
        systemctl restart znode-terminal >/dev/null 2>&1 || return 1
        sleep 1
        systemctl is-active --quiet znode-terminal
    fi
}

restore_terminal_service_for_runtime() {
    local directory="$1"
    if ! runtime_supports_terminal "$directory"; then
        remove_terminal_service
        return 0
    fi
    if [[ "$DISABLE_EXECUTE" == "1" ]]; then
        if [[ x"${release}" == x"alpine" ]]; then
            rc-update del znode-terminal default >/dev/null 2>&1 || true
            service znode-terminal stop >/dev/null 2>&1 || true
        else
            systemctl disable --now znode-terminal >/dev/null 2>&1 || true
        fi
        return 0
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update add znode-terminal default >/dev/null 2>&1 || return 1
    else
        systemctl daemon-reload >/dev/null 2>&1 || return 1
        systemctl enable znode-terminal >/dev/null 2>&1 || return 1
    fi
    start_terminal_service
}

restore_previous_runtime() {
    local current_directory="/usr/local/znode"
    local previous_directory="/usr/local/znode.previous"
    local failed_directory="/usr/local/znode.failed.$(date +%s)"
    if ! verify_runtime_checksum "$previous_directory"; then
        echo -e "${red}Checksum runtime dự phòng không hợp lệ; từ chối tự động rollback.${plain}"
        return 1
    fi
    [[ -d "$current_directory" ]] || return 1

    if [[ x"${release}" == x"alpine" ]]; then
        service znode-terminal stop >/dev/null 2>&1 || true
        service znode stop >/dev/null 2>&1 || true
    else
        systemctl stop znode-terminal >/dev/null 2>&1 || true
        systemctl stop znode >/dev/null 2>&1 || true
    fi
    mv "$current_directory" "$failed_directory" || return 1
    if ! mv "$previous_directory" "$current_directory"; then
        mv "$failed_directory" "$current_directory" || true
        return 1
    fi
    mv "$failed_directory" "$previous_directory" || true
    if ! install_geodata "$current_directory"; then
        echo -e "${red}Runtime trước đã được khôi phục nhưng không thể khôi phục GeoIP/GeoSite; giữ dịch vụ dừng để kiểm tra thủ công.${plain}"
        return 1
    fi

    if [[ x"${release}" == x"alpine" ]]; then
        service znode start >/dev/null 2>&1 || true
    else
        systemctl start znode >/dev/null 2>&1 || true
    fi
    restore_terminal_service_for_runtime "$current_directory" || return 1
    sleep 2
    check_status
}

rollback_activated_runtime() {
    local had_previous="$1"
    local current_directory="/usr/local/znode"

    if [[ "$had_previous" == true ]]; then
        restore_previous_runtime
        return $?
    fi

    if [[ x"${release}" == x"alpine" ]]; then
        service znode-terminal stop >/dev/null 2>&1 || true
        service znode stop >/dev/null 2>&1 || true
    else
        systemctl stop znode-terminal >/dev/null 2>&1 || true
        systemctl stop znode >/dev/null 2>&1 || true
    fi
    rm -rf "$current_directory"
    remove_terminal_service
    echo -e "${yellow}Đã gỡ runtime mới vì đây là lần cài đầu và không có bản trước để khôi phục.${plain}"
}

validate_release_version() {
    [[ "$1" =~ ^v?[0-9]+\.[0-9]+(\.[0-9]+)?([-+_][A-Za-z0-9.-]+)?$ ]]
}

semver_key() {
    local value="${1#v}"
    local major minor patch
    value="${value%%[-+_]*}"
    IFS=. read -r major minor patch <<< "$value"
    printf '%09d%09d%09d' "$major" "$minor" "${patch:-0}"
}

latest_release_version() {
    local repository="$1"
    local metadata version
    metadata=$(curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
        --proto '=https' --tlsv1.2 \
        "https://api.github.com/repos/${repository}/releases/latest") || return 1
    version=$(printf '%s\n' "$metadata" | awk -F'"' '/"tag_name":/ {print $4; exit}')
    validate_release_version "$version" || return 1
    printf '%s\n' "$version"
}

download_verified_script_asset() {
    local repository="$1"
    local version="$2"
    local asset_name="$3"
    local destination="$4"
    local metadata expected actual asset_url asset_size

    validate_release_version "$version" || return 1
    case "$asset_name" in
        install.sh|znode.sh|v3node.sh) ;;
        *) return 1 ;;
    esac

    metadata=$(curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
        --proto '=https' --tlsv1.2 \
        "https://api.github.com/repos/${repository}/releases/tags/${version}") || return 1
    expected=$(printf '%s\n' "$metadata" | awk -v asset="$asset_name" '
        /"name":/ { selected = index($0, "\"" asset "\"") > 0 }
        selected && /"digest": "sha256:/ {
            value=$0
            sub(/^.*"digest": "sha256:/, "", value)
            sub(/".*$/, "", value)
            print tolower(value)
            exit
        }
    ')
    if [[ ! "$expected" =~ ^[a-f0-9]{64}$ ]]; then
        echo -e "${red}Release ${version} không công bố SHA-256 cho ${asset_name}; từ chối chạy script đặc quyền.${plain}"
        return 1
    fi

    asset_url="https://github.com/${repository}/releases/download/${version}/${asset_name}"
    if ! curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
        --proto '=https' --tlsv1.2 "$asset_url" -o "$destination"; then
        rm -f "$destination"
        return 1
    fi
    asset_size=$(wc -c < "$destination" | tr -d '[:space:]')
    actual=$(sha256_file "$destination")
    if [[ ! "$asset_size" =~ ^[0-9]+$ ]] || (( asset_size < 1024 || asset_size > 1048576 )) \
        || [[ ! "$actual" =~ ^[a-f0-9]{64}$ ]] || [[ "$actual" != "$expected" ]] \
        || ! bash -n "$destination"; then
        rm -f "$destination"
        echo -e "${red}Script ${asset_name} không vượt qua xác minh SHA-256/cú pháp; từ chối thực thi.${plain}"
        return 1
    fi
}

download_verified_release() {
    local version="$1"
    local archive="$2"
    local asset_name asset_url checksum_url expected actual metadata
    local archive_size digest_size entry_count uncompressed_size
    asset_name="v3node-linux-${arch}.zip"
    asset_url="https://github.com/${RELEASE_REPO_ARG}/releases/download/${version}/${asset_name}"
    checksum_url="${asset_url}.dgst"

    if ! curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
        --proto '=https' --tlsv1.2 "$asset_url" | pv -s 30M -W -N "Tiến trình tải" > "$archive"; then
        asset_name="znode-linux-${arch}.zip"
        asset_url="https://github.com/${RELEASE_REPO_ARG}/releases/download/${version}/${asset_name}"
        checksum_url="${asset_url}.dgst"
        if ! curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
            --proto '=https' --tlsv1.2 "$asset_url" | pv -s 30M -W -N "Tiến trình tải" > "$archive"; then
            echo -e "${red}Tải gói phát hành thất bại.${plain}"
            return 1
        fi
    fi
    archive_size=$(wc -c < "$archive")
    if [[ ! "$archive_size" =~ ^[0-9]+$ ]] || (( archive_size < 1048576 || archive_size > 268435456 )); then
        echo -e "${red}Kích thước gói phát hành không hợp lệ.${plain}"
        return 1
    fi
    expected=""
    if curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
        --proto '=https' --tlsv1.2 "$checksum_url" -o "${archive}.dgst" 2>/dev/null; then
        digest_size=$(wc -c < "${archive}.dgst")
        if [[ ! "$digest_size" =~ ^[0-9]+$ ]] || (( digest_size < 64 || digest_size > 65536 )); then
            echo -e "${red}Tệp checksum của release có kích thước bất thường.${plain}"
            return 1
        fi
        expected=$(awk 'toupper($1) ~ /^SHA(2-)?256=$/ {print tolower($2); exit}' "${archive}.dgst")
    else
        rm -f "${archive}.dgst"
        metadata=$(curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
            --proto '=https' --tlsv1.2 \
            "https://api.github.com/repos/${RELEASE_REPO_ARG}/releases/tags/${version}") || metadata=""
        expected=$(printf '%s\n' "$metadata" | awk -v asset="$asset_name" '
            /"name":/ { selected = index($0, "\"" asset "\"") > 0 }
            selected && /"digest": "sha256:/ {
                value=$0
                sub(/^.*"digest": "sha256:/, "", value)
                sub(/".*$/, "", value)
                print tolower(value)
                exit
            }
        ')
    fi

    actual=$(sha256_file "$archive")
    if [[ ! "$expected" =~ ^[a-f0-9]{64}$ ]] || [[ ! "$actual" =~ ^[a-f0-9]{64}$ ]] || [[ "$expected" != "$actual" ]]; then
        echo -e "${red}Không có SHA-256 tin cậy hoặc checksum gói phát hành không khớp; không thực thi binary đã tải.${plain}"
        return 1
    fi

    if unzip -Z1 "$archive" | grep -Eq '(^/|(^|/)\.\.(/|$)|\\)'; then
        echo -e "${red}Gói phát hành chứa đường dẫn không an toàn.${plain}"
        return 1
    fi
    entry_count=$(unzip -Z1 "$archive" | wc -l | tr -d '[:space:]')
    uncompressed_size=$(unzip -l "$archive" | awk 'END {print $1}')
    if [[ ! "$entry_count" =~ ^[0-9]+$ || ! "$uncompressed_size" =~ ^[0-9]+$ ]] \
        || (( entry_count < 1 || entry_count > 64 || uncompressed_size > 536870912 )); then
        echo -e "${red}Gói phát hành vượt giới hạn giải nén an toàn.${plain}"
        return 1
    fi
}

install_manager_script() {
    local temporary manager_ref script_name="v3node.sh"
    temporary=$(mktemp /usr/bin/.v3node.XXXXXX) || return 1
    manager_ref=$(latest_release_version "$RELEASE_REPO_ARG")
    if [[ -z "$manager_ref" ]] \
        || ! download_verified_script_asset "$RELEASE_REPO_ARG" "$manager_ref" "$script_name" "$temporary"; then
        script_name="znode.sh"
        if ! download_verified_script_asset "$RELEASE_REPO_ARG" "$manager_ref" "$script_name" "$temporary"; then
            rm -f "$temporary"
            echo -e "${red}Không tải được manager đã xác minh từ release bảo mật mới nhất.${plain}"
            return 1
        fi
    fi
    if ! chmod 0755 "$temporary" || ! mv -f "$temporary" /usr/bin/v3node; then
        rm -f "$temporary"
        echo -e "${red}Không thể cài manager script theo giao dịch atomic; manager hiện tại được giữ nguyên.${plain}"
        return 1
    fi
    ln -sf /usr/bin/v3node /usr/bin/znode
}

install_znode() {
    local version_param="$1"
    local current_directory="/usr/local/znode"
    local previous_directory="/usr/local/znode.previous"
    local staging_directory archive current_version extracted_version
    local had_previous=false

    mkdir -p /usr/local
    staging_directory=$(mktemp -d /usr/local/znode.new.XXXXXX) || exit 1
    archive="$staging_directory/znode-linux.zip"

    if  [[ -z "$version_param" ]] ; then
        last_version=$(curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
            --proto '=https' --tlsv1.2 "https://api.github.com/repos/${RELEASE_REPO_ARG}/releases/latest" \
            | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}Không xác định được phiên bản znode, có thể đã vượt giới hạn GitHub API. Hãy thử lại sau hoặc chỉ định phiên bản để cài thủ công.${plain}"
            rm -rf "$staging_directory"
            exit 1
        fi
        echo -e "${green}Đã tìm thấy phiên bản mới nhất: ${last_version}. Bắt đầu cài đặt...${plain}"
    else
        last_version=$version_param
    fi
    if ! validate_release_version "$last_version"; then
        echo -e "${red}Phiên bản phát hành không hợp lệ: ${last_version}.${plain}"
        rm -rf "$staging_directory"
        exit 1
    fi
    if [[ -x "$current_directory/znode" ]]; then
        current_version=$("$current_directory/znode" version 2>/dev/null | awk 'NR==1 {print $2}')
        if validate_release_version "$current_version" \
            && [[ "$(semver_key "$last_version")" < "$(semver_key "$current_version")" ]]; then
            echo -e "${red}Release ${last_version} cũ hơn runtime hiện tại ${current_version}; dùng rollback đã xác minh thay vì hạ cấp tùy ý.${plain}"
            rm -rf "$staging_directory"
            exit 1
        fi
    fi

    if ! download_verified_release "$last_version" "$archive"; then
        rm -rf "$staging_directory"
        exit 1
    fi
    if ! unzip -q "$archive" -d "$staging_directory"; then
        echo -e "${red}Không giải nén được gói phát hành đã xác minh.${plain}"
        rm -rf "$staging_directory"
        exit 1
    fi
    rm -f "$archive" "${archive}.dgst"
    if [[ ! -f "$staging_directory/v3node" && ! -f "$staging_directory/znode" ]] \
        || find "$staging_directory" -type l -print -quit | grep -q .; then
        echo -e "${red}Gói phát hành không chứa binary ở vị trí mong đợi hoặc có symlink.${plain}"
        rm -rf "$staging_directory"
        exit 1
    fi
    if [[ -f "$staging_directory/v3node" ]]; then
        chmod 755 "$staging_directory/v3node"
        cp -f "$staging_directory/v3node" "$staging_directory/znode" 2>/dev/null || true
    elif [[ -f "$staging_directory/znode" ]]; then
        chmod 755 "$staging_directory/znode"
        cp -f "$staging_directory/znode" "$staging_directory/v3node" 2>/dev/null || true
    fi
    extracted_version=$("$staging_directory/v3node" version 2>/dev/null | awk 'NR==1 {print $2}')
    if [[ -z "$extracted_version" ]]; then
        extracted_version=$("$staging_directory/znode" version 2>/dev/null | awk 'NR==1 {print $2}')
    fi
    if [[ "${extracted_version#v}" != "${last_version#v}" ]]; then
        echo -e "${red}Binary báo phiên bản ${extracted_version:-không xác định}, không khớp release ${last_version}.${plain}"
        rm -rf "$staging_directory"
        exit 1
    fi
    if ! write_runtime_checksum "$staging_directory"; then
        echo -e "${red}Không thể ghi checksum cho runtime mới.${plain}"
        rm -rf "$staging_directory"
        exit 1
    fi
    if ! validate_geodata "$staging_directory"; then
        echo -e "${red}Xác minh dữ liệu GeoIP/GeoSite thất bại; runtime hiện hành chưa bị thay đổi.${plain}"
        rm -rf "$staging_directory"
        exit 1
    fi
    mkdir /etc/znode/ -p
    if ! ensure_instance_secret; then
        echo -e "${red}Không thể tạo khóa định danh riêng cho VPS; hủy cài đặt terminal.${plain}"
        rm -rf "$staging_directory"
        exit 1
    fi
    printf 'DISABLE_EXECUTE=%s\n' "$DISABLE_EXECUTE" > /etc/znode/terminal.env
    chmod 600 /etc/znode/terminal.env

    # Only replace the live tree after the archive, checksum, paths, binary and
    # geodata have all passed validation. The former tree becomes the sole
    # rollback candidate and carries its own binary checksum.
    if [[ -d "$current_directory" ]]; then
        had_previous=true
        write_runtime_checksum "$current_directory" || {
            echo -e "${red}Không thể chốt checksum runtime hiện tại; hủy update để giữ bản đang chạy.${plain}"
            rm -rf "$staging_directory"
            exit 1
        }
        rm -rf "$previous_directory"
        mv "$current_directory" "$previous_directory" || exit 1
    fi
    if ! mv "$staging_directory" "$current_directory"; then
        [[ -d "$previous_directory" && ! -d "$current_directory" ]] && mv "$previous_directory" "$current_directory"
        echo -e "${red}Không thể kích hoạt runtime mới; đã khôi phục bản hiện tại.${plain}"
        exit 1
    fi
    cd "$current_directory" || exit 1
    if ! install_geodata "$current_directory"; then
        echo -e "${red}Không thể kích hoạt GeoIP/GeoSite mới; đang rollback runtime.${plain}"
        if ! rollback_activated_runtime "$had_previous"; then
            echo -e "${red}Rollback sau lỗi GeoIP/GeoSite thất bại; hãy kiểm tra dịch vụ thủ công.${plain}"
        fi
        exit 1
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        rm /etc/init.d/znode -f
        cat <<EOF > /etc/init.d/znode
#!/sbin/openrc-run

name="znode"
description="znode"

command="/usr/local/znode/znode"
command_args="server"
command_user="root"
export XRAY_LOCATION_ASSET="/etc/znode"

pidfile="/run/znode.pid"
command_background="yes"

depend() {
        need net
}
EOF
        chmod +x /etc/init.d/znode
        rc-update add znode default
        cat <<EOF > /etc/init.d/znode-terminal
#!/sbin/openrc-run

name="znode-terminal"
description="znode outbound terminal relay"
command="/usr/local/znode/znode"
command_args="terminal"
command_user="root"
pidfile="/run/znode-terminal.pid"
command_background="yes"
start_pre() {
    if [ -f /etc/znode/terminal.env ]; then
        . /etc/znode/terminal.env
        export DISABLE_EXECUTE
    fi
}
depend() { need net; }
EOF
        chmod +x /etc/init.d/znode-terminal
        if [[ "$DISABLE_EXECUTE" == "1" ]]; then
            rc-update del znode-terminal default >/dev/null 2>&1 || true
            service znode-terminal stop >/dev/null 2>&1 || true
        else
            rc-update add znode-terminal default
        fi
        echo -e "${green}Đã cài znode ${last_version}${plain} và bật tự khởi động cùng hệ thống."
    else
        rm /etc/systemd/system/znode.service /etc/systemd/system/v3node.service -f
        cat <<EOF > /etc/systemd/system/v3node.service
[Unit]
Description=v3node Service
After=network.target nss-lookup.target
Wants=network.target

[Service]
User=root
Group=root
Type=simple
Environment=XRAY_LOCATION_ASSET=/etc/znode
LimitNOFILE=262144
TasksMax=8192
MemoryHigh=80%
MemoryMax=90%
WorkingDirectory=/usr/local/znode/
ExecStart=/usr/local/znode/v3node server
TimeoutStopSec=45s
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        ln -sf /etc/systemd/system/v3node.service /etc/systemd/system/znode.service
        cat <<EOF > /etc/systemd/system/znode-terminal.service
[Unit]
Description=znode outbound terminal relay
After=network.target nss-lookup.target
Wants=network.target

[Service]
User=root
Group=root
Type=simple
WorkingDirectory=/usr/local/znode/
EnvironmentFile=-/etc/znode/terminal.env
ExecStart=/usr/local/znode/znode terminal
TimeoutStopSec=45s
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable v3node znode 2>/dev/null || systemctl enable znode
        if [[ "$DISABLE_EXECUTE" == "1" ]]; then
            systemctl disable --now znode-terminal >/dev/null 2>&1 || true
        else
            systemctl enable znode-terminal
        fi
        # Keep the old runtime serving while the new tree, service unit and
        # configuration are staged. Activation below performs one short
        # restart instead of leaving every inbound offline during the update.
        echo -e "${green}Đã cài znode ${last_version}${plain} và bật tự khởi động cùng hệ thống."
    fi

    if [[ ! -f /etc/znode/config.json ]]; then
        if ! generate_znode_agent_config "$API_HOST_ARG" "$AGENT_ID_ARG" "$AGENT_TOKEN_ARG" "$POLL_INTERVAL_ARG"; then
            if ! rollback_activated_runtime "$had_previous"; then
                echo -e "${red}Không thể rollback sau lỗi tạo cấu hình Agent; hãy kiểm tra dịch vụ thủ công.${plain}"
            fi
            exit 1
        fi
        echo -e "${green}Agent config written to /etc/znode/config.json${plain}"
    else
        if ! ensure_zboard_config_type; then
            echo -e "${red}Xác minh type=zboard thất bại sau activation; đang rollback runtime.${plain}"
            if ! rollback_activated_runtime "$had_previous"; then
                echo -e "${red}Không thể rollback sau lỗi cấu hình; hãy kiểm tra dịch vụ thủ công.${plain}"
            fi
            exit 1
        fi
        migrate_tiktok_compat_profile
        if [[ x"${release}" == x"alpine" ]]; then
            service znode restart
        else
            systemctl restart znode
        fi
        sleep 2
        check_status
        local runtime_status=$?
        echo -e ""
        if [[ $runtime_status == 0 ]]; then
            echo -e "${green}Khởi động lại znode thành công${plain}"
        else
            echo -e "${red}Runtime mới không khởi động; đang khôi phục bản trước.${plain}"
            if rollback_activated_runtime "$had_previous"; then
                if [[ "$had_previous" == true ]]; then
                    echo -e "${yellow}Đã khôi phục runtime trước; update được đánh dấu thất bại.${plain}"
                else
                    echo -e "${yellow}Đã gỡ runtime lỗi của lần cài đầu; cài đặt được đánh dấu thất bại.${plain}"
                fi
            else
                echo -e "${red}Không thể tự khôi phục runtime trước. Hãy kiểm tra dịch vụ thủ công.${plain}"
            fi
            exit 1
        fi
    fi

    # enable --now does not replace an already-running process after an
    # in-place runtime swap. Restart the relay here so it always executes the
    # current binary, including the first-config path above.
    if ! start_terminal_service; then
        echo -e "${red}Dịch vụ terminal riêng không khởi động được; đang rollback runtime.${plain}"
        if ! rollback_activated_runtime "$had_previous"; then
            echo -e "${red}Không thể rollback sau lỗi terminal; hãy kiểm tra dịch vụ thủ công.${plain}"
        fi
        exit 1
    fi


    if ! install_manager_script; then
        echo -e "${red}Cài manager script thất bại; đang rollback runtime mới.${plain}"
        if ! rollback_activated_runtime "$had_previous"; then
            echo -e "${red}Không thể rollback sau lỗi manager script; hãy kiểm tra dịch vụ thủ công.${plain}"
        fi
        exit 1
    fi
    printf '%s\n' "$RELEASE_REPO_ARG" > /etc/znode/release-repo
    printf '%s\n' "$RELEASE_BRANCH_ARG" > /etc/znode/release-branch
    chmod 644 /etc/znode/release-repo /etc/znode/release-branch
    install_log_cleanup

    cd $cur_dir
    rm -f install.sh
    echo "------------------------------------------"
    echo -e "Cách sử dụng script quản lý: "
    echo "------------------------------------------"
    echo "znode              - Hiển thị menu quản lý (đầy đủ chức năng)"
    echo "znode start        - Khởi động znode"
    echo "znode stop         - Dừng znode"
    echo "znode restart      - Khởi động lại znode"
    echo "znode status       - Xem trạng thái znode"
    echo "znode enable       - Bật tự khởi động cùng hệ thống"
    echo "znode disable      - Tắt tự khởi động cùng hệ thống"
    echo "znode log          - Xem nhật ký znode"
    echo "znode generate     - Hướng dẫn enrollment Agent qua ZBoard"
    echo "znode update       - Cập nhật znode"
    echo "znode update x.x.x - Cập nhật znode lên phiên bản chỉ định"
    echo "znode rollback     - Quay lại bản znode trước đó"
    echo "znode install      - Cài đặt znode"
    echo "znode uninstall    - Gỡ cài đặt znode"
    echo "znode version      - Xem phiên bản znode"
    echo "------------------------------------------"
}

parse_args "$@"
validate_terminal_service_setting
load_agent_token
validate_release_source
acquire_znode_operation_lock || exit 1
trap release_znode_operation_lock EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
validate_agent_args
reject_legacy_v2node_config || exit 1
ensure_zboard_config_type || exit 1
validate_existing_agent_binding
echo -e "${green}Bắt đầu cài đặt${plain}"
install_base
install_znode "$VERSION_ARG"
