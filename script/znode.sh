#!/bin/bash

set -o pipefail
umask 077

# The manager downloads and launches a privileged installer. Do not let an
# inherited search path, Bash startup file or loader configuration replace the
# system helpers or inject code into those child processes.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH OPENSSL_CONF

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)
release_repo="Duyvj/v3node"
release_branch="main"
[[ -s /etc/znode/release-repo ]] && release_repo=$(tr -d '\r\n' < /etc/znode/release-repo)
[[ -s /etc/znode/release-branch ]] && release_branch=$(tr -d '\r\n' < /etc/znode/release-branch)
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

if [[ ! "$release_repo" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
    || [[ ! "$release_branch" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] \
    || [[ "$release_branch" == *..* ]] || [[ "$release_branch" == *//* ]]; then
    echo "Invalid ZNode release source in /etc/znode/release-{repo,branch}." >&2
    exit 1
fi
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

confirm() {
    if [[ $# > 1 ]]; then
        echo && read -rp "$1 [mặc định: $2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -rp "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "Bạn có muốn khởi động lại znode không?" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}Nhấn Enter để quay lại menu chính: ${plain}" && read temp
    show_menu
}

validate_release_version() {
    [[ "$1" =~ ^v?[0-9]+\.[0-9]+(\.[0-9]+)?([-+_][A-Za-z0-9.-]+)?$ ]]
}

sha256_file() {
    openssl dgst -sha256 "$1" 2>/dev/null | awk '{print tolower($NF)}'
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

run_installer() {
    local temporary status trusted_installer_ref target_version=""
    if [[ $# -gt 0 && "$1" != --* ]]; then
        target_version="$1"
        shift
        if [[ ! "$target_version" =~ ^v?[0-9]+\.[0-9]+(\.[0-9]+)?([-+_][A-Za-z0-9.-]+)?$ ]]; then
            echo -e "${red}Phiên bản ZNode đích không hợp lệ.${plain}"
            return 1
        fi
    fi

    # The requested binary version is data, never the source of installer
    # code. Always run the loader from the latest trusted release so selecting
    # an older runtime cannot revive an installer without checksum/rollback
    # enforcement.
    trusted_installer_ref=$(latest_release_version "$release_repo")
    if [[ -z "$trusted_installer_ref" ]]; then
        echo -e "${red}Không xác định được release tag hợp lệ cho installer.${plain}"
        return 1
    fi
    temporary=$(mktemp) || return 1
    if ! download_verified_script_asset "$release_repo" "$trusted_installer_ref" install.sh "$temporary"; then
        rm -f "$temporary"
        echo -e "${red}Không tải được installer đã xác minh từ release bảo mật mới nhất.${plain}"
        return 1
    fi
    if [[ -n "$target_version" ]]; then
        bash "$temporary" "$target_version" "$@"
    else
        bash "$temporary" "$trusted_installer_ref" "$@"
    fi
    status=$?
    rm -f "$temporary"
    return "$status"
}

install() {
    local install_status
    run_installer --release-repo "$release_repo" --release-branch "$release_branch"
    install_status=$?
    if [[ $install_status == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
    return "$install_status"
}

update() {
    local update_status
    if [[ $# == 0 ]]; then
        echo && echo -n -e "Nhập phiên bản cần cài (mặc định là mới nhất): " && read version
    else
        version=$2
    fi
    if [[ -n "$version" ]]; then
        run_installer "$version" --release-repo "$release_repo" --release-branch "$release_branch"
    else
        run_installer --release-repo "$release_repo" --release-branch "$release_branch"
    fi
    update_status=$?
    if [[ $update_status == 0 ]]; then
        echo -e "${green}Cập nhật hoàn tất và znode đã tự khởi động lại. Dùng znode log để xem nhật ký.${plain}"
        exit 0
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
    return "$update_status"
}

validate_runtime_geodata() {
    local runtime_directory="$1"
    local file
    for file in geoip.dat geosite.dat; do
        if [[ ! -s "$runtime_directory/$file" ]] \
            || [[ $(wc -c < "$runtime_directory/$file") -lt 1024 ]]; then
            echo -e "${red}Runtime dự phòng không chứa $file hợp lệ; từ chối rollback.${plain}"
            return 1
        fi
    done
}

install_runtime_geodata() (
    local runtime_directory="$1"
    local destination="${2:-/etc/znode}"
    local transaction_directory file restore_file

    validate_runtime_geodata "$runtime_directory" || return 1
    mkdir -p "$destination" || return 1
    transaction_directory=$(mktemp -d "$destination/.geodata.XXXXXX") || return 1
    trap 'rm -rf "$transaction_directory"' EXIT

    for file in geoip.dat geosite.dat; do
        install -m 0644 "$runtime_directory/$file" "$transaction_directory/new-$file" || return 1
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
)

swap_runtime_trees() {
    local current_directory="${1:-/usr/local/znode}"
    local previous_directory="${2:-/usr/local/znode.previous}"
    local transaction_directory held_runtime transaction_parent

    [[ -d "$current_directory" && -d "$previous_directory" ]] || return 1
    transaction_parent="${current_directory%/*}"
    transaction_directory=$(mktemp -d "$transaction_parent/.znode-swap.XXXXXX") || return 1
    held_runtime="$transaction_directory/runtime"

    if ! mv "$current_directory" "$held_runtime"; then
        rmdir "$transaction_directory" 2>/dev/null || true
        return 1
    fi
    if ! mv "$previous_directory" "$current_directory"; then
        mv "$held_runtime" "$current_directory" || true
        rmdir "$transaction_directory" 2>/dev/null || true
        return 1
    fi
    if ! mv "$held_runtime" "$previous_directory"; then
        mv "$current_directory" "$previous_directory" || true
        mv "$held_runtime" "$current_directory" || true
        rmdir "$transaction_directory" 2>/dev/null || true
        return 1
    fi
    rmdir "$transaction_directory" 2>/dev/null || true
}

start_znode_service() {
    if [[ x"${release}" == x"alpine" ]]; then
        service znode start >/dev/null 2>&1 || return 1
    else
        systemctl start znode >/dev/null 2>&1 || return 1
    fi
    start_terminal_service
}

stop_znode_service() {
    if [[ x"${release}" == x"alpine" ]]; then
        service znode-terminal stop >/dev/null 2>&1 || true
        service znode stop >/dev/null 2>&1 || true
    else
        systemctl stop znode-terminal >/dev/null 2>&1 || true
        systemctl stop znode >/dev/null 2>&1 || true
    fi
}

terminal_execution_disabled() {
    local value="${DISABLE_EXECUTE:-}"
    if [[ "$value" != "0" && "$value" != "1" && -f /etc/znode/terminal.env && ! -L /etc/znode/terminal.env ]]; then
        value=$(sed -n 's/^DISABLE_EXECUTE=\([01]\)$/\1/p' /etc/znode/terminal.env | head -n 1)
    fi
    [[ "$value" == "1" ]]
}

runtime_supports_terminal() {
    [[ -x /usr/local/znode/znode ]] && /usr/local/znode/znode terminal --help >/dev/null 2>&1
}

remove_terminal_service() {
    if [[ x"${release}" == x"alpine" ]]; then
        service znode-terminal stop >/dev/null 2>&1 || true
        rc-update del znode-terminal default >/dev/null 2>&1 || true
        rm -f /etc/init.d/znode-terminal
    else
        systemctl disable --now znode-terminal >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/znode-terminal.service
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed znode-terminal >/dev/null 2>&1 || true
    fi
}

install_terminal_service_unit() {
    if [[ x"${release}" == x"alpine" ]]; then
        cat <<'EOF' > /etc/init.d/znode-terminal
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
        chmod 0755 /etc/init.d/znode-terminal
        return $?
    fi
    cat <<'EOF' > /etc/systemd/system/znode-terminal.service
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
    systemctl daemon-reload >/dev/null 2>&1
}

enable_terminal_service() {
    if terminal_execution_disabled || ! runtime_supports_terminal; then
        return 0
    fi
    install_terminal_service_unit || return 1
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update add znode-terminal default >/dev/null 2>&1
    else
        systemctl enable znode-terminal >/dev/null 2>&1
    fi
}

start_terminal_service() {
    if terminal_execution_disabled; then
        if [[ x"${release}" == x"alpine" ]]; then
            service znode-terminal stop >/dev/null 2>&1 || true
            rc-update del znode-terminal default >/dev/null 2>&1 || true
        else
            systemctl disable --now znode-terminal >/dev/null 2>&1 || true
        fi
        return 0
    fi
    if ! runtime_supports_terminal; then
        remove_terminal_service
        return 0
    fi
    enable_terminal_service || return 1
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

restore_runtime_after_failed_rollback() {
    if ! swap_runtime_trees; then
        echo -e "${red}Không thể đưa runtime ban đầu trở lại vị trí hoạt động; giữ dịch vụ dừng.${plain}"
        return 1
    fi
    if ! install_runtime_geodata /usr/local/znode; then
        echo -e "${red}Runtime ban đầu đã trở lại nhưng GeoIP/GeoSite không thể khôi phục; giữ dịch vụ dừng.${plain}"
        return 1
    fi
    start_znode_service || return 1
    sleep 2
    check_status
}

rollback() (
    acquire_znode_operation_lock || return 1
    trap release_znode_operation_lock EXIT
    if [[ ! -x /usr/local/znode.previous/znode ]]; then
        echo -e "${red}Chưa có bản trước để quay lại. Hãy cập nhật thành công ít nhất một lần trước.${plain}"
        return 1
    fi
    local previous_version expected_checksum actual_checksum service_status=0
    if [[ ! -r /usr/local/znode.previous/.znode.sha256 ]]; then
        echo -e "${red}Bản dự phòng không có checksum tin cậy; từ chối thực thi.${plain}"
        return 1
    fi
    expected_checksum=$(awk 'NR==1 {print tolower($1)}' /usr/local/znode.previous/.znode.sha256)
    actual_checksum=$(openssl dgst -sha256 /usr/local/znode.previous/znode 2>/dev/null | awk '{print tolower($NF)}')
    if [[ ! "$expected_checksum" =~ ^[a-f0-9]{64}$ ]] \
        || [[ ! "$actual_checksum" =~ ^[a-f0-9]{64}$ ]] \
        || [[ "$expected_checksum" != "$actual_checksum" ]]; then
        echo -e "${red}Checksum bản dự phòng không khớp; từ chối rollback.${plain}"
        return 1
    fi
    previous_version=$(/usr/local/znode.previous/znode version 2>/dev/null | awk 'NR==1 {print $2}')
    if [[ ! "$previous_version" =~ ^v?([0-9]+)\.([0-9]+) ]] || (( ${BASH_REMATCH[1]} < 1 )) || (( ${BASH_REMATCH[1]} == 1 && ${BASH_REMATCH[2]} < 2 )); then
        echo -e "${red}Bản dự phòng ${previous_version:-không xác định} chưa hỗ trợ điều khiển Agent tự động; từ chối rollback để tránh mất kết nối quản trị.${plain}"
        return 1
    fi
    if ! validate_runtime_geodata /usr/local/znode.previous; then
        return 1
    fi
    echo -e "${yellow}Đang quay lại bản ZNode trước...${plain}"
    stop_znode_service
    if ! swap_runtime_trees; then
        echo -e "${red}Không thể hoán đổi runtime; bản hiện hành được giữ nguyên.${plain}"
        start_znode_service || true
        return 1
    fi
    if ! install_runtime_geodata /usr/local/znode; then
        echo -e "${red}Không thể kích hoạt GeoIP/GeoSite của bản rollback; đang khôi phục runtime ban đầu.${plain}"
        restore_runtime_after_failed_rollback || true
        return 1
    fi
    start_znode_service || service_status=$?
    sleep 2
    if [[ $service_status == 0 ]] && check_status; then
        echo -e "${green}Đã quay lại bản trước. Dùng znode version và znode log để kiểm tra.${plain}"
        return 0
    fi

    echo -e "${red}Bản rollback không khởi động; đang khôi phục runtime ban đầu.${plain}"
    stop_znode_service
    if restore_runtime_after_failed_rollback; then
        echo -e "${red}Rollback thất bại; runtime và GeoIP/GeoSite ban đầu đã được khôi phục.${plain}"
    else
        echo -e "${red}Rollback thất bại và không thể tự khôi phục đầy đủ; dịch vụ được giữ dừng.${plain}"
    fi
    return 1
)

config() {
    echo "znode sẽ tự khởi động lại sau khi bạn chỉnh sửa cấu hình"
    nano /etc/znode/config.json
    sleep 2
    restart
    check_status
    case $? in
        0)
            echo -e "Trạng thái znode: ${green}đang chạy${plain}"
            ;;
        1)
            echo -e "znode chưa chạy hoặc tự khởi động lại thất bại. Bạn có muốn xem nhật ký không? [Y/n]" && echo
            read -e -rp "(mặc định: y):" yn
            [[ -z ${yn} ]] && yn="y"
            if [[ ${yn} == [Yy] ]]; then
               show_log
            fi
            ;;
        2)
            echo -e "Trạng thái znode: ${red}chưa cài đặt${plain}"
    esac
}

uninstall() {
    confirm "Bạn có chắc muốn gỡ cài đặt znode không?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    acquire_znode_operation_lock || return 1
    trap release_znode_operation_lock EXIT
    stop_znode_service
    remove_terminal_service
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update del znode
        rm /etc/init.d/znode -f
    else
        systemctl disable znode
        rm /etc/systemd/system/znode.service -f
        systemctl daemon-reload
        systemctl reset-failed
    fi
    rm /etc/znode/ -rf
    rm /usr/local/znode/ -rf
    rm /usr/local/znode.previous/ -rf
    release_znode_operation_lock

    echo ""
    echo -e "Gỡ cài đặt thành công. Nếu muốn xóa cả script này, hãy thoát rồi chạy ${green}rm /usr/bin/znode -f${plain}"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        if start_terminal_service; then
            echo ""
            echo -e "${green}znode và dịch vụ terminal riêng đang ở trạng thái mong muốn.${plain}"
        else
            echo -e "${red}znode đang chạy nhưng dịch vụ terminal riêng không khởi động được.${plain}"
        fi
    else
        start_znode_service
        local start_status=$?
        sleep 2
        if [[ $start_status == 0 ]] && check_status; then
            echo -e "${green}Khởi động znode thành công. Dùng znode log để xem nhật ký.${plain}"
        else
            echo -e "${red}Có thể znode khởi động thất bại. Vui lòng dùng znode log để kiểm tra nhật ký.${plain}"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    stop_znode_service
    sleep 2
    check_status
    if [[ $? == 1 ]]; then
        echo -e "${green}Dừng znode thành công${plain}"
    else
        echo -e "${red}Dừng znode thất bại, có thể tiến trình cần hơn 2 giây. Vui lòng kiểm tra nhật ký sau.${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    stop_znode_service
    start_znode_service
    local restart_status=$?
    sleep 2
    if [[ $restart_status == 0 ]] && check_status; then
        echo -e "${green}Khởi động lại znode thành công. Dùng znode log để xem nhật ký.${plain}"
    else
        echo -e "${red}Có thể znode khởi động thất bại. Vui lòng dùng znode log để kiểm tra nhật ký.${plain}"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    if [[ x"${release}" == x"alpine" ]]; then
        service znode status
    else
        systemctl status znode --no-pager -l
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    local status=0
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update add znode || status=$?
    else
        systemctl enable znode || status=$?
    fi
    enable_terminal_service || status=$?
    if [[ $status == 0 ]]; then
        echo -e "${green}Đã bật tự khởi động znode cùng hệ thống${plain}"
    else
        echo -e "${red}Không thể bật tự khởi động znode cùng hệ thống${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    local status=0
    if [[ x"${release}" == x"alpine" ]]; then
        rc-update del znode || status=$?
        rc-update del znode-terminal default >/dev/null 2>&1 || true
    else
        systemctl disable znode || status=$?
        systemctl disable znode-terminal >/dev/null 2>&1 || true
    fi
    if [[ $status == 0 ]]; then
        echo -e "${green}Đã tắt tự khởi động znode cùng hệ thống${plain}"
    else
        echo -e "${red}Không thể tắt tự khởi động znode cùng hệ thống${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    if [[ x"${release}" == x"alpine" ]]; then
        echo -e "${red}Alpine hiện chưa hỗ trợ xem nhật ký bằng chức năng này${plain}\n" && exit 1
    else
        journalctl -u znode.service -e --no-pager -f
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

update_shell() {
    local temporary manager_ref
    manager_ref=$(latest_release_version "$release_repo")
    if [[ -z "$manager_ref" ]]; then
        echo -e "${red}Không xác định được release tag hợp lệ cho manager script.${plain}"
        return 1
    fi
    acquire_znode_operation_lock || return 1
    trap release_znode_operation_lock EXIT
    temporary=$(mktemp /usr/bin/.znode.XXXXXX) || {
        release_znode_operation_lock
        return 1
    }
    if ! download_verified_script_asset "$release_repo" "$manager_ref" znode.sh "$temporary"; then
        rm -f "$temporary"
        echo ""
        echo -e "${red}Tải script thất bại. Vui lòng kiểm tra kết nối tới GitHub.${plain}"
        release_znode_operation_lock
        before_show_menu
    else
        if chmod 0755 "$temporary" && mv -f "$temporary" /usr/bin/znode; then
            echo -e "${green}Nâng cấp script thành công. Vui lòng chạy lại script.${plain}" && exit 0
        fi
        rm -f "$temporary"
        echo -e "${red}Không thể cài manager script theo giao dịch atomic; manager hiện tại được giữ nguyên.${plain}"
        release_znode_operation_lock
        return 1
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

check_enabled() {
    if [[ x"${release}" == x"alpine" ]]; then
        temp=$(rc-update show | grep znode)
        if [[ x"${temp}" == x"" ]]; then
            return 1
        else
            return 0
        fi
    else
        temp=$(systemctl is-enabled znode)
        if [[ x"${temp}" == x"enabled" ]]; then
            return 0
        else
            return 1;
        fi
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        echo -e "${red}znode đã được cài đặt, vui lòng không cài lại.${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        echo -e "${red}Vui lòng cài đặt znode trước.${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
        0)
            echo -e "Trạng thái znode: ${green}đang chạy${plain}"
            show_enable_status
            ;;
        1)
            echo -e "Trạng thái znode: ${yellow}đã dừng${plain}"
            show_enable_status
            ;;
        2)
            echo -e "Trạng thái znode: ${red}chưa cài đặt${plain}"
    esac
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "Tự khởi động cùng hệ thống: ${green}có${plain}"
    else
        echo -e "Tự khởi động cùng hệ thống: ${red}không${plain}"
    fi
}

show_znode_version() {
    echo -n "Phiên bản znode: "
    /usr/local/znode/znode version
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

generate_config_file() {
    echo -e "${red}Legacy global API-key enrollment is disabled.${plain}"
    echo "Create or rotate a per-VPS Agent in ZBoard and run its enrollment command instead."
    return 1
}

show_usage() {
    echo "Cách sử dụng script quản lý znode: "
    echo "------------------------------------------"
    echo "znode              - Hiển thị menu quản lý (đầy đủ chức năng)"
    echo "znode start        - Khởi động znode"
    echo "znode stop         - Dừng znode"
    echo "znode restart      - Khởi động lại znode"
    echo "znode status       - Xem trạng thái znode"
    echo "znode enable       - Bật tự khởi động cùng hệ thống"
    echo "znode disable      - Tắt tự khởi động cùng hệ thống"
    echo "znode log          - Xem nhật ký znode"
    echo "znode x25519       - Tạo khóa x25519"
    echo "znode generate     - Hướng dẫn enrollment Agent qua ZBoard"
    echo "znode update       - Cập nhật znode"
    echo "znode update x.x.x - Cài phiên bản znode chỉ định"
    echo "znode rollback     - Quay lại bản znode trước đó"
    echo "znode install      - Cài đặt znode"
    echo "znode uninstall    - Gỡ cài đặt znode"
    echo "znode version      - Xem phiên bản znode"
    echo "------------------------------------------"
}

show_menu() {
    echo -e "
  ${green}Script quản lý znode, ${plain}${red}không dùng cho Docker${plain}
--- https://github.com/Duyvj/v3node ---
  ${green}0.${plain} Chỉnh sửa cấu hình
————————————————
  ${green}1.${plain} Cài đặt znode
  ${green}2.${plain} Cập nhật znode
  ${green}3.${plain} Gỡ cài đặt znode
————————————————
  ${green}4.${plain} Khởi động znode
  ${green}5.${plain} Dừng znode
  ${green}6.${plain} Khởi động lại znode
  ${green}7.${plain} Xem trạng thái znode
  ${green}8.${plain} Xem nhật ký znode
————————————————
  ${green}9.${plain} Bật tự khởi động cùng hệ thống
  ${green}10.${plain} Tắt tự khởi động cùng hệ thống
————————————————
  ${green}11.${plain} Xem phiên bản znode
  ${green}12.${plain} Nâng cấp script quản lý znode
  ${green}13.${plain} Hướng dẫn enrollment Agent qua ZBoard
  ${green}14.${plain} Thoát script
 "
 # Có thể bổ sung chức năng mới vào menu phía trên
    show_status
    echo && read -rp "Vui lòng chọn [0-14]: " num

    case "${num}" in
        0) config ;;
        1) check_uninstall && install ;;
        2) check_install && update ;;
        3) check_install && uninstall ;;
        4) check_install && start ;;
        5) check_install && stop ;;
        6) check_install && restart ;;
        7) check_install && status ;;
        8) check_install && show_log ;;
        9) check_install && enable ;;
        10) check_install && disable ;;
        11) check_install && show_znode_version ;;
        12) update_shell ;;
        13) generate_config_file ;;
        14) exit ;;
        *) echo -e "${red}Vui lòng nhập đúng một số từ 0 đến 15.${plain}" ;;
    esac
}


if [[ $# > 0 ]]; then
    case $1 in
        "start") check_install 0 && start 0 ;;
        "stop") check_install 0 && stop 0 ;;
        "restart") check_install 0 && restart 0 ;;
        "status") check_install 0 && status 0 ;;
        "enable") check_install 0 && enable 0 ;;
        "disable") check_install 0 && disable 0 ;;
        "log") check_install 0 && show_log 0 ;;
        "update") check_install 0 && update 0 $2 ;;
        "rollback") check_install 0 && rollback 0 ;;
        "config") config $* ;;
        "generate") generate_config_file ;;
        "install") check_uninstall 0 && install 0 ;;
        "uninstall") check_install 0 && uninstall 0 ;;
        "version") check_install 0 && show_znode_version 0 ;;
        "update_shell") update_shell ;;
        *) show_usage
    esac
else
    show_menu
fi
