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
