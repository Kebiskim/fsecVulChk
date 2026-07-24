#!/bin/bash
# lib/common.sh - shared functions for check.sh / apply.sh
# MODE=check : never modifies the system (verdicts: PASS/VULN/N-A)
# MODE=apply : applies initial hardening (verdicts: SUCCESS/ERROR/N-A)
# version for: RHEL 9+

OK=0; ERR=0; NA=0

is_apply() { [ "$MODE" = apply ]; }

log() {  # log <SRV-ID> <STATUS> <message>
    printf '[%s] [%s] [%s] %s\n' "$(date '+%F %T')" "$1" "$2" "$3" | tee -a "$LOG"
    case "$2" in SUCCESS|PASS) OK=$((OK+1));; ERROR|VULN) ERR=$((ERR+1));; N-A) NA=$((NA+1));; esac
}
pass() { log "$1" "$(is_apply && echo SUCCESS || echo PASS)" "$2"; }
fail() { log "$1" "$(is_apply && echo ERROR || echo VULN)" "$2"; }
na()   { log "$1" N-A "$2"; }
note() {  # per-method sub-check log (not counted in summary).
          # ALWAYS call this even when a command is missing, recording the reason.
    printf '[%s] [%s] [CHECK] %s\n' "$(date '+%F %T')" "$1" "$2" | tee -a "$LOG"
}

bak() {  # backup a file before modification (apply mode only, once per file)
    is_apply || return 0
    [ -f "$1" ] && [ ! -f "$BACKUP_DIR/$(echo "$1" | tr / _)" ] && \
        cp -a "$1" "$BACKUP_DIR/$(echo "$1" | tr / _)"
    return 0
}

set_kv() {  # (apply only) set_kv <file> <key> <value> <space|eq>
            # replaces active lines only; comment lines untouched; appends if absent
    is_apply || return 0
    local f=$1 k=$2 v=$3 sep=${4:-space} line
    bak "$f"; touch "$f"
    [ "$sep" = eq ] && line="${k} = ${v}" || line="${k} ${v}"
    if grep -Eq "^[[:space:]]*${k}([[:space:]]|=)" "$f"; then
        sed -ri "s#^[[:space:]]*${k}([[:space:]]*=|[[:space:]]+).*#${line}#" "$f"
    else
        echo "$line" >> "$f"
    fi
}

unit_exists() {  # systemd unit exists (exact-name match to avoid prefix false positives)
    local u=$1; case "$u" in *.service|*.socket) ;; *) u="${u}.service";; esac
    systemctl list-unit-files --no-legend "$u" 2>/dev/null | grep -q .
}
unit_active() {
    local u=$1; case "$u" in *.service|*.socket) ;; *) u="${u}.service";; esac
    systemctl is-active "$u" >/dev/null 2>&1
}
svc_off() {  # (apply only) stop + disable. return 0=unit exists, 1=not installed
    local u=$1; case "$u" in *.service|*.socket) ;; *) u="${u}.service";; esac
    unit_exists "$u" || return 1
    is_apply || return 0
    systemctl stop "$u" >/dev/null 2>&1
    systemctl disable "$u" >/dev/null 2>&1
    return 0
}

perm_le() {  # perm_le <file> <max-perm> : current perm within limit? (special bits excluded)
    [ -e "$1" ] || return 2
    local a=$((8#$(stat -c %a "$1"))) m=$((8#$2))
    [ $(( a & ~m & 0777 )) -eq 0 ]
}
owner_is() { [ "$(stat -c %U "$1" 2>/dev/null)" = "${2:-root}" ]; }

perm_max() {  # (apply only) enforce owner/permission if file exists
    [ -e "$1" ] || return 1
    is_apply || return 0
    bak "$1"
    chown "${3:-root:root}" "$1" 2>/dev/null
    chmod "$2" "$1" 2>/dev/null
    return 0
}

get_ldef() { awk -v k="$1" '$1==k {print $2}' /etc/login.defs 2>/dev/null | tail -1; }

init_common() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run as root. (sudo bash $0)" >&2; exit 1
    fi
    TS=$(date +%Y%m%d_%H%M%S)
    LOG=${LOG_DIR:-/var/log}/hardening_${MODE}_${TS}.log
    touch "$LOG" && chmod 600 "$LOG"
    if is_apply; then
        BACKUP_DIR=/root/init_hardening_backup_${TS}
        mkdir -p "$BACKUP_DIR"
    fi
    # home directories of login-capable accounts (shared by modules)
    # filter shell field like SRV-074: excludes sync/shutdown/halt whose homes are /sbin,/bin
    HOMEDIRS=$(awk -F: '$7 !~ /nologin|false|\/sync$|shutdown|halt/ && $6!="/" {print $6}' /etc/passwd | sort -u)
    SSHD=/etc/ssh/sshd_config
}

summary() {
    local a=SUCCESS b=ERROR ; is_apply || { a=PASS; b=VULN; }
    echo "==============================================================" | tee -a "$LOG"
    echo " Done(${MODE}): ${a} ${OK} / ${b} ${ERR} / N-A ${NA}"            | tee -a "$LOG"
    echo " Log: ${LOG}"                                                    | tee -a "$LOG"
    is_apply && echo " Backup: ${BACKUP_DIR}  (copy files back to revert)" | tee -a "$LOG"
    echo "==============================================================" | tee -a "$LOG"
    [ "$ERR" -eq 0 ] && exit 0 || exit 2
}
