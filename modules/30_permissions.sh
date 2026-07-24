#!/bin/bash
# modules/30_permissions.sh - umask / file permissions
# (SRV-121,122,087,091,092,093,096,084,082,083,081,094,025,012,095,144,164,166)

srv_122() {  # Methods x2: 1)per-account umask 2)config files (profile, $HOME/.profile, .*shrc)
    if is_apply; then
        cat > /etc/profile.d/umask.sh <<EOF
# init_hardening: umask criterion 022 or stricter [SRV-122]
umask ${UMASK_VAL}
EOF
        chmod 644 /etc/profile.d/umask.sh
        set_kv /etc/login.defs UMASK "$UMASK_VAL" space
    fi
    weak_umask() {  # vulnerable when the write bit (2) is not masked for group or others
        local v=$1; [ ${#v} -lt 3 ] && return 0
        local g=${v: -2:1} o=${v: -1}
        [ $(( g & 2 )) -eq 0 ] || [ $(( o & 2 )) -eq 0 ]
    }
    # Method 1: system default umask (login.defs)
    local ud; ud=$(get_ldef UMASK)
    note SRV-122 "Method 1) default umask (login.defs UMASK): ${ud:-unset}"
    # Method 2: umask in config files
    local pf bad_files=""
    pf=$(grep -rhE '^\s*umask\s' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | awk '{print $2}' | tail -1)
    note SRV-122 "Method 2-1) umask in /etc/profile family: ${pf:-unset}"
    for h in $HOMEDIRS; do
        for f in "$h/.profile" "$h/.bashrc" "$h/.kshrc" "$h/.cshrc"; do
            [ -f "$f" ] || continue
            local hv; hv=$(grep -E '^\s*umask\s' "$f" 2>/dev/null | awk '{print $2}' | tail -1)
            [ -n "$hv" ] && weak_umask "$hv" && bad_files="$bad_files ${f}(${hv})"
        done
    done
    note SRV-122 "Method 2-2) umask in home env files: weak values:${bad_files:-none}"
    local eff=${pf:-$ud}
    if [ -z "$eff" ]; then fail SRV-122 "umask setting not found"
    elif weak_umask "$eff" || [ -n "$bad_files" ]; then
        fail SRV-122 "weak umask: effective=${eff}${bad_files:+, env files:$bad_files} (022 or stricter required)"
    else pass SRV-122 "umask ${eff} (g/o write masked)${bad_files:+, exceptions:$bad_files}"; fi
}

srv_121() {  # Method: '.' or '::' in PATH (single)
    local prof_bad; prof_bad=$(grep -En 'PATH=.*(::|(^|:)\.(:|$))' /root/.bash_profile /root/.bashrc /etc/profile 2>/dev/null)
    local cur=good; echo "$PATH" | grep -qE '(^|:)\.(:|$)|::' && cur="contains '.'/'::'"
    note SRV-121 "Method) root PATH: current session=${cur}, profiles=${prof_bad:-no issue}"
    if [ -z "$prof_bad" ] && [ "$cur" = good ]; then pass SRV-121 "no '.' or '::' in root PATH"
    else fail SRV-121 "'.' or '::' in PATH - fix manually: ${prof_bad:-current session}"; fi
}

srv_087() {  # Method: others permission on C compilers via ls -alL (single)
    local found="" bad=""
    for c in /usr/bin/gcc /usr/bin/cc /usr/bin/g++ /usr/bin/c++; do
        local real; real=$(readlink -f "$c" 2>/dev/null || echo "$c")
        [ -f "$real" ] || continue
        case " $found " in *" $real "*) continue;; esac
        found="$found $real"
        is_apply && chmod o-rx "$real" 2>/dev/null
        perm_le "$real" 750 || bad="$bad ${real}($(stat -c %a "$real"))"
    done
    note SRV-087 "Method) C compiler others permission (ls -alL): ${found:-no compiler}${bad:+ / with others perm:$bad}"
    if [ -z "${found// /}" ]; then na SRV-087 "C compiler not installed"
    elif [ -z "$bad" ]; then pass SRV-087 "compilers have no others execute:$found"
    else fail SRV-087 "compilers with others permission:$bad"; fi
}

srv_091() {  # Method: find SUID/SGID files - full listing in log + new-file detection vs baseline
    # Fixed 12 paths agreed by KISA guidance as "SUID unnecessary on any system".
    # Only paths in this list can ever be chmod'ed by step (1) below. Files not in
    # this list are never modified, even when the scan below finds them.
    local SUID_REMOVE="/sbin/dump /sbin/restore /usr/bin/at /usr/bin/lpq /usr/bin/lpr /usr/bin/lprm \
/usr/bin/newgrp /usr/sbin/lpc /usr/sbin/traceroute /usr/bin/lpq-lpd /usr/bin/lpr-lpd /usr/bin/lprm-lpd"

    local hit="" removed=""
    for f in $SUID_REMOVE; do                  # iterate the fixed 12 paths only (no system search)
        [ -f "$f" ] || continue                # skip if the path does not exist (filters most)
        if [ -u "$f" ] || [ -g "$f" ]; then    # file exists AND SUID(-u) or SGID(-g) bit set
            if is_apply; then
                # (1) [THE ONLY MODIFICATION POINT] runs only via apply.sh.
                #     Three conditions must all hold: path in the 12-item list
                #     + file exists + bit set.
                #     e.g. /usr/bin/at installed as 4755 -> becomes 0755 (bit removed only)
                #     Never runs in check mode (is_apply is false).
                chmod -s "$f" && removed="$removed $f"   # record path for the log
            else
                hit="$hit $f"                  # check mode: record only -> VULN verdict below
            fi
        fi
    done

    # (2) [READ ONLY] full filesystem scan - the exact FSI assessment command.
    #     Result goes into LIST only; no chmod/rm is ever done with this list.
    local LIST; LIST=$(find / -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al {} \; 2>/dev/null)
    local cnt; cnt=$(echo "$LIST" | grep -c .)

    # (3) [READ ONLY] print the scan result line by line (perm/owner/path as-is)
    note SRV-091 "Method) find SUID/SGID files: total ${cnt}, KISA removal candidates:${hit:-${removed:- none}} - full list below"
    echo "$LIST" | while IFS= read -r l; do [ -n "$l" ] && note SRV-091 "  $l"; done

    # (4) [READ ONLY] check mode only: compare paths against the latest baseline
    #     saved by apply; new SUID files are logged/verdicted but never touched.
    local BASEF new=""
    BASEF=$(ls -t /root/suid_baseline_*.txt 2>/dev/null | head -1)   # newest baseline
    if ! is_apply && [ -n "$BASEF" ]; then
        # comm -13: paths present now but absent from baseline = new SUID files
        new=$(comm -13 <(awk '{print $NF}' "$BASEF" | sort -u) <(echo "$LIST" | awk '{print $NF}' | sort -u))
        note SRV-091 "Method) new vs baseline ($(basename "$BASEF")): ${new:-none}"
    elif ! is_apply; then
        note SRV-091 "Method) baseline compare: no baseline file (created by apply.sh) - count/list only"
    fi

    # (5) final verdict + (apply only) write baseline text file
    if is_apply; then
        local BASE=/root/suid_baseline_${TS}.txt
        printf '%s\n' "$LIST" > "$BASE"        # creates a new file (scan listing); nothing modified/deleted
        chmod 600 "$BASE"                      # permission of the text file just created; unrelated to system binaries
        pass SRV-091 "unneeded SUID removed:${removed:-none} / baseline of ${cnt} files saved (${BASE})"
    elif [ -n "$hit" ]; then                   # check: KISA candidate found -> VULN (fix via apply or manually)
        fail SRV-091 "unneeded (KISA candidate) SUID present:$hit"
    elif [ -n "$new" ]; then                   # check: new file not in baseline -> VULN (fix manually)
        fail SRV-091 "new SUID/SGID vs baseline: $(echo $new | tr '\n' ' ') - verify then chmod -s or refresh baseline"
    else
        pass SRV-091 "no KISA candidates, no new SUID (total ${cnt})"
    fi
}

srv_092() {  # Methods x2: 1)home paths in passwd 2)home owner/permission via ls -al
    # system account(UID<1000, root) excluded
    # => also checks newly added files
	local dup_home; dup_home=$(awk -F: '$7!~/nologin|false/ && ($3>=1000 || $1=="root") {print $6}' /etc/passwd | sort | uniq -d)
    note SRV-092 "Method 1) home paths in /etc/passwd: duplicate homes:${dup_home:-none}"
    local bad_own="" bad_perm="" no_home="" fixed=""
    while IFS=: read -r user _ uid _ _ home shell; do
        case "$shell" in */nologin|*/false) continue;; esac
        [ "$uid" -lt 1000 ] && [ "$user" != root ] && continue
        # account whose home does not exist: record instead of skipping
        # (abnormal state - login falls back to /)
        if [ ! -d "$home" ]; then
            no_home="$no_home ${user}(${home})"
            note SRV-092 "  [MISSING HOME] account=${user} passwd-home=${home}"
            continue
        fi
        local owner perm; owner=$(stat -c %U "$home"); perm=$(stat -c %a "$home")
        local prob=""
        [ "$owner" != "$user" ] && { bad_own="$bad_own ${user}"; prob="owner-mismatch(${owner})"; }
        if [ $(( perm % 10 & 2 )) -ne 0 ]; then
            if is_apply; then chmod o-w "$home" && fixed="$fixed $home" && prob="${prob:+$prob, }o+w->fixed"
            else bad_perm="$bad_perm ${user}"; prob="${prob:+$prob, }others-write(${perm})"; fi
        fi
        # one log line per problematic account
        [ -n "$prob" ] && note SRV-092 "  [MISMATCH] account=${user} home=${home} owner=${owner} perm=${perm} -> ${prob}"
    done < /etc/passwd
    note SRV-092 "Method 2) home owner/permission summary: owner-mismatch[${bad_own:- none}] / o+w[${bad_perm:-${fixed:- none}}] / missing-home[${no_home:- none}]"
    if [ -z "$bad_own" ] && [ -z "$bad_perm" ] && [ -z "$dup_home" ] && [ -z "$no_home" ]; then
        pass SRV-092 "home dirs: owners match, no duplicates, no others-write, none missing${fixed:+ (o-w fixed:$fixed)}"
    else
        fail SRV-092 "home dir issues - owner-mismatch:${bad_own:-none} / perm:${bad_perm:-none} / duplicate:${dup_home:-none} / missing:${no_home:-none}"
    fi
}

srv_093() {  # Method: find -perm -2 under home dirs (single)
    local cnt=0 fixed=0 f h
    for h in $HOMEDIRS; do
        [ -d "$h" ] || continue
        while IFS= read -r f; do
            cnt=$((cnt+1))
            if is_apply; then chmod o-w "$f" 2>/dev/null && fixed=$((fixed+1)) && echo "  o-w removed: $f" >> "$LOG"
            else note SRV-093 "  world-writable: $(ls -alL "$f" 2>/dev/null)"; fi
        done < <(find "$h" -xdev -perm -2 -type f 2>/dev/null)
    done
    note SRV-093 "Method) world-writable files under home dirs (find): ${cnt}"
    if is_apply; then pass SRV-093 "o-w removed from ${fixed} of ${cnt} world-writable files"
    elif [ "$cnt" -eq 0 ]; then pass SRV-093 "no world-writable files"
    else fail SRV-093 "${cnt} world-writable files - verify business need then remove"; fi
}

srv_096() {  # Method: permission of user shell env files (.profile .login .*shrc etc)
    local bad=0 fixed=0 bad_files="" seen=""
    for h in $HOMEDIRS; do
        # explicit env files + any .*shrc file (.bashrc .kshrc .cshrc .zshrc .tcshrc ...)
        for f in "$h"/.profile "$h"/.login "$h"/.bash_profile "$h"/.*shrc; do
            [ -f "$f" ] || continue
            case " $seen " in *" $f "*) continue;; esac
            seen="$seen $f"
            # vulnerable when others has any read/write/execute bit
            if [ $(( $(stat -c %a "$f") % 10 )) -ne 0 ]; then
                bad=$((bad+1)); bad_files="$bad_files ${f}($(stat -c %a "$f"))"
                is_apply && chmod o-rwx "$f" 2>/dev/null && fixed=$((fixed+1))
            fi
        done
    done
    note SRV-096 "Method) others permission on user env files (.profile/.login/.*shrc):${bad_files:- none}"
    if is_apply; then pass SRV-096 "others permission removed from ${fixed} of ${bad} env files"
    elif [ "$bad" -eq 0 ]; then pass SRV-096 "no env files with others permission"
    else fail SRV-096 "${bad} env files with others read/write/execute permission:${bad_files}"; fi
}

srv_084() {  # Per-file criteria: passwd 644 / shadow 600 / hosts 644 / (x)inetd 600 /
             # syslog 644 / services 644 / hosts.lpd 640 - one log line per file
    local spec="/etc/passwd:644 /etc/shadow:600 /etc/hosts:644 /etc/inetd.conf:600 /etc/xinetd.conf:600 \
/etc/syslog.conf:644 /etc/syslogd.conf:644 /etc/rsyslog.conf:644 /etc/services:644 /etc/hosts.lpd:640"
    local bad="" n=0
    for e in $spec; do
        local f=${e%:*} p=${e#*:}; n=$((n+1))
        if [ ! -e "$f" ]; then note SRV-084 "Method ${n}) ${f} (criterion ${p}): file missing"; continue; fi
        if is_apply; then
            if [ "$f" = /etc/shadow ]; then
                # shadow: only lower the permission; keep distro default 000
                chown root:root "$f" 2>/dev/null
                [ "$(stat -c %a "$f")" -gt 600 ] 2>/dev/null && { bak "$f"; chmod 600 "$f"; }
            else perm_max "$f" "$p"; fi
        fi
        local cur; cur="$(stat -c '%U/%a' "$f")"
        if perm_le "$f" "$p" && owner_is "$f" root; then
            note SRV-084 "Method ${n}) ${f} (criterion root/${p} or lower): ${cur} - meets"
        else
            note SRV-084 "Method ${n}) ${f} (criterion root/${p} or lower): ${cur} - below"
            bad="$bad $f"
        fi
    done
    is_apply && [ -d /etc/xinetd.d ] && { chown -R root:root /etc/xinetd.d; chmod 600 /etc/xinetd.d/* 2>/dev/null; }
    [ -z "$bad" ] && pass SRV-084 "key file permissions meet criteria" || fail SRV-084 "files below criteria:$bad"
}

srv_082() {  # Method: ls -alLd /usr /bin /sbin /etc /var (single)
    local bad=""
    for d in /usr /bin /sbin /etc /var; do
        [ -d "$d" ] || continue
        local perm; perm=$(stat -Lc %a "$d")
        if [ $(( ${perm: -1} & 2 )) -ne 0 ]; then
            if is_apply; then chmod o-w "$(readlink -f "$d")" && bad="$bad ${d}(fixed)"
            else bad="$bad ${d}(${perm})"; fi
        fi
    done
    note SRV-082 "Method) others-write on key directories: ${bad:-all good}"
    if is_apply; then pass SRV-082 "key directory others-write checked/fixed"
    elif [ -z "$bad" ]; then pass SRV-082 "no others-write on key directories"
    else fail SRV-082 "others-write allowed:$bad"; fi
}

srv_083() {  # Method: file permissions in startup directories (single)
    local cnt=0 fixed=0 f d
    for d in /etc/init.d /etc/rc.d /usr/lib/systemd/system /etc/systemd/system; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            cnt=$((cnt+1))
            if is_apply; then chmod o-w "$f" 2>/dev/null && fixed=$((fixed+1)) && echo "  o-w removed: $f" >> "$LOG"
            else note SRV-083 "  others-write: $(ls -alL "$f" 2>/dev/null)"; fi
        done < <(find "$d" -xdev -type f -perm -2 2>/dev/null)
    done
    note SRV-083 "Method) o+w files in startup dirs (init.d/rc.d/systemd): ${cnt}"
    if is_apply; then pass SRV-083 "o-w removed from ${fixed} startup files (${cnt} found)"
    elif [ "$cnt" -eq 0 ]; then pass SRV-083 "no others-write on startup scripts"
    else fail SRV-083 "${cnt} files with others-write"; fi
}

srv_081() {  # Methods x4: 1)crontab command 2)spool 3)at.allow/deny 4)cron.allow/deny
    # Method 1
    local r1="file missing" r1_bad=""
    if [ -f /usr/bin/crontab ]; then
        is_apply && chmod 4750 /usr/bin/crontab 2>/dev/null
        if perm_le /usr/bin/crontab 4750; then r1="$(stat -c %a /usr/bin/crontab) meets (750 or lower)"
        else r1="$(stat -c %a /usr/bin/crontab) below criterion"; r1_bad=y; fi
    fi
    note SRV-081 "Method 1) /usr/bin/crontab permission: ${r1}"
    # Method 2
    local r2="directory missing" sp_bad="" sp_seen=""
    for d in /var/spool/cron; do
        [ -d "$d" ] || continue
        is_apply && find "$d" -type f -exec chmod 600 {} \; 2>/dev/null
        find "$d" -type f \( -perm -o+r -o -perm -o+w \) 2>/dev/null | grep -q . && sp_bad="$sp_bad $d"
        sp_seen=y
    done
    [ -n "$sp_seen" ] && r2="others permission:${sp_bad:-none}"
    note SRV-081 "Method 2) /var/spool/cron file permissions: ${r2}"
    # Methods 3 and 4
    local r34_bad=""
    for f in /etc/at.allow /etc/at.deny; do
        [ -e "$f" ] || { note SRV-081 "Method 3) ${f}: file missing"; continue; }
        is_apply && perm_max "$f" 640
        { perm_le "$f" 640 && owner_is "$f" root; } \
            && note SRV-081 "Method 3) ${f}: $(stat -c '%U/%a' "$f") meets" \
            || { note SRV-081 "Method 3) ${f}: $(stat -c '%U/%a' "$f") below"; r34_bad="$r34_bad $f"; }
    done
    for f in /etc/cron.allow /etc/cron.deny; do
        [ -e "$f" ] || { note SRV-081 "Method 4) ${f}: file missing"; continue; }
        is_apply && perm_max "$f" 640
        { perm_le "$f" 640 && owner_is "$f" root; } \
            && note SRV-081 "Method 4) ${f}: $(stat -c '%U/%a' "$f") meets" \
            || { note SRV-081 "Method 4) ${f}: $(stat -c '%U/%a' "$f") below"; r34_bad="$r34_bad $f"; }
    done
    if [ -n "$r1_bad" ] || [ -n "$sp_bad" ] || [ -n "$r34_bad" ]; then
        fail SRV-081 "cron-related file permissions below criteria:${sp_bad}${r34_bad}"
    else pass SRV-081 "cron-related file permissions meet criteria (methods 1-4)"; fi
}

srv_094() {  # Method: permissions of files cron executes (single)
    local cnt=0 fixed=0 f d
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            cnt=$((cnt+1))
            if is_apply; then chmod o-w "$f" 2>/dev/null && fixed=$((fixed+1)) && echo "  o-w removed: $f" >> "$LOG"
            else note SRV-094 "  others-write: $(ls -alL "$f" 2>/dev/null)"; fi
        done < <(find "$d" -xdev -type f -perm -2 2>/dev/null)
    done
    is_apply && perm_max /etc/crontab 644
    note SRV-094 "Method) o+w files in cron reference dirs: ${cnt} (scripts inside user crontabs: review manually)"
    if is_apply; then pass SRV-094 "o-w removed from ${fixed} cron reference files"
    elif [ "$cnt" -eq 0 ]; then pass SRV-094 "no others-write on cron reference files"
    else fail SRV-094 "${cnt} reference files with others-write"; fi
}

srv_025() {  # Methods x2: 1)/etc/hosts.equiv 2)per-account $HOME/.rhosts - check '+' and stray entries
    local bad="" fixed=""
    chk_rf() {  # <no> <file>
        [ -f "$2" ] || { note SRV-025 "Method $1) $2: file missing (good)"; return 0; }
        if grep -q '^\s*+' "$2"; then
            if is_apply; then
                bak "$2"; sed -ri 's|^(\s*\+)|# init_hardening blocked: \1|' "$2"; chmod 600 "$2"
                note SRV-025 "Method $1) $2: '+' found -> commented out, 600 applied"
                fixed="$fixed $2"
            else
                note SRV-025 "Method $1) $2: '+' entry found (vulnerable)"
                bad="$bad $2"
            fi
        else
            is_apply && perm_max "$2" 600
            # no '+', but list actual host/account entries so operator can verify they are trusted only
            local ents; ents=$(grep -vE '^\s*(#|$)' "$2" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/ $//')
            note SRV-025 "Method $1) $2: no '+', perm $(stat -c %a "$2")${ents:+, entries: ${ents} (verify trusted hosts only)}"
            perm_le "$2" 600 || bad="$bad ${2}(perm-too-open)"
        fi
    }
    chk_rf 1 /etc/hosts.equiv
    for h in $HOMEDIRS; do chk_rf 2 "$h/.rhosts"; done
    if [ -n "$fixed" ]; then pass SRV-025 "'+' commented out and 600 applied:$fixed (review contents manually)"
    elif [ -n "$bad" ]; then fail SRV-025 "vulnerable settings:$bad"
    else pass SRV-025 "hosts.equiv/.rhosts no issues (methods 1-2)"; fi
}

srv_012() {  # Methods x2: 1).netrc existence 2)sensitive contents (manual)
    local netrc; netrc=$(for h in $HOMEDIRS; do [ -f "$h/.netrc" ] && echo "$h/.netrc"; done)
    note SRV-012 "Method 1) .netrc files present: ${netrc:-none}"
    if [ -z "$netrc" ]; then
        note SRV-012 "Method 2) sensitive contents check: not applicable (no file)"
        pass SRV-012 "no .netrc files"; return
    fi
    # Method 2: scan contents for credential keywords (login/password/account)
    local sens=""
    for f in $netrc; do
        grep -iqwE 'password|login|account' "$f" 2>/dev/null && sens="$sens $f"
        is_apply && chmod 600 "$f" 2>/dev/null
    done
    note SRV-012 "Method 2) .netrc with sensitive info (login/password/account):${sens:-none}"
    if [ -n "$sens" ]; then
        fail SRV-012 ".netrc contains sensitive info:${sens}$(is_apply && echo ' - 600 applied,') remove credentials or delete file"
    else
        pass SRV-012 ".netrc present but no sensitive info (login/password/account):$(echo $netrc | tr '\n' ' ')"
    fi
}

srv_095() {  # Methods x2: 1)find -nouser 2)find -nogroup (container userns paths excluded)
    # user namespace / container storage may legitimately show nouser/nogroup due to UID/GID
    # remapping (permission isolation) - exclude these per criterion exception
    local prune='-path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/kubelet -o -path /var/lib/lxc -o -path /var/lib/lxd -o -path /run/containerd'
    local c1 c2
    c1=$(find / -xdev \( $prune \) -prune -o -nouser -print 2>/dev/null | wc -l)
    note SRV-095 "Method 1) find / -nouser (container userns paths excluded): ${c1}"
    c2=$(find / -xdev \( $prune \) -prune -o -nogroup -print 2>/dev/null | wc -l)
    note SRV-095 "Method 2) find / -nogroup (container userns paths excluded): ${c2}"
    if is_apply; then
        local NOOWN=/root/no_owner_files_${TS}.txt
        find / -xdev \( $prune \) -prune -o \( -nouser -o -nogroup \) -exec ls -alLd {} \; 2>/dev/null > "$NOOWN"
        chmod 600 "$NOOWN"
        [ $((c1+c2)) -eq 0 ] && pass SRV-095 "no unowned files" \
                             || fail SRV-095 "unowned files exist - review listing (${NOOWN}) then clean up"
    else
        [ $((c1+c2)) -eq 0 ] && pass SRV-095 "no unowned files" \
                             || fail SRV-095 "nouser ${c1} / nogroup ${c2} files exist"
    fi
}

srv_144() {  # Method: find /dev -type f (excluding mqueue/shm) (single)
    local dev_bad; dev_bad=$(find /dev -type f ! -path '/dev/mqueue/*' ! -path '/dev/shm/*' 2>/dev/null)
    note SRV-144 "Method) find /dev -type f (excluding mqueue/shm): $(echo "$dev_bad" | grep -c . ) found"
    [ -z "$dev_bad" ] && pass SRV-144 "no stray regular files in /dev" \
                      || fail SRV-144 "regular files in /dev: $(echo $dev_bad | tr '\n' ' ') - verify then remove manually"
}

srv_164() {  # Methods x2: 1)passwd-group cross check 2)focus on new GIDs (1000+)
    local empty_gid=""
    while IFS=: read -r gname _ gid members; do
        [ "$gid" -ge 1000 ] 2>/dev/null || continue
        [ -n "$members" ] && continue
        awk -F: -v g="$gid" '$4==g{f=1} END{exit !f}' /etc/passwd || empty_gid="$empty_gid ${gname}(${gid})"
    done < /etc/group
    note SRV-164 "Method 1) /etc/passwd vs /etc/group cross-check: system groups (GID<1000, e.g. daemon/bin) excluded to avoid false positives"
    note SRV-164 "Method 2) new GIDs (1000+) with no members and not used as any user's primary group:${empty_gid:-none}"
    [ -z "$empty_gid" ] && pass SRV-164 "no memberless new GIDs" \
                        || fail SRV-164 "memberless groups:$empty_gid - check owned files then groupdel"
}

srv_166() {  # Methods x2: 1)/tmp,/var/tmp hidden files+dirs 2)home non-standard hidden files+dirs
    # Method 1: hidden files AND directories under /tmp and /var/tmp (any depth)
    # => This doesn't check the entire / path => only the ones under /tmp and /var/tmp
    local tmplist; tmplist=$(find /tmp /var/tmp -name '.*' \( -type f -o -type d \) 2>/dev/null)
    local tmpcnt; tmpcnt=$(printf '%s' "$tmplist" | grep -c .)
    note SRV-166 "Method 1) hidden files/dirs in /tmp,/var/tmp: ${tmpcnt}"
    [ -n "$tmplist" ] && while IFS= read -r p; do
        [ -n "$p" ] && note SRV-166 "  hidden(/tmp): $(ls -ald "$p" 2>/dev/null)"
    done <<< "$tmplist"
    # Method 2: non-standard hidden files AND directories in home dirs (standard dotfiles/dirs excluded)
    local homelist=""
    for h in $HOMEDIRS; do
        homelist="${homelist}
$(find "$h" -maxdepth 1 -name '.*' \( -type f -o -type d \) \
            ! -name '.bash*' ! -name '.profile' ! -name '.viminfo' \
            ! -name '.*history' ! -name '.lesshst' \
            ! -name '.ssh' ! -name '.config' ! -name '.cache' ! -name '.local' \
            ! -name '.gnupg' ! -name '.pki' ! -name '.dbus' ! -name '.mozilla' 2>/dev/null)"
    done
    homelist=$(printf '%s\n' "$homelist" | grep -v '^$')
    local hcnt; hcnt=$(printf '%s' "$homelist" | grep -c .)
    note SRV-166 "Method 2) non-standard hidden files/dirs in home dirs: ${hcnt}"
    [ -n "$homelist" ] && while IFS= read -r p; do
        [ -n "$p" ] && note SRV-166 "  hidden(home): $(ls -ald "$p" 2>/dev/null)"
    done <<< "$homelist"
    local total=$((tmpcnt+hcnt))
    if is_apply; then
        local HIDDEN=/root/hidden_files_${TS}.txt
        { [ -n "$tmplist" ] && printf '%s\n' "$tmplist"; [ -n "$homelist" ] && printf '%s\n' "$homelist"; } > "$HIDDEN"
        chmod 600 "$HIDDEN"
        pass SRV-166 "baseline of ${total} hidden files/dirs saved (${HIDDEN}) - remove non-business items manually"
    else
        [ "$total" -eq 0 ] && pass SRV-166 "no non-standard hidden files/dirs" \
                           || fail SRV-166 "${total} non-standard hidden files/dirs (see list above) - compare with baseline then decide"
    fi
}

run_30() { srv_012; srv_025; srv_081; srv_082; srv_083; srv_084; srv_087
           srv_091; srv_092; srv_093; srv_094; srv_095; srv_096; srv_121
           srv_122; srv_144; srv_164; srv_166; }
