#!/bin/bash
# modules/20_accounts.sh - accounts/authentication
# (SRV-022,026,028,069,070,073,074,075,127,131,133,142,165,177)

srv_022() {  # Method: empty password field in /etc/shadow (single) => only detects blank
    local empty; empty=$(awk -F: '($2==""){print $1}' /etc/shadow)
    note SRV-022 "Method) accounts with empty password field in /etc/shadow: ${empty:-none}"
    if [ -z "$empty" ]; then pass SRV-022 "no empty-password accounts"; return; fi
    if is_apply; then
        local f=""; for u in $empty; do passwd -l "$u" >/dev/null 2>&1 || f="$f $u"; done
        [ -z "$f" ] && pass SRV-022 "locked empty-password accounts: $(echo $empty | tr '\n' ' ')" \
                    || fail SRV-022 "failed to lock accounts:$f"
    else fail SRV-022 "empty-password accounts exist: $(echo $empty | tr '\n' ' ')"; fi
}

srv_026() {  # Methods x2: 1)Telnet - securetty pts 2)SSH - sshd_config PermitRootLogin
    # Method 1: Telnet (securetty)
    local r1 r1_bad=""
    if unit_exists telnet.socket || unit_exists telnet || ss -lnt 2>/dev/null | grep -q ':23 '; then
        if [ -f /etc/securetty ]; then
            grep -q '^pts' /etc/securetty && { r1="pts terminals allowed (vulnerable)"; r1_bad=y; } \
                                          || r1="pts not allowed (good)"
        else r1="securetty file missing (possibly vulnerable - manual review)"; r1_bad=y; fi
    else r1="not applicable (Telnet not in use)"; fi
    note SRV-026 "Method 1) Telnet: pts entries in /etc/securetty: ${r1}"
    # Method 2: SSH (sshd_config)
    if [ ! -f "$SSHD" ]; then
        note SRV-026 "Method 2) SSH: PermitRootLogin in sshd_config: not checkable (sshd_config missing)"
        na SRV-026 "neither SSH nor Telnet installed"; return
    fi
    if is_apply; then
        bak "$SSHD"
        grep -Eq '^[[:space:]]*PermitRootLogin' "$SSHD" \
            && sed -ri 's|^[[:space:]]*#?[[:space:]]*PermitRootLogin.*|PermitRootLogin no|' "$SSHD" \
            || echo 'PermitRootLogin no' >> "$SSHD"
        if [ -d /etc/ssh/sshd_config.d ]; then
            for f in /etc/ssh/sshd_config.d/*.conf; do
                [ -f "$f" ] && grep -Eq '^[[:space:]]*PermitRootLogin' "$f" && \
                    { bak "$f"; sed -ri 's|^[[:space:]]*PermitRootLogin.*|PermitRootLogin no|' "$f"; }
            done
        fi
        [ -f /etc/securetty ] && grep -q '^pts' /etc/securetty && { bak /etc/securetty; sed -i '/^pts/d' /etc/securetty; }
    fi
    local eff src="sshd -T (effective config)"
    eff=$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')
    [ -z "$eff" ] && { src="config file grep"; eff=$(grep -rhEi '^[[:space:]]*PermitRootLogin' "$SSHD" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1 | awk '{print $2}'); }
    note SRV-026 "Method 2) SSH: PermitRootLogin=${eff:-unset} (${src})"
    if is_apply; then
        if sshd -t 2>/dev/null; then
            systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1
            pass SRV-026 "PermitRootLogin no applied (sshd reloaded)"
        else
            cp -a "$BACKUP_DIR/$(echo "$SSHD" | tr / _)" "$SSHD"
            fail SRV-026 "sshd syntax check failed - reverted, manual review"
        fi
    else
        case "${eff:-yes}" in
            no|forced-commands-only|prohibit-password)
                [ -n "$r1_bad" ] && fail SRV-026 "SSH is good but Telnet securetty is vulnerable" \
                                 || pass SRV-026 "root remote login restricted";;
            *) fail SRV-026 "PermitRootLogin=${eff:-unset (default may allow)}";;
        esac
    fi
}

srv_028() {  # Method: TMOUT value in /etc/profile family (single)
    if is_apply; then
        cat > /etc/profile.d/tmout.sh <<EOF
# init_hardening: session timeout (criterion: 900s or less) [SRV-028]
TMOUT=${TMOUT_SEC}
readonly TMOUT
export TMOUT
EOF
        chmod 644 /etc/profile.d/tmout.sh
    fi
    local t; t=$(grep -rhE '^[[:space:]]*(export )?TMOUT=' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | tail -1 | grep -oE '[0-9]+')
    note SRV-028 "Method) TMOUT in /etc/profile family: ${t:-unset}"
    if [ -z "$t" ]; then fail SRV-028 "TMOUT not set"
    elif [ "$t" -le 900 ]; then pass SRV-028 "TMOUT=${t} (criterion: 900 or less)"
    else fail SRV-028 "TMOUT=${t} - exceeds 900s criterion"; fi
}

srv_069() {  # Methods x3 per manual: 1)password length 2)complexity(credits) 3)chage policy
             # Manual allows either source for methods 1-2 (RPM-based systems):
             #   /etc/security/pwquality.conf  OR  /etc/pam.d/system-auth (pam_pwquality line)
             # Both are read; the pam inline option wins at runtime, so it takes precedence.
    local PWQ=/etc/security/pwquality.conf PAMSA=/etc/pam.d/system-auth

    pq_get() {  # pq_get <file> <key> - reads "key = N" (conf) and inline "key=N" (pam line); ignores comments
        [ -f "$1" ] || return 1
        sed -rn "s/^[^#]*\\b$2[[:space:]]*=[[:space:]]*(-?[0-9]+).*/\\1/p" "$1" 2>/dev/null | tail -1
    }

    if is_apply; then
        if [ -f $PWQ ] || rpm -q libpwquality >/dev/null 2>&1; then
            set_kv $PWQ minlen "$PASS_MIN_LEN" eq; set_kv $PWQ minclass "$PASS_MIN_CLASS" eq
            set_kv $PWQ lcredit -1 eq; set_kv $PWQ ucredit -1 eq
            set_kv $PWQ dcredit -1 eq; set_kv $PWQ ocredit -1 eq
        fi
        set_kv /etc/login.defs PASS_MAX_DAYS "$PASS_MAX_DAYS" space
        set_kv /etc/login.defs PASS_MIN_DAYS 1 space
        set_kv /etc/login.defs PASS_MIN_LEN "$PASS_MIN_LEN" space
        # NOTE: the PAM stack (system-auth) is never auto-edited - a bad edit breaks all authentication
    fi

    # Method 1: password length - check both sources
    local ml_conf ml_pam ml
    ml_conf=$(pq_get $PWQ minlen); ml_pam=$(pq_get $PAMSA minlen)
    ml=${ml_pam:-$ml_conf}
    note SRV-069 "Method 1) password length - ${PWQ}: minlen=${ml_conf:-unset} / ${PAMSA}: minlen=${ml_pam:-unset} -> effective ${ml:-unset}"

    # Method 2: complexity - lcredit/ucredit/dcredit/ocredit values (per manual)
    local c v_conf v_pam eff cred_bad="" cred_show=""
    for c in lcredit ucredit dcredit ocredit; do
        v_conf=$(pq_get $PWQ "$c"); v_pam=$(pq_get $PAMSA "$c")
        eff=${v_pam:-$v_conf}
        cred_show="${cred_show} ${c}=${eff:-unset}"
        { [ -n "$eff" ] && [ "$eff" -le -1 ]; } || cred_bad="$cred_bad $c"
    done
    local mc; mc=$(pq_get $PWQ minclass)
    note SRV-069 "Method 2) complexity -${cred_show} (minclass=${mc:-unset}, informational)"

    # Method 3: chage -l per account - maximum AND minimum number of days (per manual)
    local md mind bad_max="" bad_min=""
    md=$(get_ldef PASS_MAX_DAYS); mind=$(get_ldef PASS_MIN_DAYS)
    if command -v chage >/dev/null 2>&1; then
        local u out mx mn
        for u in $(awk -F: '$2!~/^[*!]/ && $2!="" {print $1}' /etc/shadow); do
            out=$(chage -l "$u" 2>/dev/null) || continue
            mx=$(echo "$out" | awk -F: '/Maximum/{gsub(/^[ \t]+/,"",$2);print $2}')
            mn=$(echo "$out" | awk -F: '/Minimum/{gsub(/^[ \t]+/,"",$2);print $2}')
            case "$mx" in ''|*[!0-9]*) :;; *) [ "$mx" -gt "$PASS_MAX_DAYS" ] && bad_max="$bad_max ${u}(max=${mx})";; esac
            case "$mn" in ''|*[!0-9]*) :;; *) [ "$mn" -lt 1 ] && bad_min="$bad_min ${u}(min=${mn})";; esac
        done
        note SRV-069 "Method 3) chage -l per account: login.defs MAX=${md:-unset}/MIN=${mind:-unset}, over-max:${bad_max:-none}, under-min:${bad_min:-none}"
    else
        note SRV-069 "Method 3) chage -l: not checkable (chage command not installed) - login.defs MAX=${md:-unset}/MIN=${mind:-unset}"
    fi

    local bad=""
    { [ -n "$ml" ] && [ "$ml" -ge "$PASS_MIN_LEN" ]; } || bad="$bad length"
    [ -z "$cred_bad" ] || bad="$bad complexity(${cred_bad# })"
    { [ -n "$md" ] && [ "$md" -le "$PASS_MAX_DAYS" ] && [ -z "$bad_max" ] && [ -z "$bad_min" ]; } || bad="$bad change-policy"
    if [ -z "$bad" ]; then pass SRV-069 "password policy meets criteria (methods 1-3)"
    elif is_apply && [ ! -f $PWQ ]; then
        fail SRV-069 "libpwquality not installed - install from repo and rerun (login.defs applied)"
    else
        fail SRV-069 "below criteria:${bad}${bad_max:+ / fix with chage -M ${PASS_MAX_DAYS}:${bad_max}}${bad_min:+ / fix with chage -m 1:${bad_min}}"
    fi
}

srv_070() {  # Method 1 (manual bullet 1): is the encrypted_password field in /etc/shadow
             #                               actually encrypted ($id$salt$hashed)
             # Method 2 (manual bullet 2): ENCRYPT_METHOD in /etc/login.defs
             #   The manual's "OR" alternative for bullet 2 is the shadow field itself,
             #   which method 1 already covers - so only login.defs is read here.
             # $id$ table: $1$=MD5(weak) / $2a$,$2y$,$2b$=Blowfish / $5$=SHA-256 / $6$=SHA-512
    is_apply && set_kv /etc/login.defs ENCRYPT_METHOD SHA512 space

    # Method 1: only problem accounts are listed; healthy ones are counted
    local u h n_ok=0 bad_weak="" bad_plain=""
    while IFS=: read -r u h _; do
        case "$h" in ''|'!'|'!!'|'*'|'!*'|'*LK*') continue ;; esac   # empty/locked: see SRV-022
        h=${h#!}; h=${h#!}                                          # keep the hash behind lock markers
        case "$h" in
            '$1$'*)                                                  bad_weak="$bad_weak ${u}(MD5)" ;;
            '$2a$'*|'$2y$'*|'$2b$'*|'$5$'*|'$6$'*|'$y$'*|'$7$'*)     n_ok=$((n_ok+1)) ;;
            *)                                                       bad_plain="$bad_plain ${u}" ;;
        esac
    done < /etc/shadow
    note SRV-070 "Method 1) /etc/shadow encrypted_password: ${n_ok} account(s) properly hashed / MD5:${bad_weak:-none} / not-encrypted:${bad_plain:-none}"

    # Method 2: ENCRYPT_METHOD in login.defs (shadow-utils; present on any standard RHEL install)
    local em=""
    if [ -f /etc/login.defs ]; then
        em=$(get_ldef ENCRYPT_METHOD)
        note SRV-070 "Method 2) ENCRYPT_METHOD in /etc/login.defs: ${em:-unset (distro default applies)}"
    else
        note SRV-070 "Method 2) ENCRYPT_METHOD: not checkable (/etc/login.defs missing - shadow-utils not installed)"
    fi

    if [ -n "$bad_plain" ]; then
        fail SRV-070 "password not encrypted (no \$id\$ prefix):$bad_plain - reset password immediately"
    elif [ -n "$bad_weak" ]; then
        fail SRV-070 "MD5(\$1\$) hashed accounts:$bad_weak - set ENCRYPT_METHOD=SHA512 and reset those passwords"
    elif [ -n "$em" ] && ! echo "$em" | grep -qiE '^(sha512|yescrypt)$'; then
        fail SRV-070 "ENCRYPT_METHOD=${em} - change to SHA512 (new passwords would use a weaker method)"
    else
        pass SRV-070 "stored passwords encrypted with an acceptable algorithm; ENCRYPT_METHOD=${em:-distro default}"
    fi
}

srv_073() {  # Method: root line in /etc/group (single)
    local extra; extra=$(awk -F: '$1=="root"{print $4}' /etc/group | tr ',' '\n' | grep -v '^root$' | grep -v '^$')
    note SRV-073 "Method) members of root group in /etc/group: root${extra:+,$(echo $extra | tr '\n' ',')}"
    [ -z "$extra" ] && pass SRV-073 "no unnecessary accounts in root group" \
                    || fail SRV-073 "extra accounts in root group: $(echo $extra | tr '\n' ' ') - review/remove manually"
}

srv_074() {  # Methods x2 per login-capable account: 1)login history 2)password change date
             # Criterion: PASS  = logged in at least once per quarter AND password is being changed
             #            VULN  = no login within a quarter OR password never/long unchanged
             #            (business need must be confirmed before locking - see message)
             # Operational review item: the script never locks or deletes accounts.
    local QUARTER_DAYS=90
    local shells; shells=$(awk -F: '$7 !~ /nologin|false|\/sync$|shutdown|halt/ {print $1}' /etc/passwd)

    # Method 1: login history - "lastlog -t N" lists only logins newer than N days
    local stale="" u
    if command -v lastlog >/dev/null 2>&1; then
        for u in $shells; do
            LC_ALL=C lastlog -u "$u" -t "$QUARTER_DAYS" 2>/dev/null | tail -n +2 | grep -q . && continue
            LC_ALL=C lastlog -u "$u" 2>/dev/null | tail -1 | grep -q 'Never logged in' \
                && stale="$stale ${u}(never)" || stale="$stale ${u}(>${QUARTER_DAYS}d)"
        done
        note SRV-074 "Method 1) login history (lastlog -t ${QUARTER_DAYS}): accounts without a login in the last quarter:${stale:-none}"
    else
        note SRV-074 "Method 1) login history: not checkable (lastlog command not installed)"
    fi

    # Method 2: password change date - never, or older than one quarter
    local nochg="" d age now; now=$(date +%s)
    if command -v chage >/dev/null 2>&1; then
        for u in $shells; do
            d=$(LC_ALL=C chage -l "$u" 2>/dev/null | awk -F': ' '/Last password change/{gsub(/^[ \t]+/,"",$2); print $2}')
            case "$d" in
                ''|*ever) [ -n "$d" ] && nochg="$nochg ${u}(never)" ;;
                *) age=$(date -d "$d" +%s 2>/dev/null) || continue
                   age=$(( (now - age) / 86400 ))
                   [ "$age" -gt "$QUARTER_DAYS" ] && nochg="$nochg ${u}(${age}d ago)" ;;
            esac
        done
        note SRV-074 "Method 2) password change date (chage -l): accounts not changed within the last quarter:${nochg:-none}"
    else
        note SRV-074 "Method 2) password change date: not checkable (chage command not installed)"
    fi

    if is_apply; then
        # At initial build no account has a login or change history yet, which is expected -
        # record the baseline and hand the item to the periodic review process.
        na SRV-074 "operational review item - no auto-remediation. Baseline login-capable accounts: $(echo $shells | tr '\n' ' ')${stale:+ / no login yet (expected at build time):$stale}${nochg:+ / password not changed yet:$nochg} - review quarterly"
    elif [ -z "$stale" ] && [ -z "$nochg" ]; then
        pass SRV-074 "every login-capable account logged in and changed its password within the last quarter"
    else
        fail SRV-074 "no login in the last quarter:${stale:-none} / password not changed:${nochg:-none} - confirm business need, then lock or delete manually"
    fi
}

# ☆ChkLater
srv_075() {  # Methods x2: 1)accounts able to log in without a password 2)password crack attempt
             # Criterion: PASS = every account meets the complexity rule
             #            VULN = password unset, or an account fails the complexity rule
             #   complexity: 2 char-types -> 10+ chars, 3 char-types -> 8+ chars
             #               (password containing the account name or the org name = VULN)
             # Stored passwords are hashes, so existing passwords cannot be inspected directly;
             # method 2 (cracking) is a manual task. The script verifies the enforced policy
             # (pwquality) that makes new/changed passwords satisfy the rule.
    local MINLEN_3CLASS=8 MINLEN_2CLASS=10
    local PWQ=/etc/security/pwquality.conf PAMSA=/etc/pam.d/system-auth PAMPA=/etc/pam.d/password-auth

    pq75_get() {  # <file> <key> - reads "key = N" (conf) and inline "key=N" (pam line)
        [ -f "$1" ] || return 1
        sed -rn "s/^[^#]*\b$2[[:space:]]*=[[:space:]]*(-?[0-9]+).*/\1/p" "$1" 2>/dev/null | tail -1
    }
    pq75_eff() { local a b; a=$(pq75_get $PWQ "$1"); b=$(pq75_get $PAMSA "$1"); echo "${b:-$a}"; }

    # (apply) make the policy actually bite: without enforce_for_root, a root-set password
    # only triggers a "BAD PASSWORD" warning and is still accepted
    if is_apply && [ -f $PWQ ]; then
        grep -qsE '^[^#]*\benforce_for_root\b' $PWQ || { bak $PWQ; echo 'enforce_for_root' >> $PWQ; }
    fi

    # Method 1: accounts with an empty password field
    local empty; empty=$(awk -F: '{gsub(/[ \t]/,"",$2)} $2=="" {print $1}' /etc/shadow)
    note SRV-075 "Method 1) accounts able to log in without a password: ${empty:-none}"

    # Method 2: crack attempt is manual - verify the enforced complexity policy instead
    local ml mc c v cred=0
    ml=$(pq75_eff minlen); mc=$(pq75_eff minclass)
    for c in lcredit ucredit dcredit ocredit; do
        v=$(pq75_eff "$c"); { [ -n "$v" ] && [ "$v" -le -1 ]; } && cred=$((cred+1))
    done
    local classes=${mc:-0}; [ "$cred" -gt "$classes" ] && classes=$cred
    local need=0
    case "$classes" in
        0|1) need=0 ;;                            # fewer than 2 classes enforced - rule not covered
        2)   need=$MINLEN_2CLASS ;;
        *)   need=$MINLEN_3CLASS ;;
    esac
    # is pam_pwquality actually in the password stack? if not, pwquality.conf is inert
    local in_stack=no
    grep -qsE '^[^#]*pam_pwquality\.so' $PAMSA $PAMPA && in_stack=yes
    # without enforce_for_root, passwords set by root bypass the rule
    local efr=no
    grep -qsE '^[^#]*\benforce_for_root\b' $PWQ $PAMSA $PAMPA && efr=yes
    local uc; uc=$(pq75_eff usercheck)
    local bw; bw=$(sed -rn 's/^[^#]*\bbadwords[[:space:]]*=[[:space:]]*(.*)/\1/p' $PWQ 2>/dev/null | tail -1)
    note SRV-075 "Method 2) password crack attempt: manual item (script runs no cracker) - enforced policy checked instead: classes=${classes} (minclass=${mc:-unset}, negative credits=${cred}), minlen=${ml:-unset}, required minlen for ${classes} classes=${need}"
    note SRV-075 "Method 2) enforcement: pam_pwquality in PAM stack=${in_stack}, enforce_for_root=${efr} (if no, root-set passwords are only warned about, not rejected)"
    note SRV-075 "Method 2) account/org name in password: usercheck=${uc:-1 (pwquality default: enabled)}, badwords=${bw:-unset (org name not registered)}"

    local bad=""
    [ "$in_stack" = no ] && bad="$bad pam_pwquality-not-in-PAM-stack(policy inert)"
    [ "$efr" = no ] && bad="$bad enforce_for_root-missing(root can set weak passwords)"
    if [ "$need" -eq 0 ]; then bad="$bad char-classes(${classes}<2)"
    elif [ -z "$ml" ] || [ "$ml" -lt "$need" ]; then bad="$bad minlen(${ml:-unset}<${need})"; fi
    [ "${uc:-1}" = 0 ] && bad="$bad usercheck-disabled(account name allowed)"

    if [ -n "$empty" ]; then
        fail SRV-075 "passwordless accounts exist: $(echo $empty | tr '\n' ' ')"
    elif [ -n "$bad" ]; then
        fail SRV-075 "complexity policy below criterion:${bad} (2 classes need ${MINLEN_2CLASS}+, 3 classes need ${MINLEN_3CLASS}+)"
    else
        local bwmsg
        [ -n "$bw" ] && bwmsg=", org badwords set (${bw})" \
                     || bwmsg=" - org name not registered in badwords; existing passwords still need a manual crack test or a forced reset"
        pass SRV-075 "no passwordless accounts; policy enforced for all users incl. root, ${classes} classes with minlen=${ml}${bwmsg}"
    fi
}

srv_127() {  # Method: lockout threshold in the files in use (RHEL 9)
             #   /etc/security/faillock.conf  - primary location since RHEL 8 (deny=, unlock_time=)
             #   /etc/pam.d/system-auth, /etc/pam.d/password-auth - pam_faillock.so lines:
             #     auth required pam_faillock.so preauth  / auth [default=die] ... authfail
             #     account required pam_faillock.so
             # pam_tally2/pam_tally (RHEL 7 and earlier) and common-auth (Debian) are not checked.
             # Only active (non-comment) lines count - a commented example is not a setting.
    local FLC=/etc/security/faillock.conf
    local PAMS="/etc/pam.d/system-auth /etc/pam.d/password-auth"

    if is_apply && [ -f $FLC ]; then
        set_kv $FLC deny "$FAIL_DENY" eq
        set_kv $FLC unlock_time "$FAIL_UNLOCK" eq
        # The PAM stack is wired up through authselect only - system-auth is never edited
        # directly, because a broken PAM file locks every login out of the machine.
        if command -v authselect >/dev/null 2>&1; then
            local as_cur as_out as_rc
            as_cur=$(authselect current 2>&1 | head -1)
            as_out=$(authselect enable-feature with-faillock 2>&1); as_rc=$?
            if [ $as_rc -eq 0 ]; then
                authselect apply-changes >/dev/null 2>&1
                note SRV-127 "Apply) authselect enable-feature with-faillock: applied (profile: ${as_cur})"
            else
                note SRV-127 "Apply) authselect enable-feature with-faillock FAILED (rc=${as_rc}): ${as_out} | current: ${as_cur}"
            fi
        else
            note SRV-127 "Apply) authselect not installed - PAM stack left untouched; add pam_faillock lines manually"
        fi
    fi

    # faillock.conf - active values only
    local fl_deny="" fl_unlock=""
    if [ -f $FLC ]; then
        fl_deny=$(sed -rn 's/^[[:space:]]*deny[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' $FLC 2>/dev/null | tail -1)
        fl_unlock=$(sed -rn 's/^[[:space:]]*unlock_time[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' $FLC 2>/dev/null | tail -1)
        note SRV-127 "Method 1) ${FLC}: deny=${fl_deny:-unset} unlock_time=${fl_unlock:-unset}"
    else
        note SRV-127 "Method 1) ${FLC}: file missing"
    fi

    # PAM stack - pam_faillock.so lines
    local f auth_ok="" acct_ok="" in_deny="" in_unlock="" used_file=""
    for f in $PAMS; do
        if [ ! -f "$f" ]; then note SRV-127 "Method 2) ${f}: file missing"; continue; fi
        if ! grep -qE '^[[:space:]]*[^#].*pam_faillock\.so' "$f" 2>/dev/null; then
            note SRV-127 "Method 2) ${f}: pam_faillock.so not in active lines"; continue
        fi
        local a_line=no c_line=no d="" u=""
        grep -qE '^[[:space:]]*auth[[:space:]].*pam_faillock\.so' "$f" 2>/dev/null && a_line=yes
        grep -qE '^[[:space:]]*account[[:space:]].*pam_faillock\.so' "$f" 2>/dev/null && c_line=yes
        d=$(sed -rn 's/^[[:space:]]*[^#].*pam_faillock\.so.*[[:space:]]deny=([0-9]+).*/\1/p' "$f" 2>/dev/null | tail -1)
        u=$(sed -rn 's/^[[:space:]]*[^#].*pam_faillock\.so.*[[:space:]]unlock_time=([0-9]+).*/\1/p' "$f" 2>/dev/null | tail -1)
        note SRV-127 "Method 2) ${f}: auth line=${a_line}, account line=${c_line}, inline deny=${d:-unset} unlock_time=${u:-unset}"
        [ -z "$used_file" ] && used_file=$f
        [ "$a_line" = yes ] && auth_ok=yes
        [ "$c_line" = yes ] && acct_ok=yes
        [ -z "$in_deny" ] && in_deny=$d
        [ -z "$in_unlock" ] && in_unlock=$u
    done

    # effective threshold: inline option first, then faillock.conf
    local eff_deny=${in_deny:-$fl_deny} eff_unlock=${in_unlock:-$fl_unlock}

    if [ -z "$used_file" ]; then
        fail SRV-127 "pam_faillock.so not in any active PAM line - lockout not enforced${fl_deny:+ (faillock.conf deny=${fl_deny} is inert without the PAM module)}"
    elif [ "$auth_ok" != yes ]; then
        fail SRV-127 "pam_faillock.so present in ${used_file} but no auth-phase line - failures not counted"
    elif [ -z "$eff_deny" ]; then
        fail SRV-127 "pam_faillock.so in use but no deny threshold (neither inline nor in ${FLC})"
    elif [ "$acct_ok" != yes ]; then
        fail SRV-127 "deny=${eff_deny} set, but the 'account required pam_faillock.so' line is missing"
    else
        pass SRV-127 "pam_faillock.so in use (${used_file}): deny=${eff_deny}, unlock_time=${eff_unlock:-unset}, auth and account lines present"
    fi
}

srv_131() {  # Method: /etc/pam.d/su configuration
             # Criterion: PASS = "auth required pam_wheel.so use_uid" line exists (active)
             #            VULN = the line is missing OR commented out
    local PAMSU=/etc/pam.d/su
    local WHEEL_RE='^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so([[:space:]]|$).*use_uid'

    if [ ! -f $PAMSU ]; then
        note SRV-131 "Method) ${PAMSU}: file missing"
        fail SRV-131 "${PAMSU} not found - cannot restrict su"; return
    fi

    if grep -Eq "$WHEEL_RE" $PAMSU; then
        note SRV-131 "Method) ${PAMSU}: 'auth required pam_wheel.so use_uid' active"
        pass SRV-131 "su restricted to the '${SU_GROUP}' group via pam_wheel.so use_uid"; return
    fi

    # not active - report why (missing / no use_uid / commented out)
    local why="no pam_wheel.so line"
    grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' $PAMSU \
        && why="pam_wheel.so active but WITHOUT use_uid (criterion requires use_uid)"
    grep -Eq '^[[:space:]]*#.*pam_wheel\.so' $PAMSU && why="pam_wheel.so line is commented out"
    note SRV-131 "Method) ${PAMSU}: ${why}"

    if is_apply; then
        bak $PAMSU
        local line="auth        required      pam_wheel.so use_uid"
        [ "$SU_GROUP" != wheel ] && line="${line} group=${SU_GROUP}"
        if grep -Eq '^[[:space:]]*#.*auth.*required.*pam_wheel\.so.*use_uid' $PAMSU; then
            sed -ri 's|^[[:space:]]*#[[:space:]]*(auth[[:space:]]+required[[:space:]]+pam_wheel\.so[[:space:]]+use_uid.*)|\1|' $PAMSU
        elif grep -Eq '^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so' $PAMSU; then
            sed -ri "\|^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so|a ${line}" $PAMSU
        else
            sed -i "1i ${line}" $PAMSU        # no anchor line - put it first so it still takes effect
        fi
        # verify the edit landed instead of reporting success blindly
        grep -Eq "$WHEEL_RE" $PAMSU \
            && pass SRV-131 "applied '${line}' (NOTE: su is now blocked outside the '${SU_GROUP}' group)" \
            || fail SRV-131 "failed to insert the pam_wheel line into ${PAMSU} - add it manually (backup: ${BACKUP_DIR})"
    else
        fail SRV-131 "${why} - add 'auth required pam_wheel.so use_uid' to ${PAMSU}"
    fi
}

srv_133() {  # Method: existence of cron.allow / cron.deny and whether accounts are listed inside
             # Criterion: PASS = accounts are listed in cron.allow OR in cron.deny
             #                   / neither file exists (only root can use cron)
             #            VULN = cron.allow missing AND cron.deny lists no account
    local A=/etc/cron.allow D=/etc/cron.deny

    if is_apply; then
        bak $A
        [ -f $A ] || echo root > $A
        grep -q '^root$' $A || echo root >> $A
        chown root:root $A && chmod 640 $A
    fi

    # an "account" = a non-empty, non-comment line
    acct_list() { [ -f "$1" ] && grep -E '^[[:space:]]*[^#[:space:]]' "$1" 2>/dev/null | tr '\n' ' '; }
    local a_list d_list
    a_list=$(acct_list $A); d_list=$(acct_list $D)
    note SRV-133 "Method) ${A}: $([ -f $A ] && echo "exists - accounts: ${a_list:-none}" || echo 'file missing')"
    note SRV-133 "Method) ${D}: $([ -f $D ] && echo "exists - accounts: ${d_list:-none}" || echo 'file missing')"

    if [ -n "$a_list" ] || [ -n "$d_list" ]; then
        pass SRV-133 "cron users restricted${a_list:+ - cron.allow: ${a_list}}${d_list:+ - cron.deny: ${d_list}}"
    elif [ ! -f $A ] && [ ! -f $D ]; then
        pass SRV-133 "neither cron.allow nor cron.deny exists - only root can use cron"
    elif [ -f $A ]; then
        pass SRV-133 "cron.allow exists but lists no account - nobody except root can use cron"
    else
        fail SRV-133 "cron.allow missing and cron.deny lists no account - every user can use cron"
    fi
}

srv_142() {  # Method: duplicate UID in /etc/passwd (single)
    local dup; dup=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    note SRV-142 "Method) duplicate UIDs in /etc/passwd: ${dup:-none}"
    [ -z "$dup" ] && pass SRV-142 "no duplicate UIDs" \
                  || fail SRV-142 "duplicate UIDs: $(echo $dup | tr '\n' ' ') - fix manually with usermod"
}

srv_165() {  # Method: shells of daemon accounts in /etc/passwd (single)
    local bad="" fixed="" NOSH=/sbin/nologin; [ -x $NOSH ] || NOSH=/usr/sbin/nologin
    for u in daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher ftp lp mail news uucp; do
        getent passwd "$u" >/dev/null || continue
        local cur; cur=$(getent passwd "$u" | awk -F: '{print $7}')
        case "$cur" in */nologin|*/false) continue;; esac
        if is_apply; then usermod -s $NOSH "$u" 2>/dev/null && fixed="$fixed $u" || bad="$bad $u"
        else bad="$bad $u"; fi
    done
    note SRV-165 "Method) daemon account shells in /etc/passwd: with shell:${bad:-${fixed:- none}}"
    if is_apply; then
        [ -n "$fixed" ] && pass SRV-165 "daemon account shells changed to nologin:$fixed" || \
        { [ -z "$bad" ] && pass SRV-165 "no daemon accounts with a shell" || fail SRV-165 "change failed:$bad"; }
    else
        [ -z "$bad" ] && pass SRV-165 "no daemon accounts with a shell" || fail SRV-165 "daemon accounts with a shell:$bad"
    fi
}

srv_177() {  # Methods x2: 1)which sudo + sudoers check 2)sudoers.d listing
    if ! command -v sudo >/dev/null 2>&1; then
        note SRV-177 "Method 1) which sudo: not checkable (sudo not installed)"
        na SRV-177 "sudo not installed"; return
    fi
    is_apply && { chown root:root /etc/sudoers; chmod 440 /etc/sudoers; }
    local r1="perm $(stat -c '%a(%U)' /etc/sudoers 2>/dev/null)"
    visudo -c >/dev/null 2>&1 && r1="$r1, syntax OK" || r1="$r1, syntax ERROR"
    note SRV-177 "Method 1) /etc/sudoers: ${r1}"
    local extra; extra=$(ls /etc/sudoers.d/ 2>/dev/null | grep -v '^README$')
    note SRV-177 "Method 2) /etc/sudoers.d/ listing: ${extra:-no extra files}"

    # over-permissive grants: an active rule that grants ALL commands to a principal
    # other than the expected admin ones (root / %wheel / %sudo / %admin).
    # awk reads the real first token as the principal (no line-number prefix), so
    # standard admin principals are excluded correctly. *_Alias definitions and
    # Defaults lines are not grants and are skipped.
    # sudoers.d basenames treated as known-good and skipped (e.g. cloud-init/WSL defaults).
    # space-separated; add more as needed.
    local SUDO_EXCEPT="90-cloud-init-users"
    local SUDO_FILES; SUDO_FILES="/etc/sudoers $(ls /etc/sudoers.d/* 2>/dev/null)"
    scan_loose() {  # prints "<file>:<lineno>:<content>" per offending rule
        local f b
        for f in $SUDO_FILES; do
            [ -f "$f" ] || continue
            b=$(basename "$f")
            case " $SUDO_EXCEPT " in *" $b "*) continue;; esac
            awk -v F="$f" '
                /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
                {
                    who=$1; last=$NF
                    if (index($0,"=")>0 && (last=="ALL" || last ~ /:ALL$/)) {
                        if (who!="root" && who!="%wheel" && who!="%sudo" && who!="%admin" \
                            && who !~ /_Alias$/ && who !~ /^Defaults/)
                            printf "%s:%d:%s\n", F, NR, $0
                    }
                }
            ' "$f"
        done
    }
    local loose; loose=$(scan_loose)
    local skipped="" b; for b in $SUDO_EXCEPT; do [ -f "/etc/sudoers.d/$b" ] && skipped="$skipped $b"; done
    note SRV-177 "Method 2) over-permissive sudo grants: ${loose:-none}${skipped:+ (excepted:$skipped)}"

    # (apply only) comment out offending grants: backup -> comment -> visudo validate -> revert on error
    local fix_done="" fix_fail=""
    if is_apply && [ -n "$loose" ]; then
        local files_touched f nums n
        files_touched=$(echo "$loose" | awk -F: '{print $1}' | sort -u)
        for f in $files_touched; do
            bak "$f"
            nums=$(echo "$loose" | awk -F: -v ff="$f" '$1==ff{print $2}' | sort -rn)
            for n in $nums; do
                sed -i "${n}s|^|# init_hardening blocked (over-permissive sudo): |" "$f"
            done
            if visudo -cf "$f" >/dev/null 2>&1; then fix_done="$fix_done $f"
            else cp -a "$BACKUP_DIR/$(echo "$f" | tr / _)" "$f"; fix_fail="$fix_fail $f"; fi
        done
        loose=$(scan_loose)   # recompute: successfully commented lines drop off; reverted files remain
        note SRV-177 "Apply) commented over-permissive grants in:${fix_done:-none}${fix_fail:+ / reverted(validation failed):$fix_fail}"
    fi

    if ! visudo -c >/dev/null 2>&1; then fail SRV-177 "visudo syntax check failed - manual review"
    elif ! perm_le /etc/sudoers 440 || ! owner_is /etc/sudoers root; then
        fail SRV-177 "sudoers below criterion (440, root)"
    elif [ -n "$loose" ]; then
        fail SRV-177 "over-permissive sudo grants: $(echo $loose | tr '\n' ' ')${fix_fail:+ (auto-fix reverted:$fix_fail)} - restrict to specific users/groups"
    elif [ -n "$extra" ]; then
        pass SRV-177 "sudoers 440(root)${fix_done:+, over-permissive grants commented out:$fix_done}. review sudoers.d contents manually ($(echo $extra | tr '\n' ' '))"
    else pass SRV-177 "sudoers 440(root), no extra sudoers.d files"; fi
}

run_20() { srv_022; srv_026; srv_028; srv_069; srv_070; srv_073; srv_074; srv_075
           srv_127; srv_131; srv_133; srv_142; srv_165; srv_177; }
