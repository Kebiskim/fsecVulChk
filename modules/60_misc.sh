#!/bin/bash
# modules/60_misc.sh - access control / banner / procedural / EOL (SRV-027,163,115,118,179)

srv_027() {  # Methods x3: 1)firewall status 2)3rd-party product 3)tcp-wrapper - check what applies
    local r1="not in use" r3="not configured" ok=""
    if systemctl is-active firewalld >/dev/null 2>&1; then r1="firewalld active"; ok=y
    elif systemctl is-active nftables >/dev/null 2>&1; then r1="nftables active"; ok=y
    elif command -v iptables >/dev/null 2>&1; then
        iptables -L -n 2>/dev/null | grep -vq '^Chain\|^target\|^$' && { r1="iptables rules present"; ok=y; } || r1="no iptables rules"
    else r1="not checkable (no firewall tool installed)"; fi
    note SRV-027 "Method 1) firewall status: ${r1}"
    note SRV-027 "Method 2) 3rd-party access-control product: cannot be detected by script - verify deployment manually"
    grep -Eqs '^[[:space:]]*[^#[:space:]]' /etc/hosts.allow /etc/hosts.deny && { r3="hosts.allow/deny rules present"; ok=y; }
    note SRV-027 "Method 3) tcp-wrapper (hosts.allow/deny): ${r3}"
    [ -n "$ok" ] && pass SRV-027 "access-control mechanism present" \
                 || fail SRV-027 "no access-control mechanism - verify session path then enable firewalld (not auto-applied)"
}

srv_163() {  # Methods x3: 1)/etc/issue.net 2)/etc/motd 3)sshd_config Banner
    if is_apply; then
        local BANNER='================================================================
                        [ WARNING ]
 This system is restricted to authorized users only.
 All access and activity on this system is logged and audited.
 Unauthorized access may result in prosecution under
 applicable laws.
================================================================'
        for f in /etc/issue /etc/issue.net /etc/motd; do
            bak "$f"; printf '%s\n' "$BANNER" > "$f"; chmod 644 "$f"
        done
        if [ -f "$SSHD" ]; then
            grep -Eq '^\s*Banner\s' "$SSHD" && sed -ri 's|^\s*#?\s*Banner\s.*|Banner /etc/issue.net|' "$SSHD" \
                                            || echo 'Banner /etc/issue.net' >> "$SSHD"
            sshd -t 2>/dev/null && systemctl reload sshd >/dev/null 2>&1
        fi
    fi
    # criteria: displayed via ANY of the paths = pass; version info exposed = hard fail
    local shown="" verexp="" n=1
    for f in /etc/issue.net /etc/motd; do
        if [ ! -s "$f" ]; then note SRV-163 "Method ${n}) ${f}: not set (empty)"
        elif grep -qE '\\r|\\m|\\s|\\v' "$f"; then note SRV-163 "Method ${n}) ${f}: contains OS-info escapes (version exposed)"; verexp="$verexp ${f}"
        else note SRV-163 "Method ${n}) ${f}: warning banner set, no version info"; shown=y; fi
        n=$((n+1))
    done
    if [ -f "$SSHD" ]; then
        local b; b=$(grep -E '^\s*Banner\s' "$SSHD" | grep -viE 'Banner\s+none' | tail -1)
        note SRV-163 "Method 3) sshd_config Banner: ${b:-unset (or none)}" 
        [ -n "$b" ] && shown=y
    else
        note SRV-163 "Method 3) sshd_config Banner: not checkable (sshd not installed)"
    fi
    if [ -n "$verexp" ]; then fail SRV-163 "version info exposed in banner:$verexp"
    elif [ -n "$shown" ]; then pass SRV-163 "login warning message displayed, no version exposure"
    else fail SRV-163 "no login warning message configured (issue.net/motd/sshd Banner all unset)"; fi
}

srv_115() {
    note SRV-115 "Method) log-review reports / interviews: not checkable by script (document/interview item)"
    na SRV-115 "operational-procedure item (periodic log review/reporting) - manage as a process with evidence"
}

srv_118() {
    note SRV-118 "Method 1) vendor patch info acquisition/review procedure: manual/interview item (not script-checkable)"
    if command -v rpm >/dev/null 2>&1; then
        note SRV-118 "Method 2) rpm -qa (installed patch listing): $(rpm -qa 2>/dev/null | wc -l) packages"
        note SRV-118 "Method 2) recent updates (rpm -qa --last, top 5): $(rpm -qa --last 2>/dev/null | head -5 | tr '\n' '|')"
    elif command -v dpkg >/dev/null 2>&1; then
        note SRV-118 "Method 2) dpkg -l (installed patch listing): $(dpkg -l 2>/dev/null | grep -c '^ii') packages"
        note SRV-118 "Method 2) recent updates (grep upgrade /var/log/dpkg.log, top 5): $(grep ' upgrade ' /var/log/dpkg.log 2>/dev/null | tail -5 | tr '\n' '|')"
    else
        note SRV-118 "Method 2) installed patch listing: not checkable (no rpm/dpkg)"
    fi
    na SRV-118 "operational-procedure item (patch intake & review process) - current OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)"
}

srv_179() {  # RHEL 9 target - Methods x2: 1)os-release + RHEL lifecycle 2)repo validity (de-facto support)
    . /etc/os-release 2>/dev/null
    note SRV-179 "Method 1) cat /etc/os-release: ${PRETTY_NAME:-unknown}"
    # RHEL lifecycle (this tool targets RHEL 9+): RHEL 7 and earlier past general support (RHEL7 ended 2024-06)
    local osid="${ID:-unknown}" osver="${VERSION_ID%%.*}" eol=n
    case "$osid" in
        rhel) [ "${osver:-0}" -le 7 ] && eol=y ;;
        *)    note SRV-179 "Method 1) non-RHEL distro (${osid}) - out of scope for RHEL 9 baseline, verify lifecycle manually" ;;
    esac
    note SRV-179 "Method 1) vendor lifecycle comparison: ${osid} ${VERSION_ID:-?} -> $([ $eol = y ] && echo 'standard support ended (EOL)' || echo 'supported (RHEL 9+ target)')"
    # Method 2: repo validity as a de-facto support signal (cache-only, no network on closed nets)
    local repo="not checkable (no dnf)"
    command -v dnf >/dev/null 2>&1 && repo="$(dnf repolist --enabled -C 2>/dev/null | grep -cE '^[^ ]') enabled dnf repos (cache)"
    note SRV-179 "Method 2) repo validity / update-source availability: ${repo}"
    if [ "$eol" = y ]; then
        fail SRV-179 "${PRETTY_NAME:-$osid} - vendor standard support ended. Vulnerable unless ELS/ESU is contracted with a documented post-mgmt procedure (verify Method 2 repos + CVE patch feed)"
    else
        pass SRV-179 "${PRETTY_NAME:-$osid} - vendor-supported (RHEL 9+ target; recheck lifecycle periodically)"
    fi
}

run_60() { srv_027; srv_115; srv_118; srv_163; srv_179; }
