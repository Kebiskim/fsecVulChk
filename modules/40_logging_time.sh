#!/bin/bash
# modules/40_logging_time.sh - logging/time (SRV-108,109,112,175)

srv_108() {  # Method: /var/log file permissions (single; exceptions wtmp 664/btmp 660/lastlog 664)
    if is_apply; then
        find /var/log -maxdepth 2 -type f \
            ! -name wtmp ! -name btmp ! -name lastlog \
            -exec chmod o-w,g-w {} \; 2>/dev/null
        [ -f /var/log/wtmp ]    && chmod 664 /var/log/wtmp
        [ -f /var/log/btmp ]    && chmod 660 /var/log/btmp
        [ -f /var/log/lastlog ] && chmod 664 /var/log/lastlog
    fi
    local list bad
    list=$(find /var/log -maxdepth 2 -type f \
        ! -name wtmp ! -name btmp ! -name lastlog \
        \( -perm -g+w -o -perm -o+w \) 2>/dev/null)
    bad=$(echo "$list" | grep -c .)
    note SRV-108 "Method) /var/log file permissions: ${bad} writable by non-owner (exceptions: wtmp 664, btmp 660, lastlog 664)"
    if ! is_apply; then
        echo "$list" | while IFS= read -r f; do [ -n "$f" ] && note SRV-108 "  non-owner writable: $(ls -alL "$f" 2>/dev/null)"; done
    fi
    if [ "$bad" -eq 0 ]; then pass SRV-108 "/var/log file permissions meet criteria"
    else fail SRV-108 "${bad} log files writable by non-owner"; fi
}

srv_109() {  # Method: auth/authpriv in /etc/syslog.conf or /etc/rsyslog.conf
    local conf="" r
    for f in /etc/rsyslog.conf /etc/syslog.conf; do [ -f "$f" ] && conf=$f && break; done
    if [ -z "$conf" ]; then
        note SRV-109 "Method) syslog.conf/rsyslog.conf: neither file exists (rsyslog not installed)"
        fail SRV-109 "syslog daemon not installed - install rsyslog from repo"; return
    fi
    # match an active auth/authpriv selector, but ignore ".none" (which disables logging)
    if grep -Ehs '^[^#]*auth(priv)?\.' "$conf" /etc/rsyslog.d/*.conf 2>/dev/null \
         | sed -E 's/auth(priv)?\.none//g' | grep -qE 'auth(priv)?\.[a-z*]'; then
        r="auth/authpriv enabled"
    else r="auth/authpriv missing"; fi
    note SRV-109 "Method) log policy in ${conf}(+rsyslog.d): ${r}"
    if [ "$r" = "auth/authpriv enabled" ]; then pass SRV-109 "syslog auth/authpriv logging enabled"
    elif is_apply; then
        bak "$conf"; echo 'authpriv.*    /var/log/secure' >> "$conf"
        systemctl restart rsyslog >/dev/null 2>&1
        pass SRV-109 "authpriv.* added and rsyslog restarted"
    else fail SRV-109 "auth/authpriv logging not configured"; fi
}

srv_112() {  # Method: cron entry in syslog.conf/rsyslog.conf
    local conf=""
    for f in /etc/rsyslog.conf /etc/syslog.conf; do [ -f "$f" ] && conf=$f && break; done
    if [ -z "$conf" ]; then
        note SRV-112 "Method) cron entry in syslog config: config file missing"
        fail SRV-112 "syslog daemon not installed - remediate SRV-109 first"; return
    fi
    local r; grep -Eqs '^[^#]*cron\.' "$conf" /etc/rsyslog.d/*.conf 2>/dev/null && r="cron entry present" || r="cron entry missing"
    note SRV-112 "Method) cron entry in ${conf}(+rsyslog.d): ${r}"
    if [ "$r" = "cron entry present" ]; then pass SRV-112 "cron logging enabled"
    elif is_apply; then
        bak "$conf"; echo 'cron.*    /var/log/cron' >> "$conf"
        systemctl restart rsyslog >/dev/null 2>&1
        pass SRV-112 "cron.* added and rsyslog restarted"
    else fail SRV-112 "cron logging not configured"; fi
}

srv_175() {  # Methods x3: 1)ntpq -pn 2)chronyc tracking 3)date
    # apply: configure first
    if is_apply; then
        if [ -z "$NTP_SERVER" ]; then
            note SRV-175 "Apply) NTP_SERVER variable empty - skipping config change, check only"
        elif command -v chronyc >/dev/null 2>&1; then
            bak /etc/chrony.conf
            sed -ri 's/^(server|pool) /#&/' /etc/chrony.conf
            echo "server ${NTP_SERVER} iburst" >> /etc/chrony.conf
            systemctl enable --now chronyd >/dev/null 2>&1; systemctl restart chronyd >/dev/null 2>&1; sleep 2
        elif command -v ntpq >/dev/null 2>&1; then
            bak /etc/ntp.conf
            sed -ri 's|^server |#&|' /etc/ntp.conf
            echo "server ${NTP_SERVER} iburst" >> /etc/ntp.conf
            systemctl enable --now ntpd >/dev/null 2>&1
        fi
    fi
    # run and record all three methods
    local r1 r2 sync=n
    if command -v ntpq >/dev/null 2>&1; then
        ntpq -pn 2>/dev/null | grep -q '^\*' && { r1="synced peer present"; sync=y; } || r1="no synced peer"
    else r1="not checkable (ntpq command not installed)"; fi
    note SRV-175 "Method 1) ntpq -pn: ${r1}"
    if command -v chronyc >/dev/null 2>&1; then
        if chronyc tracking 2>/dev/null | grep -q 'Reference ID'; then r2="tracking info present"; sync=y
        else r2="chronyd not running or no response"; fi
    else r2="not checkable (chronyc command not installed)"; fi
    note SRV-175 "Method 2) chronyc tracking: ${r2}"
    note SRV-175 "Method 3) date (current time): $(date '+%Y-%m-%d %T')"
    local cfg=n; grep -qsE '^(server|pool) ' /etc/chrony.conf /etc/ntp.conf 2>/dev/null && cfg=y
    if [ "$sync" = y ]; then pass SRV-175 "NTP synchronization active (methods 1-3 performed)"
    elif [ "$cfg" = y ]; then pass SRV-175 "NTP server synchronization configured (sync not actively confirmed - verify with chronyc sources)"
    elif is_apply && [ -z "$NTP_SERVER" ]; then fail SRV-175 "NTP_SERVER unset - set internal NTP server IP and rerun"
    else fail SRV-175 "NTP server synchronization not configured"; fi
}

run_40() { srv_108; srv_109; srv_112; srv_175; }
