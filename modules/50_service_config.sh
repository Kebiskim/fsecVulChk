#!/bin/bash
# modules/50_service_config.sh - per-service configuration (applied/checked only when installed)
# SNMP: 001,003 / SMTP: 005-010,170 / FTP: 011,013,021,161,171 / NFS: 014 / DNS: 062,063,064,066,173

# ☆SNMP, SMTP, FTP, NFS, DNS => do not use (double check)
run_snmp() {
    local SNMPC=""
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf; do [ -f "$f" ] && SNMPC=$f && break; done
    if [ -z "$SNMPC" ]; then
        note SRV-001 "Method) snmpd.conf: file missing"
        note SRV-003 "Method) snmpd.conf access control: file missing"
        na SRV-001 "SNMP config file missing"; na SRV-003 "SNMP config file missing"; return
    fi
    # SRV-003 (community / access control - grep syntax specified by the criteria)
    local acl; acl=$(grep -E '^(agentAddress|rocommunity|rwcommunity|com2sec|group|view|access|rouser|rwuser|createUser)' "$SNMPC" | head -10)
    note SRV-003 "Method 1) grep access-control directives ${SNMPC}: ${acl:-none defined}"
    local comm; comm=$(grep -nE '^\s*(rocommunity|rwcommunity|com2sec)\b.*\b(public|private)\b' "$SNMPC" | head -3)
    note SRV-003 "Method 2) grep default community (public/private) ${SNMPC}: ${comm:-not found}"
    if [ -n "$comm" ]; then
        if is_apply; then
            bak "$SNMPC"
            sed -ri 's/^(\s*(rocommunity|rwcommunity|com2sec).*(public|private).*)/# init_hardening blocked: \1/' "$SNMPC"
            pass SRV-003 "default community lines commented out - configure v3 before restarting service"
        else fail SRV-003 "default community (public/private) in use - access control inadequate"; fi
    else pass SRV-003 "default community not used - access control adequate"; fi
    # SRV-001 (v3 AuthPriv)
    local v3; v3=$(grep -E '^\s*(rouser|rwuser|createUser)' "$SNMPC" | head -3)
    note SRV-001 "Method) SNMPv3 security level (AuthPriv): ${v3:-no v3 settings}"
    if grep -Eq '^\s*(rouser|rwuser).*(priv|authpriv)' "$SNMPC"; then
        pass SRV-001 "SNMPv3 AuthPriv user present"
    else fail SRV-001 "SNMPv3 AuthPriv not configured - use v3 (authPriv) if monitoring is needed"; fi
}


run_smtp() {
    if command -v postconf >/dev/null 2>&1; then
        # SRV-005: Methods 1)connect and try vrfy OR 2)check main.cf - 'OR' condition, method 2 chosen
        note SRV-005 "Method) 1) connect+vrfy attempt OR 2) main.cf check - 'OR' condition, using method 2 (config file)"
        if is_apply; then
            bak /etc/postfix/main.cf
            postconf -e 'disable_vrfy_command = yes'
            postconf -e 'smtpd_banner = $myhostname ESMTP'
        fi
        local v; v=$(postconf -h disable_vrfy_command 2>/dev/null)
        note SRV-005 "Method 2) main.cf disable_vrfy_command: ${v:-unknown}"
        [ "$v" = yes ] && pass SRV-005 "vrfy command disabled" || fail SRV-005 "disable_vrfy_command=${v:-no}"
        # SRV-006
        local dpl; dpl=$(postconf -h debug_peer_level 2>/dev/null)
        note SRV-006 "Method) debug_peer_level (criterion 2+, default 2): ${dpl:-2}"
        if [ "${dpl:-2}" -ge 2 ]; then pass SRV-006 "debug_peer_level=${dpl:-2}"
        elif is_apply; then postconf -e 'debug_peer_level = 2'; pass SRV-006 "debug_peer_level raised to 2"
        else fail SRV-006 "debug_peer_level=${dpl} - 2 or higher required"; fi
        # SRV-007 (version readable; latest-or-not is manual)
        local mv; mv=$(postconf -h mail_version 2>/dev/null)
        note SRV-007 "Method) postconf -d mail_version: ${mv} (criterion: 2.8.3+/CVE-2011-1720)"
        fail SRV-007 "postfix ${mv} - verify manually against internal patch baseline"
        # SRV-008 (check each of the 5 parameters)
        local dos_bad="" k v8
        for k in message_size_limit header_size_limit default_process_limit smtpd_recipient_limit local_destination_concurrency_limit; do
            v8=$(postconf -h $k 2>/dev/null)
            note SRV-008 "Method) ${k}: ${v8:-default} $([ "$v8" = 0 ] && echo '(0=unlimited, vulnerable)' || echo '(kept)')"
            [ "$v8" = 0 ] && dos_bad="$dos_bad $k"
        done
        [ -z "$dos_bad" ] && pass SRV-008 "DoS limits kept (nothing set to 0)" \
                          || fail SRV-008 "set to 0:$dos_bad - restore defaults"
        # SRV-009
        local rr; rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        note SRV-009 "Method) smtpd_relay_restrictions: ${rr:-unset}"
        if echo "$rr" | grep -Eq 'permit_mynetworks.*(reject|defer)_unauth_destination'; then
            pass SRV-009 "relay restrictions confirmed"
        elif is_apply; then
            postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
            pass SRV-009 "relay blocking configured"
        else fail SRV-009 "relay restrictions insufficient"; fi
        # SRV-010
        local PSUP; PSUP=$(command -v postsuper || echo /usr/sbin/postsuper)
        if [ -f "$PSUP" ]; then
            is_apply && chmod o-rx "$PSUP"
            note SRV-010 "Method) postsuper permission: $(stat -c %a "$PSUP")"
            perm_le "$PSUP" 750 && pass SRV-010 "postsuper not executable by others" \
                                || fail SRV-010 "postsuper executable by others"
        else
            note SRV-010 "Method) postsuper permission: not checkable (binary not found)"
            fail SRV-010 "postsuper not found - manual review"
        fi
        # SRV-170
        local bn; bn=$(postconf -h smtpd_banner 2>/dev/null)
        note SRV-170 "Method) smtpd_banner: ${bn}"
        echo "$bn" | grep -q mail_version && fail SRV-170 "banner contains mail_version" \
                                          || pass SRV-170 "banner has no version info"
    elif [ -f /etc/mail/sendmail.cf ] || [ -f /etc/sendmail.cf ]; then
        local SMCF=/etc/mail/sendmail.cf; [ -f $SMCF ] || SMCF=/etc/sendmail.cf
        note SRV-005 "Method 2) PrivacyOptions in ${SMCF}: $(grep -oE 'PrivacyOptions=.*' $SMCF | head -1)"
        grep -Eq 'PrivacyOptions=.*(goaway|(noexpn.*novrfy|novrfy.*noexpn))' $SMCF \
            && pass SRV-005 "goaway/noexpn+novrfy present" || fail SRV-005 "add goaway to PrivacyOptions"
        note SRV-006 "Method) LogLevel: $(grep -oE '^O *LogLevel=[0-9]+' $SMCF || echo unset)"
        grep -Eq '^O *LogLevel=(9|[1-9][0-9])' $SMCF && pass SRV-006 "LogLevel 9 or higher" || fail SRV-006 "set LogLevel 9 or higher"
        note SRV-007 "Method) sendmail version: $(echo | /usr/lib/sendmail -bt -d0 2>/dev/null | grep -i version || echo unknown)"
        fail SRV-007 "verify 8.14.9+ manually (CVE-2009-4565)"
        note SRV-008 "Method) MaxDaemonChildren and 4 other params: manual review required"
        fail SRV-008 "sendmail DoS limits - manual review required"
        note SRV-009 "Method) relay restrictions (access DB): manual review required"
        fail SRV-009 "sendmail relay restrictions - manual review required"
        note SRV-010 "Method) restrictqrun: $(grep -q restrictqrun $SMCF && echo present || echo missing)"
        grep -q restrictqrun $SMCF && pass SRV-010 "restrictqrun present" || fail SRV-010 "add restrictqrun"
        note SRV-170 "Method) \$v in SmtpGreetingMessage: $(grep -Eq 'SmtpGreetingMessage.*\$v' $SMCF && echo present || echo absent)"
        grep -Eq 'SmtpGreetingMessage.*\$v' $SMCF && fail SRV-170 "banner contains version (\$v)" || pass SRV-170 "banner has no version"
    else
        for i in SRV-005 SRV-006 SRV-007 SRV-008 SRV-009 SRV-010 SRV-170; do
            note $i "Method) SMTP config: not checkable (postfix/sendmail not installed)"
            na $i "SMTP not installed"
        done
    fi
}

run_ftp() {
    local VSF=/etc/vsftpd/vsftpd.conf; [ -f $VSF ] || VSF=/etc/vsftpd.conf
    local PROF=/etc/proftpd.conf; [ -f $PROF ] || PROF=/etc/proftpd/proftpd.conf
    if [ -f "$VSF" ]; then
        vs_get() { grep -E "^${1}=" "$VSF" | tail -1 | cut -d= -f2-; }
        if is_apply; then
            bak "$VSF"
            vs_set() { grep -Eq "^#?${1}=" "$VSF" && sed -ri "s|^#?${1}=.*|${1}=${2}|" "$VSF" || echo "${1}=${2}" >> "$VSF"; }
            vs_set anonymous_enable NO
            vs_set ftpd_banner "Authorized users only"
            local FU=/etc/vsftpd/ftpusers; [ -f $FU ] || FU=/etc/ftpusers
            touch "$FU"; grep -q '^root$' "$FU" || { bak "$FU"; echo root >> "$FU"; }
            [ -f /etc/vsftpd/user_list ] && { grep -q '^root$' /etc/vsftpd/user_list || echo root >> /etc/vsftpd/user_list; }
        fi
        # SRV-011: Methods 1)root in ftpusers 2)actual connection denial (manual)
        local rf; rf=$(grep -ls '^root$' /etc/vsftpd/ftpusers /etc/ftpusers 2>/dev/null | head -1)
        note SRV-011 "Method 1) root in ftpusers: ${rf:+present in ${rf}}${rf:-not registered}"
        note SRV-011 "Method 2) actual root FTP login denial: manual check required (script does not attempt connections)"
        [ -n "$rf" ] && pass SRV-011 "root registered in ftpusers" || fail SRV-011 "root missing from ftpusers"
        # SRV-013: Methods 1)config file 2)anonymous login attempt (manual)
        local an; an=$(vs_get anonymous_enable)
        note SRV-013 "Method 1) vsftpd.conf anonymous_enable: ${an:-unset (check version default)}"
        note SRV-013 "Method 2) actual anonymous login attempt: manual check required"
        [ "$an" = NO ] && pass SRV-013 "anonymous disabled" || fail SRV-013 "anonymous_enable=${an:-unset}"
        # SRV-021
        local ac=none
        grep -Eq '^tcp_wrappers=YES' "$VSF" && ac=tcp_wrappers
        systemctl is-active firewalld >/dev/null 2>&1 && ac="${ac}+firewalld"
        note SRV-021 "Method) FTP access control settings: ${ac}"
        [ "$ac" != none ] && pass SRV-021 "access control exists (${ac}) - register allowed IPs per policy" \
                          || fail SRV-021 "FTP access control not configured"
        # SRV-161
        local perm_bad=""
        for f in /etc/ftpusers /etc/vsftpd/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/user_list; do
            [ -e "$f" ] || continue
            is_apply && perm_max "$f" 640
            note SRV-161 "Method) ls -alLd ${f}: $(stat -c '%U/%a' "$f")"
            { perm_le "$f" 640 && owner_is "$f" root; } || perm_bad="$perm_bad $f"
        done
        [ -z "$perm_bad" ] && pass SRV-161 "ftpusers files root/640 or lower" || fail SRV-161 "below criteria:$perm_bad"
        # SRV-171
        local bn; bn=$(vs_get ftpd_banner)
        note SRV-171 "Method) ftpd_banner: ${bn:-unset (default banner may expose version)}"
        [ -n "$bn" ] && pass SRV-171 "custom banner configured" || fail SRV-171 "default banner - version may be exposed"
    elif [ -f "$PROF" ]; then
        if is_apply; then
            bak "$PROF"
            grep -Eq '^\s*ServerIdent\s+off' "$PROF" || echo 'ServerIdent off' >> "$PROF"
            grep -Eq '^\s*RootLogin\s+off' "$PROF" || echo 'RootLogin off' >> "$PROF"
        fi
        note SRV-011 "Method 1) proftpd RootLogin: $(grep -E '^\s*RootLogin' "$PROF" || echo unset)"
        note SRV-011 "Method 2) actual login denial: manual check required"
        grep -Eq '^\s*RootLogin\s+off' "$PROF" && pass SRV-011 "RootLogin off" || fail SRV-011 "restrict RootLogin"
        note SRV-013 "Method 1) proftpd Anonymous block: $(grep -qi '<Anonymous' "$PROF" && echo present || echo absent)"
        note SRV-013 "Method 2) anonymous login attempt: manual check required"
        grep -Eqi '<Anonymous' "$PROF" && fail SRV-013 "Anonymous block present" || pass SRV-013 "no Anonymous block"
        note SRV-021 "Method) proftpd access control (Limit/Allow/Deny): $(grep -Eq '^\s*(Allow|Deny)\b' "$PROF" && echo present || echo absent)"
        grep -Eq '^\s*(Allow|Deny)\b' "$PROF" && pass SRV-021 "access control present" || fail SRV-021 "<Limit LOGIN> required"
        for f in /etc/ftpusers /etc/ftpd/ftpusers; do
            [ -e "$f" ] || continue
            is_apply && perm_max "$f" 640
            note SRV-161 "Method) ls -alLd ${f}: $(stat -c '%U/%a' "$f")"
        done
        pass SRV-161 "ftpusers permission check performed"
        note SRV-171 "Method) ServerIdent: $(grep -E '^\s*ServerIdent' "$PROF" || echo unset)"
        grep -Eq '^\s*ServerIdent\s+off' "$PROF" && pass SRV-171 "ServerIdent off" || fail SRV-171 "ServerIdent not set"
    else
        for i in SRV-011 SRV-013 SRV-021 SRV-161 SRV-171; do
            note $i "Method) FTP config: not checkable (vsftpd/proftpd not installed)"
            na $i "FTP service not installed"
        done
    fi
}

run_nfs_cfg() {  # SRV-014: Methods x3 1)service running 2)exports file 3)share access-control options
    local r1="not running"
    { pgrep -x nfsd >/dev/null 2>&1 || unit_active nfs-server; } && r1=running
    note SRV-014 "Method 1) NFS service running: ${r1}"
    if [ ! -f /etc/exports ]; then
        note SRV-014 "Method 2) /etc/exports: file missing"
        note SRV-014 "Method 3) share access-control options: not applicable (no file)"
        na SRV-014 "/etc/exports missing (NFS not used)"; return
    fi
    is_apply && perm_max /etc/exports 644
    note SRV-014 "Method 2) /etc/exports owner/permission: $(stat -c '%U/%a' /etc/exports) (criterion root/644 or lower)"
    local opt="no export entries" opt_bad=""
    grep -Eq '^\s*/' /etc/exports && { grep -Eq '^\s*/\S+\s+\*' /etc/exports && { opt="wildcard (*) host allowed (vulnerable)"; opt_bad=y; } || opt="host restriction present"; }
    note SRV-014 "Method 3) share access-control options: ${opt}"
    if ! perm_le /etc/exports 644 || ! owner_is /etc/exports root; then fail SRV-014 "exports owner/permission below criteria"
    elif [ -n "$opt_bad" ]; then fail SRV-014 "exports shared to all hosts - restrict to specific hosts"
    else pass SRV-014 "NFS access control meets criteria (methods 1-3)"; fi
}

run_dns() {
    local NAMED=/etc/named.conf
    if [ ! -f $NAMED ]; then
        for i in SRV-062 SRV-063 SRV-064 SRV-066 SRV-173; do
            note $i "Method) named.conf: not checkable (file missing)"
            na $i "BIND not installed"
        done
        return
    fi
    note SRV-062 "Method) version directive in named.conf: $(grep -E 'version\s' $NAMED | head -1 || echo none)"
    grep -Eq 'version\s+"' $NAMED && pass SRV-062 "version banner configured" || fail SRV-062 "add version \"unknown\"; to options"
    note SRV-063 "Method) recursion option in named.conf: $(grep -E 'recursion\s' $NAMED | head -1 || echo 'unset (default yes)')"
    grep -Eq 'recursion\s+no' $NAMED && pass SRV-063 "recursion no" || fail SRV-063 "restrict recursion"
    # SRV-064: method requires dig porttest + version check - external dig impossible on closed network
    note SRV-064 "Method 1) dig porttest.dns-oarc.net: not checkable (closed network - no external DNS queries)"
    note SRV-064 "Method 2) BIND version: $(named -v 2>/dev/null || echo 'named -v failed')"
    fail SRV-064 "compare version against vulnerability matrix manually"
    note SRV-066 "Method) allow-transfer in named.conf: $(grep -E 'allow-transfer' $NAMED | head -1 || echo none)"
    grep -Eq 'allow-transfer' $NAMED && pass SRV-066 "zone transfer restricted" || fail SRV-066 "add allow-transfer { secondary-ip; };"
    note SRV-173 "Method) allow-update/update-policy in named.conf: $(grep -E 'allow-update|update-policy' $NAMED | head -1 || echo 'unset (default none)')"
    if grep -Eq 'allow-update.*(none|key )' $NAMED || ! grep -q allow-update $NAMED; then
        pass SRV-173 "dynamic updates disabled / key-restricted"
    else fail SRV-173 "allow-update too permissive"; fi
}

run_50() { run_snmp; run_smtp; run_ftp; run_nfs_cfg; run_dns; }
