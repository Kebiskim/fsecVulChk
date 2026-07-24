#!/bin/bash
# modules/10_services.sh - unnecessary services (SRV-004,015,016,034,035,037,147,158,174)
# Items with multiple assessment methods run every method and log each as a [CHECK] line

srv_004() {  # Method: check SMTP on port 25 (single)
    local found=""; for s in postfix sendmail exim; do unit_exists "$s" && found="$found $s"; done
    is_apply && for s in $found; do svc_off "$s"; done
    local p25="not running"; ss -lnt 2>/dev/null | grep -q ':25 ' && p25=running
    note SRV-004 "Method) SMTP on port 25: ${p25}"
    if [ "$p25" = running ]; then fail SRV-004 "SMTP running on port 25 (record exception if business-required)"
    elif [ -n "$found" ]; then pass SRV-004 "SMTP disabled:$found"
    else na SRV-004 "SMTP service not installed"; fi
}

srv_015() {  # Methods x3: 1)nfsd process 2)rpcinfo -p 3)inetd.conf
    local inst=""; unit_exists nfs-server && inst=y
    is_apply && { svc_off nfs-server; svc_off nfs; }
    local r1="not found" r2 r3="not found"
    pgrep -x nfsd >/dev/null 2>&1 && r1=found
    note SRV-015 "Method 1) nfsd process running: ${r1}"
    if command -v rpcinfo >/dev/null 2>&1; then
        r2="not found"; rpcinfo -p 2>/dev/null | grep -qw nfs && r2=found
    else r2="not checkable (rpcinfo command not installed)"; fi
    note SRV-015 "Method 2) nfs entry in rpcinfo -p: ${r2}"
    grep -qsE '^[^#]*\bnfs' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null && r3=found
    note SRV-015 "Method 3) nfs entry in inetd.conf: ${r3}"
    if [ "$r1" = found ] || [ "$r2" = found ] || [ "$r3" = found ]; then
        fail SRV-015 "NFS traces found - manual review (record exception if business-required)"
    elif [ -n "$inst" ]; then pass SRV-015 "NFS disabled (methods 1-3: nothing found)"
    else na SRV-015 "NFS not installed (methods 1-3: nothing found)"; fi
}

srv_016() {  # Methods x3: 1)rpc processes 2)rpcinfo -p 3)inetd.conf
    local inst=""; { unit_exists rpcbind || unit_exists rpcbind.socket; } && inst=y
    is_apply && { svc_off rpcbind; svc_off rpcbind.socket; }
    local RPCS='cmsd|ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|nisd|rexd|pcnfsd|statd|ypupdated|rquotad|kcms_server|cachefsd'
    local r1="not found" r2 r3="not found"
    pgrep -f "rpc\.|rusersd|walld|sprayd|rstatd|rexd|sadmind|kcms_server|cachefsd" >/dev/null 2>&1 && r1=found
    note SRV-016 "Method 1) rpc-family processes: ${r1}"
    if command -v rpcinfo >/dev/null 2>&1; then
        r2="not found"; rpcinfo -p 2>/dev/null | grep -qEw "$RPCS" && r2=found
    else r2="not checkable (rpcinfo command not installed)"; fi
    note SRV-016 "Method 2) RPC services in rpcinfo -p: ${r2}"
    grep -qsE "^[^#]*\b(${RPCS})\b" /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null && r3=found
    note SRV-016 "Method 3) RPC services in inetd.conf: ${r3}"
    if [ "$r1" = found ] || [ "$r2" = found ] || [ "$r3" = found ]; then
        fail SRV-016 "RPC traces found - manual review"
    elif [ -n "$inst" ]; then pass SRV-016 "rpcbind disabled (methods 1-3: nothing found)"
    else na SRV-016 "RPC services not installed (methods 1-3: nothing found)"; fi
}

srv_034() {  # Methods x3: 1)ps automount 2)inetd.conf 3)version check
    local r1="not found" r2="not found"
    pgrep -f 'autofs|automount' >/dev/null 2>&1 && r1=found
    is_apply && unit_exists autofs && svc_off autofs && { pgrep -f 'autofs|automount' >/dev/null 2>&1 && r1=found || r1="found -> stopped"; }
    note SRV-034 "Method 1) automount process (ps): ${r1}"
    grep -qs automount /etc/inetd.conf 2>/dev/null && r2=found
    note SRV-034 "Method 2) automount in inetd.conf: ${r2}"
    if [ "$r1" = found ] || [ "$r2" = found ]; then
        note SRV-034 "Method 3) automountd version: service active - check version vulnerability manually"
        fail SRV-034 "automount active traces found"
    else
        note SRV-034 "Method 3) automountd version: not applicable (service inactive)"
        unit_exists autofs && pass SRV-034 "autofs disabled (methods 1-2: nothing found)" \
                           || na SRV-034 "autofs not installed (methods 1-2: nothing found)"
    fi
}

srv_035() {  # Methods x5: 1)tftp/talk/ntalk 2)finger 3)r-family 4)DoS-prone 5)NIS - each via ps+inetd
    local units="tftp.socket tftp talk.socket ntalk finger rexec.socket rlogin.socket rsh.socket \
echo.socket discard.socket daytime.socket chargen.socket ypserv ypbind"
    local found=""; for s in $units; do unit_exists "$s" && found="$found $s" && { is_apply && svc_off "$s"; }; done
    chk_grp() {  # <no> <name> <ps-pattern> <inetd-pattern>
        local r_ps="not found" r_in="not found"
        pgrep -f "$3" >/dev/null 2>&1 && r_ps=found
        grep -qsE "^[^#]*\b($4)\b" /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null && r_in=found
        note SRV-035 "Method $1) $2 - ps: ${r_ps} / inetd.conf: ${r_in}"
        [ "$r_ps" = found ] || [ "$r_in" = found ]
    }
    local bad=""
    chk_grp 1 "tftp/talk/ntalk" 'in\.tftpd|in\.talkd|in\.ntalkd' 'tftp|talk|ntalk' && bad="$bad tftp/talk"
    chk_grp 2 "finger" 'in\.fingerd' 'finger' && bad="$bad finger"
    chk_grp 3 "r-family(rexec/rlogin/rsh)" 'in\.rexecd|in\.rlogind|in\.rshd' 'rexec|rlogin|rsh|shell' && bad="$bad r-family"
    chk_grp 4 "DoS-prone(echo/discard/daytime/chargen)" 'in\.echod|in\.discardd' 'echo|discard|daytime|chargen' && bad="$bad DoS-family"
    chk_grp 5 "NIS/NIS+" 'ypserv|ypbind|ypxfrd' 'ypserv|ypbind' && bad="$bad NIS"
    if [ -n "${bad// /}" ]; then fail SRV-035 "vulnerable services active:${bad}"
    elif [ -n "$found" ]; then pass SRV-035 "vulnerable services disabled:$found (methods 1-5: nothing found)"
    else na SRV-035 "vulnerable services not installed (methods 1-5: nothing found)"; fi
}

srv_037() {  # Method: check FTP on port 21 (single)
    local found=""; for s in vsftpd proftpd pure-ftpd; do unit_exists "$s" && found="$found $s"; done
    is_apply && for s in $found; do svc_off "$s"; done
    local p21="not running"; ss -lnt 2>/dev/null | grep -q ':21 ' && p21=running
    note SRV-037 "Method) FTP on port 21: ${p21}"
    if [ "$p21" = running ]; then fail SRV-037 "FTP running (record exception if business-required)"
    elif [ -n "$found" ]; then pass SRV-037 "FTP services disabled:$found"
    else na SRV-037 "FTP service not installed"; fi
}

srv_147() {  # Method: ps -ef | grep snmp (manual command used verbatim)
    # grep -v grep : excludes the grep process itself, the classic ps|grep false positive
    ps_snmp() { ps -ef 2>/dev/null | grep snmp | grep -v grep; }
    local cnt; cnt=$(ps_snmp | grep -c .)
    note SRV-147 "Method) ps -ef | grep snmp: ${cnt} process(es)"
    ps_snmp | head -5 | while IFS= read -r l; do [ -n "$l" ] && note SRV-147 "  $l"; done
    local inst=""
    { unit_exists snmpd || unit_exists snmptrapd; } && inst=y
    if is_apply; then svc_off snmpd; svc_off snmptrapd; fi
    if ps_snmp | grep -q .; then
        is_apply && fail SRV-147 "snmp process still running after stop - manual review" \
                 || fail SRV-147 "snmp process running (if needed, configure v3 and record exception)"
    elif [ -n "$inst" ]; then
        pass SRV-147 "snmpd/snmptrapd disabled (ps -ef | grep snmp: nothing found)"
    else
        na SRV-147 "SNMP not installed (ps -ef | grep snmp: nothing found)"
    fi
}

srv_158() {  # Method: check Telnet on port 23 (single)
    local found=""; for s in telnet.socket telnet; do unit_exists "$s" && found="$found $s"; done
    is_apply && for s in $found; do svc_off "$s"; done
    local p23="not running"; ss -lnt 2>/dev/null | grep -q ':23 ' && p23=running
    note SRV-158 "Method) Telnet on port 23: ${p23}"
    if [ "$p23" = running ]; then fail SRV-158 "Telnet running"
    elif [ -n "$found" ]; then pass SRV-158 "Telnet service disabled"
    else na SRV-158 "Telnet service not installed"; fi
}

srv_174() {  # Method: ps named check (single)
    local r="not found"; pgrep -x named >/dev/null 2>&1 && r=found
    note SRV-174 "Method) ps -ef | grep named: ${r}"
    if unit_exists named; then
        is_apply && svc_off named
        pgrep -x named >/dev/null 2>&1 && fail SRV-174 "named running (record exception if business-required)" \
                                       || pass SRV-174 "named disabled"
    else na SRV-174 "DNS service not installed"; fi
}

run_10() { srv_004; srv_015; srv_016; srv_034; srv_035; srv_037; srv_147; srv_158; srv_174; }
