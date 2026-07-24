#!/bin/bash
################################################################################
# check.sh - server vulnerability check (NEVER modifies the system; log only)
#  Basis: FSI (Financial Security Institute) e-financial infrastructure server
#         assessment criteria - all 70 LINUX items
#  Usage: # bash check.sh [module-no]   e.g. bash check.sh      (all modules)
#                                            bash check.sh 20   (accounts only)
#  Result: /var/log/hardening_check_YYYYmmdd_HHMMSS.log (PASS/VULN/N-A)
################################################################################
MODE=check
BASE="$(cd "$(dirname "$0")" && pwd)"

# Check thresholds (keep identical to apply.sh)
TMOUT_SEC=600; UMASK_VAL=022; PASS_MAX_DAYS=90; PASS_MIN_LEN=8; PASS_MIN_CLASS=3
FAIL_DENY=5; FAIL_UNLOCK=600; SU_GROUP=wheel; NTP_SERVER=""

. "$BASE/lib/common.sh"
init_common
echo "==== Vulnerability check started $TS - no system changes ====" | tee -a "$LOG"
for m in "$BASE"/modules/*.sh; do
    mn=$(basename "$m")
    [ -n "$1" ] && [[ "$mn" != "$1"* ]] && continue
    . "$m"; "run_${mn%%_*}"
done
summary
