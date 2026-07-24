#!/bin/bash
################################################################################
# apply.sh - initial Linux hardening (INITIAL BUILD ONLY - do not rerun on
#            production servers; rerunning reverts business-required changes
#            such as services, mail relay policy, and banners to initial values.
#            Use check.sh for inspection on running servers.)
#  Basis: FSI e-financial infrastructure server assessment criteria - 70 LINUX items
#  Required before running: 1) set NTP_SERVER
#                           2) add admin accounts to the wheel group
#                              (su will be blocked for non-wheel users)
#  Usage: # bash apply.sh [module-no]
#  Result: /var/log/hardening_apply_YYYYmmdd_HHMMSS.log (SUCCESS/ERROR/N-A)
#  Backup: /root/init_hardening_backup_YYYYmmdd_HHMMSS/
################################################################################
MODE=apply
BASE="$(cd "$(dirname "$0")" && pwd)"

# Site variables (edit per environment)
NTP_SERVER=""                 # internal NTP server IP - SRV-175 reports ERROR if empty
TMOUT_SEC=600                 # criterion: 900s or less
UMASK_VAL=022                 # criterion: no write for group/others
PASS_MAX_DAYS=90; PASS_MIN_LEN=8; PASS_MIN_CLASS=3
FAIL_DENY=5; FAIL_UNLOCK=600
SU_GROUP=wheel                # after apply, su is limited to this group

. "$BASE/lib/common.sh"
init_common
echo "==== Initial hardening (apply) started $TS (backup: $BACKUP_DIR) ====" | tee -a "$LOG"
for m in "$BASE"/modules/*.sh; do
    mn=$(basename "$m")
    [ -n "$1" ] && [[ "$mn" != "$1"* ]] && continue
    . "$m"; "run_${mn%%_*}"
done
echo " NOTE: pam_wheel applied - accounts outside '${SU_GROUP}' group cannot use su" | tee -a "$LOG"
echo " NOTE: re-login recommended to verify umask/TMOUT" | tee -a "$LOG"
summary
