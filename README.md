# serverSecChk

Linux server security check and initial hardening scripts based on the FSI
(Financial Security Institute) e-financial infrastructure server assessment
criteria — all 70 LINUX items.

Target platform: **RHEL 9+** (closed/air-gapped networks supported — no
outbound network access is required or attempted).

## Modes

| Script | Mode | System changes | Verdicts |
|--------|------|----------------|----------|
| `check.sh` | Inspection | **Never modifies the system** (log only) | `PASS` / `VULN` / `N-A` |
| `apply.sh` | Initial hardening | Applies settings, backs up every file first | `SUCCESS` / `ERROR` / `N-A` |

> **Warning:** `apply.sh` is for the **initial build only**. Do not rerun it on
> production servers — rerunning reverts business-required changes (services,
> mail relay policy, banners) to initial values. Use `check.sh` for inspection
> on running servers.

## Usage

```bash
# run everything (as root)
bash check.sh            # inspection only
bash apply.sh            # initial hardening

# run a single module by number prefix
bash check.sh 20         # accounts module only
bash apply.sh 50         # service-configuration module only
```

Before running `apply.sh`:

1. Set `NTP_SERVER` at the top of `apply.sh` (internal NTP server IP).
   SRV-175 reports `ERROR` if it is left empty.
2. Add admin accounts to the `wheel` group — after apply, `su` is blocked
   for accounts outside that group (`pam_wheel.so use_uid`).

## Output

- Log file: `/var/log/hardening_<mode>_<YYYYmmdd_HHMMSS>.log` (mode 600)
  - One `[CHECK]` line per assessment method (evidence), then one final
    verdict line per SRV item.
- Backups (apply mode): `/root/init_hardening_backup_<TS>/` — copy files
  back to revert.
- Baselines (apply mode): `/root/suid_baseline_<TS>.txt`,
  `/root/hidden_files_<TS>.txt`, `/root/no_owner_files_<TS>.txt`
  (used by later check runs for drift detection).
- Exit code: `0` when no `VULN`/`ERROR`, otherwise `2`.

## Layout

```
serverSecChk/
├── check.sh                    # entry point - inspection (read-only)
├── apply.sh                    # entry point - initial hardening
├── lib/
│   └── common.sh               # shared helpers (log/pass/fail/na, bak, set_kv, perm helpers)
└── modules/
    ├── 10_services.sh          # unnecessary services (SMTP/NFS/RPC/FTP/Telnet/SNMP/DNS ...)
    ├── 20_accounts.sh          # accounts & authentication (password policy, PAM, sudo, su ...)
    ├── 30_permissions.sh       # umask & file/directory permissions, SUID, world-writable ...
    ├── 40_logging_time.sh      # syslog policy, log permissions, NTP time sync
    ├── 50_service_config.sh    # per-service config: SNMP, SMTP, FTP, NFS, DNS
    └── 60_misc.sh              # access control, login banner, procedural items, OS EOL
```

Modules are sourced and dispatched by number prefix (`run_10` … `run_60`), so
a module can be run in isolation by passing its prefix as the first argument.

## Design notes

- **Check mode is strictly read-only.** Every mutating call (`chmod`, `sed -i`,
  `systemctl stop`, `usermod`, …) is gated behind `is_apply`; the shared
  helpers (`svc_off`, `perm_max`, `set_kv`, `bak`) enforce the same gate
  internally.
- **Closed-network safe.** Time-sync checks query only the local daemon
  (`ntpq -pn`, `chronyc tracking`); repository validity uses cache-only
  queries (`dnf repolist -C`); external lookups (e.g. `dig porttest`) are
  recorded as not checkable instead of being attempted.
- **Safety rails in apply mode.** SSH config edits are validated with
  `sshd -t` and reverted from backup on failure; sudoers edits are validated
  with `visudo -cf` and reverted on failure; SUID bit removal is limited to a
  fixed 12-path KISA candidate list; the PAM stack is wired only through
  `authselect` (never edited directly).
- **Procedural items** (periodic log review, patch intake process, quarterly
  account review) are logged as `N-A` with collected evidence — they must be
  managed as operational processes with documentation.

## Requirements

- Root privileges (`sudo bash check.sh`)
- Bash, coreutils, `systemctl` — standard on RHEL 9
- Optional (checked gracefully when absent): `chage`, `lastlog`, `authselect`,
  `chronyc`/`ntpq`, `rpcinfo`, `postconf`, `visudo`
