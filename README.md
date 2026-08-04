# linux-patch

Staged `dnf` patch management across a RHEL 9 fleet. SSH in, collect pending
updates, tag security advisories, and apply them with live re-validation and
opt-in serialized reboots. Output is a formatted Excel report plus a machine
readable patch plan.

Fourth tool in a family with [linux-audit](https://github.com/vikozs/linux-audit),
[linux-harden](https://github.com/vikozs/linux-harden), and
[linux-diskspace](https://github.com/vikozs/linux-diskspace). It shares their
transport (`ssh_exec.py`) and Excel safety layer (`xlsx_safe.py`).

## What it does

- Enumerates pending updates per host from `dnf check-update`.
- Tags which updates carry a security advisory, with severity, from
  `dnf updateinfo list security`.
- Detects reboot-required state with `needs-restarting -r`.
- Applies the plan with per-host confirmation, re-validating each host against
  live state first.
- Optionally reboots each host after apply, one at a time, waiting for it to
  return before touching the next.
- Can undo a single host's transaction with `dnf history undo`.

It never installs blindly. The discover plan is a candidate list; apply re-runs
`check-update` and installs only the intersection of the plan and what is still
pending.

## Requirements

- Python 3.9+ and `openpyxl` on the machine you run it from.
- `sshpass` on that machine if you use password SSH login.
- RHEL 9 (or any `dnf`/`yum` host) as targets. `needs-restarting` comes from
  `dnf-utils`/`yum-utils`; without it, reboot state reports as unknown.

```
pip install -r requirements.txt
```

## Usage

Discover, writing `patch_plan.json` and `patch_report.xlsx`:

```
python3 linux_patch.py discover -H hosts.txt -u local.user \
    --ask-ssh-pass --sudo-pass-same-as-ssh
```

Review the report, then apply, confirming per host:

```
python3 linux_patch.py apply --plan patch_plan.json -u local.user \
    --ask-ssh-pass --sudo-pass-same-as-ssh
```

Security updates only, with a serialized reboot after each host:

```
python3 linux_patch.py apply --plan patch_plan.json --security --reboot \
    -H hosts.txt -u local.user --ask-ssh-pass --sudo-pass-same-as-ssh
```

Undo a host's most recent patch transaction:

```
python3 linux_patch.py rollback --host web01.hostname.loc --txn 48 \
    -u local.user --ask-ssh-pass --sudo-pass-same-as-ssh
```

Re-render an existing plan to Excel without touching the fleet:

```
python3 linux_patch.py report --plan patch_plan.json -o report.xlsx
```

### Authentication

Password SSH plus password sudo, sharing one domain account, is the common
case:

```
python3 linux_patch.py discover -H hosts.txt -u local.user \
    --ask-ssh-pass --sudo-pass-same-as-ssh
```

Non-interactive, password from the environment:

```
SSH_PW='...' python3 linux_patch.py discover -H hosts.txt -u local.user \
    --ssh-pass-env SSH_PW --sudo-pass-same-as-ssh
```

Key-based auth with passwordless sudo:

```
python3 linux_patch.py discover -H hosts.txt -u local.user -i ~/.ssh/id_ed25519
```

Passwords travel via stdin or the `SSHPASS` env var, never on the command line.

## Reboots

Reboot is report-only by default. The report and plan flag every host whose
kernel or core libraries need a restart, and you decide what to do.

`--reboot` opts in. Reboots are serialized: apply installs on a host, schedules
its reboot, then waits (up to `--reboot-timeout`, default 600s) for the host to
answer SSH again before moving to the next. If a host does not come back, the
reboot loop stops and the remaining hosts are left untouched, so a bad kernel
never takes the whole fleet down at once.

## Output

`patch_report.xlsx` sheets:

- Summary: one row per host, update and security counts, reboot flag.
- Pending Updates: every update, with repo, whether it is a security fix, and
  severity.
- Security Advisories: the security subset, by advisory id.
- Reboot Required: hosts whose kernel or libraries need a restart.
- Errors: hosts that could not be reached, with the ssh reason.
- About: tool version, build stamp, totals.

`patch_plan.json` is the same data as structured input for `apply`. `apply`
writes `patch_results.json` recording what was installed and the transaction id
per host, which you feed to `rollback`.

## Security considerations

Run artifacts describe your fleet and what it is missing. `patch_plan.json`,
`patch_results.json`, and the xlsx are gitignored for that reason. Do not commit
them.

The remote scripts run under sudo. Package names from the plan are shell-quoted
before they reach the install command, and untrusted strings written to the
report are neutralised so a hostile package name cannot become a spreadsheet
formula.

## Development

```
pip install -r requirements.txt pytest
pytest -q
```

The parsers and plan logic are pure functions tested against captured `dnf`
output fixtures. The SSH transport is the same module the other tools use.

## License

MIT. See [LICENSE](LICENSE).
