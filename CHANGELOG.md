# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
semantic versioning.

## [1.0.0] - 2026-07-31

Initial release.

### Added
- `discover` mode: collect pending updates per host, tag security advisories
  with severity, detect reboot-required, write a patch plan (JSON) and a
  formatted Excel report.
- `apply` mode: install updates from a plan with per-host confirmation,
  re-validating each host against live `dnf check-update` output before
  installing. Records the resulting transaction id.
- `--security` to restrict a plan and an apply to security-advisory packages.
- `--reboot`: opt-in, serialized reboots. Each host is rebooted and waited for
  before the next is touched; a host that does not return aborts the loop.
- `rollback` mode: `dnf history undo` for a single host and transaction.
- `report` mode: re-render an existing plan to Excel with no SSH.
- Shared `ssh_exec.py` transport and `xlsx_safe.py` Excel safety layer from the
  linux-audit family.
- Test suite covering the parsers, plan assembly, apply reconciliation, script
  generation, and report generation. GitHub Actions CI on Python 3.9-3.12.
