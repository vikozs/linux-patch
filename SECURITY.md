# Security

## Reporting

Report vulnerabilities privately through GitHub Security Advisories on this
repository, or by opening an issue asking for a private contact if that is not
available. Please do not disclose details publicly until a fix is released.

## Handling of credentials and run artifacts

- SSH and sudo passwords are passed to the remote over stdin or the `SSHPASS`
  environment variable, never as command-line arguments.
- Remote scripts run under sudo. Package names taken from a plan are
  shell-quoted before use.
- Run artifacts (`patch_plan.json`, `patch_results.json`, `*.xlsx`) describe
  your fleet and its missing patches. They are gitignored. Do not commit them or
  share them outside the team.
- Values written into the Excel report are neutralised against spreadsheet
  formula injection.
