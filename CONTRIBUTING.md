# Contributing

Bug reports and pull requests are welcome.

- Keep the SSH transport (`ssh_exec.py`) and Excel safety layer (`xlsx_safe.py`)
  in sync with the rest of the family rather than forking their behaviour.
- Parsers and plan logic are pure functions. Add a fixture under
  `tests/fixtures/` for any new `dnf` output shape and test the parser against
  it, rather than testing over SSH.
- Run `pytest -q` before opening a PR. CI runs on Python 3.9 through 3.12.
- Plain, direct writing in docs and messages.
