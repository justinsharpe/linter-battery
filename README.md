# linter-battery

One call, every linter, one normalized JSON schema.

## Why this exists

Build, not rent. Instead of subscribing to a hosted "AI code review" service,
run your own local battery of linters over a diff, a staged set, or an
explicit path list and get every finding back in one normalized JSON schema —
regardless of which linter produced it. The corpus never leaves your machine:
no cloud linter, no upload, no API key.

- One command, many linters, one output shape.
- Missing a linter? It's recorded as a `skip`, never a crash.
- Fail-open: the battery reports; gating is *your* call (`--gate`).

## Usage

```sh
python3 linter_battery.py --staged        # lint staged files in the current repo
python3 linter_battery.py --diff main     # lint files changed vs a git ref
python3 linter_battery.py --paths src/ tests/ app.py
```

Options:

| flag | effect |
| --- | --- |
| `--deep` | add slow-pass tools (`ty`, `bandit`) |
| `--gate` | exit 1 if any error-severity finding |
| `--json PATH` | write the full findings report as JSON |
| `--config PATH` | override `linter-battery.json` |
| `--self-test` | run the built-in self-test and exit |

## Tool list

Configurable in `linter-battery.json`. Defaults:

| tool | targets | severity |
| --- | --- | --- |
| ruff | Python | error |
| ty | Python (deep) | error |
| bandit | Python (deep) | warning |
| oxlint | JS / TS / JSX / TSX | warning / error |
| swiftlint | Swift | warning / error |
| shellcheck | shell | warning |
| shfmt | shell | info |
| hadolint | Dockerfile | warning |
| actionlint | GitHub workflows | error |
| typos | Markdown | warning |
| vale | Markdown | warning |
| gitleaks | staged secrets | error |

## Configuration

`linter-battery.json` drives the tool list, file filters, severity mapping,
timeout, file cap, and which severity levels trip `--gate`. Point `--config`
at your own file to add, remove, or reweight linters without touching code.

## Self-test

```sh
python3 linter_battery.py --self-test
# or
python3 test_linter_battery.py
```

The self-test needs no linters installed: it exercises the skip path (a
missing binary is recorded, not fatal), the normalized JSON schema, and
argument parsing.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Justin Sharpe.
