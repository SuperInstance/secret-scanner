# Fleet Secret Scanner

Scans all fleet repositories for accidentally committed secrets and sensitive data. Unlike outbound leak detectors (which inspect network traffic), this tool checks **git history** — finding secrets that were committed at any point in time, even if they were later removed.

## Features

- **Current files**: Scan all files in the working directory
- **Git history**: Walk `git log -p` to find secrets in every commit
- **Diff scan**: Scan uncommitted changes (`git diff`)
- **Staged scan**: Scan the staging area (`git diff --cached`)
- **Baseline drift**: Save a snapshot and detect NEW secrets over time

## Secret Patterns Detected

| Severity | Type | Examples |
|----------|------|---------|
| CRITICAL | GitHub PATs | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` |
| CRITICAL | AWS Keys | `AKIA...`, `aws_secret_access_key=...` |
| CRITICAL | Stripe Live Keys | `sk_live_...`, `rk_live_...` |
| HIGH | Private Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| HIGH | Connection Strings | `postgresql://...`, `mongodb+srv://...` |
| HIGH | Hardcoded Passwords | `password = "..."` |
| HIGH | Slack Tokens | `xoxb-...` |
| HIGH | JWTs | `eyJhbG...` |
| HIGH | Authorization Headers | `Bearer ...` |
| HIGH | SendGrid / Twilio / Heroku | Service-specific keys |
| MEDIUM | Google API Keys | `AIza...` |
| MEDIUM | Stripe Test Keys | `sk_test_...` |
| MEDIUM | Generic API Keys | `api_key = "..."` |
| LOW | Sensitive Env Vars | `DB_PASSWORD=...` |

## Quick Start

```bash
# Scan a single repository
python cli.py scan /path/to/repo

# Scan all fleet repos
python cli.py scan-all --fleet-dir /path/to/fleet

# Scan git history
python cli.py scan-history /path/to/repo

# Scan uncommitted changes
python cli.py scan-diff /path/to/repo

# Scan staged changes
python cli.py scan-staged /path/to/repo

# JSON output
python cli.py scan /path/to/repo --format json

# Markdown output
python cli.py scan /path/to/repo --format markdown
```

## Baseline Drift Detection

```bash
# Save current state as baseline
python cli.py baseline save /path/to/repo

# Compare current scan with baseline
python cli.py baseline compare /path/to/repo

# Save to custom location
python cli.py baseline save /path/to/repo --output /tmp/baseline.json
```

## Allow-list

The scanner automatically skips:

- Test files (`tests/`, `*_test.py`, `*.spec.*`)
- Fixtures (`fixtures/`, `mocks/`, `fakes/`)
- Documentation (`README.md`, `docs/`)
- Example directories (`examples/`)
- Known placeholder values (`REPLACE_ME`, `<YOUR_KEY>`, `changeme`)

## Ignore-list

The following are always skipped:

- `.git/`, `node_modules/`, `__pycache__/`, `venv/`, `dist/`, `build/`
- Binary files (`.png`, `.jpg`, `.woff`, etc.)
- Lock files (`package-lock.json`, `yarn.lock`)

## Architecture

```
fleet/secret-scanner/
├── scanner.py          # Core scanner — pattern matching, file scanning, git integration
├── reporter.py         # Report generation — JSON, text, Markdown, diff reports
├── git_analyzer.py     # Git history analysis — commit introspection, secret tracking
├── cli.py              # CLI interface — all subcommands
├── tests/
│   └── test_secret_scanner.py  # Comprehensive test suite
├── pyproject.toml
└── README.md
```

## Requirements

- Python 3.10+
- Git (for history scanning)
- No external dependencies (stdlib only)

## Running Tests

```bash
cd fleet/secret-scanner
python -m pytest tests/ -v
```
