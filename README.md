# reconpipe

Full passive recon pipeline for web bug-bounty targets. One command, one report.

## Stages

1. **Subdomains** — enumerate via crt.sh (certificate transparency, passive)
2. **Live probe** — find responding hosts (plain GET, no scanning)
3. **JS hunt** — [jshunter](https://github.com/sourabhbeni/jshunter) scans each live host's JavaScript for leaked secrets and hidden endpoints
4. **Wayback harvest** — pull historical URLs from the Wayback Machine CDX API, surface ones with interesting parameters (`?id=`, `?redirect=`, …) or sensitive paths (`/api/`, `/admin`, …)
5. **Report** — unified text/JSON report plus a `probe_targets` list ready to feed into [aegis](https://github.com/sourabhbeni/aegis) (SQLi/XSS) or manual testing

## Install

```bash
pip install -r requirements.txt
# jshunter powers stage 3 (skipped gracefully if absent):
pip install git+https://github.com/sourabhbeni/jshunter.git
```

## Usage

```bash
python -m reconpipe.cli example.com --i-am-authorized
python -m reconpipe.cli example.com --i-am-authorized --json -o recon.json
```

The `--i-am-authorized` flag is required. Only recon targets in your bug-bounty scope (or your own assets/labs). Passive recon still counts as testing under most program policies — read the scope first.

## Scope & ethics

All stages are plain HTTP GETs against public endpoints. No exploitation, no auth bypass, no DoS. Findings are leads, not vulnerabilities — verify manually before reporting.

## Tests

```bash
python -m pytest tests/ -q
```
