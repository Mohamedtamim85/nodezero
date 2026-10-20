# nodezero-lite

A local, authorization-gated AI-assisted penetration testing console.

This project is inspired by platforms like Horizon3.ai's NodeZero — an
"autonomous pentesting" tool that continuously finds and validates exploitable
attack paths — but scoped down to something you can run entirely on your own
machine, against your own authorized targets, using non-destructive
reconnaissance techniques plus an AI layer that turns raw findings into a
readable risk report.

**This is not a clone of NodeZero.** It does not do exploitation, lateral
movement, credential cracking, or attack-path graphing. It automates the
boring, safe, read-only parts of early-stage recon (port discovery, banner
grabs, TLS/cert checks, security headers, DNS) and uses an LLM only to
*summarize findings a human already has in front of them* — never to decide
what to scan next.

## Why it's built this way

Every run requires an **engagement authorization file**: a signed, local
record of who authorized testing, what scope they authorized, and for how
long. No module can touch a target until:

1. the operator has explicitly typed/accepted an authorization attestation,
2. the engagement time window is currently active, and
3. the specific target is inside the `allow` list and not in the `deny` list.

These checks live in `nodezero/modules/base.py` — the one place every module
calls through — so there's no code path that reaches a socket without first
passing scope + authorization. See `tests/test_module_scope_gate.py` for the
enforcement tests.

**Only use this against systems you own or have explicit written permission
to test.** Scanning systems without authorization is illegal in most
jurisdictions (e.g. the US Computer Fraud and Abuse Act) regardless of intent.

## Install

```bash
pip install -e ".[dev]"
# optional, for AI-generated executive summaries:
pip install -e ".[ai]"
export ANTHROPIC_API_KEY=sk-...
```

## Usage

```bash
# 1. Create an engagement authorization (interactive)
nodezero init-engagement engagement.json

# 2. See what modules are available
nodezero list-modules

# 3. Run an assessment (every target is checked against engagement.json's scope)
nodezero run engagement.json --target 10.0.5.10 --target 10.0.5.0/28 \
    --format markdown --output report.md

# Without ANTHROPIC_API_KEY set, or with --no-ai, reports use a deterministic
# offline summary instead of a model-generated one.
```

## Modules (all non-intrusive, read-only)

| Module | What it does |
|---|---|
| `port_scan` | TCP connect scan of common ports + best-effort banner read |
| `http_headers` | Fetches `/` and checks for missing security headers (HSTS, CSP, etc.) |
| `tls_check` | Inspects the TLS handshake/certificate on port 443 |
| `dns_recon` | Resolves A/AAAA and reverse DNS via the system resolver |

There are no exploitation or brute-force modules, and none are planned. If
you need active exploitation/validation as part of an authorized engagement,
pair this tool's recon output with a dedicated, licensed platform (Metasploit,
Burp Suite Pro, Horizon3.ai NodeZero, etc.) operated under the same signed
authorization.

## Architecture

```
nodezero/
  authorization.py   # engagement sign-off: who/what/when, must be accepted
  scope.py           # allow/deny target matching, deny always wins
  audit.py            # append-only JSONL log of every scope check + module run
  findings.py        # shared Finding/Severity data model
  engine.py           # orchestrator: validates auth once, runs modules, summarizes
  modules/
    base.py           # enforces authorization+scope before run_one() is called
    port_scan.py, http_headers.py, tls_check.py, dns_recon.py
  ai/
    advisor.py         # HeuristicAdvisor (offline) / ClaudeAdvisor (optional, read-only summarizer)
  reporting/
    report.py          # Markdown / JSON report rendering
  cli.py                # click-based CLI
```

## Testing

```bash
pytest -q
```
