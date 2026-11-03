# OSINT Desk: handoff context (v0.5.0)

Source of truth for architecture and invariants. Keep it accurate when behavior changes.

## Purpose
Local, single-user SOC triage. Analyst pastes an alert or one IOC; the app extracts and
classifies indicators, fans out to sources, streams one attributed card per source over
SSE, and shows a short decision summary. The analyst decides; there is no blended score.

## Architecture
FastAPI (single process) + SQLite/FTS5 trigram + Jinja2 + vanilla JS over SSE. No build
step, no frontend framework, no accounts, no Redis.

| Area | Files |
|---|---|
| Pages + HTTP API | `osint/app.py` (`/`, `/history`, `/graph`, `/providers`, `/ai`, `/maintain`, `/lookup/{id}`, `/healthz`, `/download.zip`, `/api/*`) |
| Detection | `osint/detect.py` (`classify_one`, `extract_indicators`), `defang.py`, `psl.py`, `hunt.py` |
| Policy | `osint/policy.py` (reserved-IP hard block) |
| Fan-out | `osint/orchestrator.py`, `registry.py`, `bus.py`, `rate_limit.py`, `ttl.py` |
| Verdicts | `osint/verdict.py` (per-source score to verdict), `summary.py` (decision card) |
| Providers | `osint/providers/<id>.py` + `sources.yaml` |
| AI | `osint/ai.py` (chat, extract, assess, ticket, explain) |
| Storage | `osint/db.py`; secrets in `secrets.env` |
| Security | `osint/security.py` (Host/Origin checks, CSRF, headers, CSP) |
| UI | `osint/templates/`, `osint/static/js/app.js`, `osint/static/css/app.css` |

## Sources
32 entries in `sources.yaml`: 20 `api`, 2 `local`, 10 `link_only`. Adding an API source =
yaml entry + provider module + tests; link-only = yaml entry only. Cache is ~60 min per
source unless overridden in `sources.yaml`.

## Invariants (see CLAUDE.md "HARD RULES")
No blended verdict; link-only sources stay links; reserved IPs never leave the machine;
AI output is untrusted; IPv6 not extracted from free text (lone IPv6 accepted via the
single-IOC fast path in `extract_indicators`); secrets never in SQLite/yaml; CSRF + security
headers on all `/api/` writes; not for the public internet without access control.

## Runtime defaults
- `DEFAULT_HOST` = `127.0.0.1` (`osint/config.py`). `run_local.py` also pins loopback.
  `run.py` and `startup.sh` explicitly bind `0.0.0.0` for Colab/preview.
- `OSINT_STRICT_HOSTS` defaults to off (any Host header accepted). Turn it on when bound
  beyond loopback behind a known hostname.
- CSP: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; ...`.
  No third-party scripts are loaded.

## Changelog of notable fixes (this branch)
- IPv6 free-text extraction removed (was violating hard rule 5); tests added.
- CSP no longer allows `https://grok.com`; the `grok.com` script tag was removed from
  `base.html`.
- Default bind host changed from `0.0.0.0` to `127.0.0.1`; Colab entry points opt in.

## Known open items
- `OSINT_STRICT_HOSTS` off by default.
- Orchestrator User-Agent still says `OSINT-Desk/0.4`.
- Duplicate rollup function in `verdict.py`; event-bus buffers never freed.
- No JS/UI tests.
