# CLAUDE.md — OSINT Desk (v0.5.0)

Local, single-user SOC desk. The analyst pastes an alert or one IOC. The app extracts
indicators, queries up to 32 sources in parallel, and shows one card per source plus a
short decision summary. It never blends sources into one score.

Repo: https://github.com/Onkar-K-Mane/osint-desk
Full handoff: `OSINT_DESK_CONTEXT.md` (source of truth, read it before big changes).

## Your role
You may read, create, edit, rename, and delete any file in this repo, run any shell
command, install dependencies, and restructure the project. Work like a senior
engineer, SOC analyst, and UI designer. Prefer small, reviewable commits. Explain what
you changed and why at the end of every task.

## Run / test
```bash
pip install -r requirements.txt
python3 run_local.py          # 127.0.0.1:8080
pytest -q                     # run before and after every change
```
Colab: `run.py` or `startup.sh` bind 0.0.0.0:8080. Both call `uvicorn osint.app:app`.

Env: `OSINT_HOST`, `OSINT_PORT` (8080), `OSINT_DATA_DIR` (default `data/app`: SQLite,
`secrets.env`, `session.secret`, `ai.json`), `OSINT_STRICT_HOSTS`.

## Stack
FastAPI (one process), SQLite + FTS5 trigram, Jinja2, vanilla JS (`osint/static/js/app.js`)
over Server-Sent Events, CSS variables (dark default, light toggle). No React, no Redis,
no accounts, no build step. Do not introduce a frontend framework or bundler.
Cache is ~60 min per source (overridable in `sources.yaml`).

## Code map
- `osint/app.py` pages + HTTP API
- `osint/detect.py` `classify_one`, `extract_indicators`
- `osint/defang.py` refang / defang
- `osint/policy.py` reserved-IP decision
- `osint/orchestrator.py` fan-out, cache, children, rollup, SSE
- `osint/registry.py` loads `sources.yaml`
- `osint/providers/` one module per API source
- `osint/verdict.py` score to verdict
- `osint/ai.py` chat, extract, assess, ticket, explain
- `osint/db.py` schema, FTS, verdicts, raw bodies
- `osint/summary.py` server-side summary
- `osint/static/js/app.js`, `osint/static/css/app.css`, `osint/templates/`
- `tests/` detect, policy, summary, verdict, security, hunt

## Pages
`/` Investigate (`/bulk` 301s here), `/history`, `/graph`, `/providers`, `/ai`,
`/maintain`, `/lookup/{id}`, `/healthz`, `/download.zip`.

## HARD RULES (do not change, even when refactoring or redesigning)
1. **No blended verdict.** Every claim is attributed to the source that produced it.
   "Consensus" = two sources share a tag or malware family, not a merged score.
2. **Link-only sources stay links** (ANY.RUN, HIBP, Talos, Censys, Shodan, X-Force,
   Spamhaus, MxToolbox, URLVoid, HE BGP). They are not cards and are never called as APIs.
3. **Reserved IPs are a hard block** (private, loopback, link-local, multicast,
   reserved). No external request is ever made. Show a policy card.
4. **AI output is untrusted.** AI-extracted IOCs count only after `classify_one`
   accepts them (tag `origin=ai`). No silent fallback between AI backends.
5. **IPv6 is not extracted from free text.** A lone pasted IPv6 can still be looked up.
6. **Secrets never go in SQLite or `sources.yaml`.** Keys live in `secrets.env`. Never
   print, log, commit, or read `secrets.env` or `session.secret`.
7. **Extracted tray** appears only when more than one IOC is found.
8. **Clean / no-detections is its own outcome filter**, separate from info.
9. **The summary is a short decision card** (stance, why, agreement, few facts), not a
   dump of every field.
10. **Flipping a card or summary** means "explain this raw data with the configured AI",
    never a static playbook.
11. Defanged input is accepted; display and copy are defanged.
12. Every POST/PUT/DELETE under `/api/` requires `X-CSRF-Token`. Keep CSRF and the
    security headers (nosniff, X-Frame-Options SAMEORIGIN, no-referrer, self CSP).
13. Not safe for the public internet without access control. Do not add auth silently;
    if asked, treat it as a design decision and document it.

If a task requires breaking a hard rule, stop and ask first.

## Design direction (SOC-friendly UI)
- Analyst-first: dense but readable, keyboard-driven (`/` focus search, Enter submit,
  Escape closes modal, `[` collapses rail). Keep these shortcuts working.
- Dark by default, light toggle. Use CSS variables for all colors.
- Verdict colors must never be the only signal: pair with icon/text (WCAG AA contrast,
  visible focus rings, ARIA labels, `prefers-reduced-motion`).
- Responsive: usable at laptop and tablet widths; tables and long values scroll
  inside their own container, never the page body.
- Performance: no heavy dependencies, no layout shift as SSE cards stream in.
- Outcome filters: malicious, suspicious, info, clean / no detections, error.

## Conventions
- Python: type hints, small functions, no new dependencies unless needed (update
  `requirements.txt`). New API source = `sources.yaml` entry + `osint/providers/<id>.py`
  + tests. Link-only source = `sources.yaml` entry only.
- Add or update tests for any change in detection, policy, verdict, summary, security.
- Keep `OSINT_DESK_CONTEXT.md` and `README.md` accurate when behavior changes; bump the
  version in `/healthz` only when asked.
- Work on a branch (e.g. `claude/<task>`), commit in small steps with clear messages.
  Never force-push.
- Do not commit `data/`, `*.env`, `session.secret`, or SQLite files.

## Workflow for each task
1. Read the relevant files and `OSINT_DESK_CONTEXT.md`.
2. Briefly state a plan.
3. Make the change, run `pytest -q`, start the app and hit `/healthz`.
4. Summarize: files changed, why, anything that needs the user's decision.