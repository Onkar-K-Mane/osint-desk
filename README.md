# OSINT Desk

Local, single-user SOC desk. Paste an alert or one IOC (IP, domain, URL, hash, email).
The app extracts indicators, queries up to 32 sources in parallel and shows **one card
per source** plus a short decision summary. It never blends sources into one score.

## Run

```bash
pip install -r requirements.txt
python3 run_local.py          # http://127.0.0.1:8080
pytest -q

# optional browser tests (palette, streaming, export, restart repaint, phone layout)
pip install -r requirements-dev.txt && python3 -m playwright install chromium
```

Colab / preview: `python3 run.py` or `bash startup.sh` bind `0.0.0.0:8080`.
`osint.config.DEFAULT_HOST` is loopback (`127.0.0.1`); only those two entry points opt in
to all interfaces. **Not safe for the public internet without access control.**

## Using the desk

| Key | Action |
|---|---|
| `/` | focus the input (or history search) |
| `Ctrl/Cmd` + `Enter` | run the lookup |
| `Ctrl/Cmd` + `K` | command palette: run an IOC, search history, jump to a page, export |
| `?` | shortcut help |
| `[` | collapse / expand navigation |
| `1`..`6` | filter extracted IOCs by type |
| `Esc` | close a dialog or modal |

Also: live type chips while you paste, skeleton cards that hold each source's place as it
streams in, a compact/comfortable density toggle, **Report** download (Markdown or JSON,
always defanged, one section per source, no blended score), and a composer draft that
survives a reload. Theme and density persist and apply before first paint.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OSINT_HOST` | `127.0.0.1` (`0.0.0.0` via `run.py`/`startup.sh`) | bind address |
| `OSINT_PORT` | `8080` | port |
| `OSINT_DATA_DIR` | `data/app` | SQLite, `secrets.env`, `session.secret`, `ai.json` |
| `OSINT_STRICT_HOSTS` | `1` (`0` via `run.py`/`startup.sh`/Colab) | `1` accepts only localhost and known preview suffixes; `0` accepts any Host |

API keys live in `<data dir>/secrets.env` (never in SQLite or `sources.yaml`).

## Sources

`sources.yaml` lists 32 entries: 20 API, 2 local, 10 link-only. Link-only sources
(ANY.RUN, HIBP, Talos, Censys, Shodan, X-Force, Spamhaus, MxToolbox, URLVoid, HE BGP) are
links, never API calls. Reserved IPs (private, loopback, link-local, multicast, reserved)
are blocked with a policy card and no external request.

## Behavior notes

- Defanged input is accepted; display and copy are defanged.
- IPv6 is **not** extracted from free text; a lone pasted IPv6 can still be looked up.
- Optional AI (any OpenAI-compatible endpoint) explains data; its output is untrusted and
  AI-extracted IOCs count only after `classify_one` accepts them.
- Security: CSRF on every `/api/` POST/PUT/DELETE, nosniff, `X-Frame-Options: SAMEORIGIN`,
  `no-referrer`, and a self-only CSP (`script-src 'self'`, no third-party scripts).

See `OSINT_DESK_CONTEXT.md` for the architecture handoff and `CLAUDE.md` for contributor
rules.
