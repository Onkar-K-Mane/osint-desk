"""FastAPI application — HTMX pages + JSON/SSE API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, PlainTextResponse, FileResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import escape

from osint.config import APP_NAME, APP_VERSION, load_secrets, write_secret, has_key, ai_settings, public_ai_settings, save_ai_prefs
from osint.db import (
    forget_indicator,
    get_conn,
    graph_around,
    init_db,
    lookup_bundle,
    search_history,
    decompress_raw,
    active_analyst_verdict,
    analyst_history,
    add_analyst_verdict,
    verdicts_for_values,
    rebuild_fts,
    integrity_check,
    snapshot_db,
    prune,
    export_history,
    result_raw,
    row_to_result,
)
from osint.detect import extract_indicators
from osint.hunt import hunt_pack
from osint.models import AnalystVerdict, LookupTrigger
from osint.orchestrator import start_lookups, deeplink_for, compute_rollup, http_client
from osint.bus import BUS
from osint.rate_limit import RateLimiter
from osint.registry import get_registry
from osint.security import SecurityHeadersMiddleware, csrf_token
from osint.summary import render_summary
from osint import ai as ai_mod

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True


def _short_dt(value: str | None) -> str:
    if not value:
        return ""
    try:
        from datetime import datetime, timezone

        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(value)[:19]


templates.env.filters["short_dt"] = _short_dt


def create_app() -> FastAPI:
    load_secrets()
    init_db()
    app = FastAPI(title=APP_NAME, version=APP_VERSION, docs_url=None, redoc_url=None)
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.on_event("startup")
    async def _startup() -> None:
        load_secrets()
        init_db()
        http_client()

    def ctx(request: Request, **extra: Any) -> dict[str, Any]:
        registry = get_registry()
        keyed = sum(1 for s in registry.sources.values() if s.mode == "api" and s.key_env)
        have = sum(1 for s in registry.sources.values() if s.mode == "api" and s.key_env and s.key_present())
        label = ai_settings()["label"]
        return {
            "request": request,
            "app_name": APP_NAME,
            "csrf": csrf_token(request),
            "nav": extra.pop("nav", "investigate"),
            "keys_have": have,
            "keys_need": keyed,
            "ai_label": label,
            "rail_collapsed": request.cookies.get("osint_rail") == "collapsed",
            **extra,
        }

    def page(request: Request, name: str, **extra: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, name, ctx(request, **extra))

    @app.get("/", response_class=HTMLResponse)
    async def investigate(request: Request) -> HTMLResponse:
        recent = [dict(r) for r in search_history("", limit=8)]
        return page(request, "investigate.html", nav="investigate", recent=recent)

    @app.get("/bulk")
    async def bulk_page() -> RedirectResponse:
        return RedirectResponse(url="/", status_code=301)

    @app.get("/maintain", response_class=HTMLResponse)
    async def maintain_page(request: Request) -> HTMLResponse:
        info = integrity_check()
        return page(request, "maintain.html", nav="maintain", info=info)

    @app.get("/history", response_class=HTMLResponse)
    async def history_page(request: Request, q: str = "", type: str = "") -> HTMLResponse:
        rows = search_history(q, limit=80)
        items = [dict(r) for r in rows]
        if type:
            items = [it for it in items if it.get("type") == type]
        for it in items:
            av = active_analyst_verdict(int(it["id"]))
            it["analyst"] = av
        return page(request, "history.html", nav="history", items=items, q=q, ftype=type)

    @app.get("/graph", response_class=HTMLResponse)
    async def graph_page(request: Request, type: str = "", value: str = "") -> HTMLResponse:
        data = graph_around(type, value) if type and value else {"nodes": [], "edges": []}
        recent = [dict(r) for r in search_history("", limit=12)]
        return page(
            request,
            "graph.html",
            nav="graph",
            graph=data,
            gtype=type,
            gvalue=value,
            recent=recent,
        )

    @app.get("/providers", response_class=HTMLResponse)
    async def providers_page(request: Request) -> HTMLResponse:
        registry = get_registry()
        limiter = RateLimiter()
        cards = []
        for spec in registry.sources.values():
            snap = limiter.snapshot(spec)
            cards.append(
                {
                    "id": spec.id,
                    "name": spec.name,
                    "mode": spec.mode,
                    "types": sorted(t.value for t in spec.types),
                    "auto_query": spec.auto_query,
                    "has_key": spec.key_present() if spec.key_env else True,
                    "needs_key": bool(spec.key_env),
                    "key_env": spec.key_env or "",
                    "tos": spec.tos_note,
                    "quota": snap.windows,
                    "malicious_at": spec.verdict.malicious_at,
                    "suspicious_at": spec.verdict.suspicious_at,
                    "enabled": spec.enabled,
                }
            )
        return page(request, "providers.html", nav="providers", cards=cards)

    @app.get("/lookup/{lookup_id}", response_class=HTMLResponse)
    async def lookup_page(request: Request, lookup_id: str) -> HTMLResponse:
        bundle = lookup_bundle(lookup_id)
        if not bundle:
            return page(request, "investigate.html", nav="investigate", error="Lookup not found")
        registry = get_registry()
        results = []
        specs = {}
        for row in bundle["results"]:
            spec = registry.get(row["provider"])
            name = spec.name if spec else row["provider"]
            if spec:
                specs[spec.id] = spec
            results.append(row_to_result(row, name).to_public_dict())
        return page(
            request,
            "investigate.html",
            nav="investigate",
            resume_lookup=lookup_id,
            resume_indicator=dict(bundle["indicator"]),
            resume_results=results,
        )

    # --- API ---

    @app.post("/api/detect")
    async def api_detect(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        text = str(body.get("text") or "")
        inds = extract_indicators(text)
        ai_tagged = []
        if body.get("use_ai"):
            try:
                extra = await ai_mod.extract_with_ai(text)
            except ai_mod.AIError as exc:
                return JSONResponse(
                    {"error": str(exc), "indicators": [_ind_pub(i) for i in inds], "ai": ai_mod.backend_label()},
                    status_code=exc.status,
                )
            have = {i.key for i in inds}
            for e in extra:
                if e.key not in have:
                    inds.append(e)
                    ai_tagged.append(e.key)
                    have.add(e.key)
        return JSONResponse(
            {
                "indicators": [_ind_pub(i) for i in inds],
                "ai": ai_mod.backend_label() if body.get("use_ai") else None,
            }
        )

    @app.post("/api/lookups")
    async def api_lookups(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        text = str(body.get("text") or body.get("value") or "")
        selected = body.get("selected")  # optional list of values from bulk checklist
        trigger_s = str(body.get("trigger") or "manual")
        try:
            trigger = LookupTrigger(trigger_s)
        except ValueError:
            trigger = LookupTrigger.MANUAL
        force_full = bool(body.get("force_full"))
        parent = body.get("parent_lookup_id")
        extra = None
        if body.get("use_ai"):
            try:
                extra = await ai_mod.extract_with_ai(text)
            except ai_mod.AIError as exc:
                return JSONResponse({"error": str(exc), "lookups": [], "ai": ai_mod.backend_label()}, status_code=exc.status)
        if isinstance(selected, list) and selected:
            from osint.detect import classify_one

            extra = extra or []
            have = {i.key for i in extra}
            for v in selected:
                ind = classify_one(str(v))
                if ind and ind.key not in have:
                    extra.append(ind)
                    have.add(ind.key)
            text = "\n".join(str(v) for v in selected)
        created = await start_lookups(
            text,
            trigger=trigger,
            parent_lookup_id=parent,
            force_full=force_full,
            extra=extra,
        )
        if not created:
            return JSONResponse({"error": "no indicators found", "lookups": []}, status_code=400)
        pack = hunt_pack(extract_indicators("\n".join(c["value"] for c in created)))
        return JSONResponse({"lookups": created, "hunt": pack, "ai": ai_mod.backend_label() if body.get("use_ai") else None})

    @app.get("/api/lookups/{lookup_id}/stream")
    async def api_stream(lookup_id: str) -> StreamingResponse:
        async def gen():
            async for event, payload in BUS.subscribe(lookup_id):
                yield f"event: {event}\ndata: {payload}\n\n"

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/lookups/{lookup_id}")
    async def api_lookup(lookup_id: str) -> JSONResponse:
        bundle = lookup_bundle(lookup_id)
        if not bundle:
            return JSONResponse({"error": "not found"}, status_code=404)
        registry = get_registry()
        results = []
        specs = {}
        for row in bundle["results"]:
            spec = registry.get(row["provider"])
            name = spec.name if spec else row["provider"]
            if spec:
                specs[spec.id] = spec
            results.append(row_to_result(row, name).to_public_dict())
        return JSONResponse(
            {
                "lookup": dict(bundle["lookup"]),
                "indicator": dict(bundle["indicator"]),
                "results": results,
                "children": [dict(c) for c in bundle["children"]],
                "analyst": active_analyst_verdict(int(bundle["indicator"]["id"])),
                "analyst_history": analyst_history(int(bundle["indicator"]["id"])),
            }
        )

    @app.get("/api/lookups/{lookup_id}/summary")
    async def api_summary(
        lookup_id: str, format: str = "md", raw: int = 0, tlp: str = "CLEAR", extra: str = ""
    ):
        extra_ids = [x.strip() for x in extra.split(",") if x.strip()]
        text = render_summary(
            lookup_id,
            fmt=format,
            raw_indicators=bool(raw),
            extra_ids=extra_ids,
            tlp=tlp,
        )
        if format == "text":
            return PlainTextResponse(text)
        return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")

    @app.get("/api/summary")
    async def api_summary_batch(
        ids: str = "", format: str = "md", raw: int = 0, tlp: str = "CLEAR"
    ):
        lookup_ids = [x.strip() for x in ids.split(",") if x.strip()]
        if not lookup_ids:
            return PlainTextResponse("no lookups", status_code=400)
        text = render_summary(
            lookup_ids[0],
            fmt=format,
            raw_indicators=bool(raw),
            extra_ids=lookup_ids[1:],
            tlp=tlp,
        )
        if format == "text":
            return PlainTextResponse(text)
        return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")

    @app.get("/api/quota")
    async def api_quota() -> JSONResponse:
        registry = get_registry()
        limiter = RateLimiter()
        out = []
        for spec in registry.sources.values():
            if not spec.limits:
                continue
            snap = limiter.snapshot(spec)
            tight = False
            for w, q in snap.windows.items():
                lim = q.get("limit") or 0
                used = q.get("used") or 0
                if lim and used / lim >= 0.5:
                    tight = True
            out.append(
                {
                    "id": spec.id,
                    "name": spec.name,
                    "windows": snap.windows,
                    "reason": snap.reason,
                    "blocked": snap.blocked,
                    "reserved": snap.reserved,
                    "tight": tight or snap.blocked or snap.reserved,
                }
            )
        return JSONResponse({"providers": out})

    @app.post("/api/hunt")
    async def api_hunt(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        text = str(body.get("text") or "")
        values = body.get("values")
        from osint.detect import classify_one

        inds = extract_indicators(text) if text else []
        if isinstance(values, list):
            have = {i.key for i in inds}
            for v in values:
                ind = classify_one(str(v))
                if ind and ind.key not in have:
                    inds.append(ind)
                    have.add(ind.key)
        return JSONResponse(hunt_pack(inds))

    @app.post("/api/lookups/{lookup_id}/refresh")
    async def api_refresh(lookup_id: str, request: Request) -> JSONResponse:
        bundle = lookup_bundle(lookup_id)
        if not bundle:
            return JSONResponse({"error": "not found"}, status_code=404)
        body = await _json_or_form(request)
        provider = body.get("provider") or None
        ind = bundle["indicator"]
        text = ind["value"]
        # Re-detect so we get a proper Indicator
        created = await start_lookups(
            text,
            trigger=LookupTrigger.REFRESH,
            parent_lookup_id=lookup_id,
            force=True,
            only_provider=provider,
        )
        return JSONResponse({"lookups": created})

    @app.get("/api/search")
    async def api_search(q: str = "", type: str = "") -> JSONResponse:
        rows = search_history(q, limit=80)
        items = [dict(r) for r in rows]
        if type:
            items = [it for it in items if it.get("type") == type]
        for it in items:
            av = active_analyst_verdict(int(it["id"]))
            if av:
                it["analyst"] = av
        return JSONResponse({"items": items})

    @app.get("/api/graph")
    async def api_graph(type: str = "", value: str = "") -> JSONResponse:
        return JSONResponse(graph_around(type, value))

    @app.get("/api/indicators/{indicator_id}/history")
    async def api_ind_history(indicator_id: int) -> JSONResponse:
        c = get_conn()
        lookups = c.execute(
            "SELECT * FROM lookups WHERE indicator_id=? ORDER BY started_at DESC",
            (indicator_id,),
        ).fetchall()
        return JSONResponse({"lookups": [dict(r) for r in lookups]})

    @app.delete("/api/indicators/{indicator_id}")
    async def api_forget(indicator_id: int) -> JSONResponse:
        forget_indicator(indicator_id)
        return JSONResponse({"ok": True})

    @app.get("/api/providers")
    async def api_providers() -> JSONResponse:
        registry = get_registry()
        limiter = RateLimiter()
        out = []
        for spec in registry.sources.values():
            snap = limiter.snapshot(spec)
            out.append(
                {
                    "id": spec.id,
                    "name": spec.name,
                    "mode": spec.mode,
                    "types": [t.value for t in spec.types],
                    "has_key": spec.key_present() if spec.key_env else True,
                    "needs_key": bool(spec.key_env),
                    "auto_query": spec.auto_query,
                    "quota": snap.windows,
                    "tos_note": spec.tos_note,
                    "verdict": {
                        "style": spec.verdict.style,
                        "malicious_at": spec.verdict.malicious_at,
                        "suspicious_at": spec.verdict.suspicious_at,
                    },
                }
            )
        return JSONResponse({"providers": out})

    @app.put("/api/providers")
    async def api_providers_put(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        # thresholds stored in provider_settings; keys go to secrets.env
        pid = str(body.get("id") or "")
        spec = get_registry().get(pid)
        if not spec:
            return JSONResponse({"error": "unknown provider"}, status_code=404)
        if "key" in body and spec.key_env:
            write_secret(spec.key_env, str(body.get("key") or ""))
        c = get_conn()
        enabled = body.get("enabled")
        auto = body.get("auto_query")
        mal = body.get("malicious_at")
        sus = body.get("suspicious_at")
        c.execute(
            """
            INSERT INTO provider_settings(provider, enabled, auto_query, malicious_at, suspicious_at)
            VALUES (?,?,?,?,?)
            ON CONFLICT(provider) DO UPDATE SET
              enabled=COALESCE(excluded.enabled, enabled),
              auto_query=COALESCE(excluded.auto_query, auto_query),
              malicious_at=COALESCE(excluded.malicious_at, malicious_at),
              suspicious_at=COALESCE(excluded.suspicious_at, suspicious_at)
            """,
            (
                pid,
                None if enabled is None else int(bool(enabled)),
                None if auto is None else int(bool(auto)),
                None if mal is None else float(mal),
                None if sus is None else float(sus),
            ),
        )
        c.commit()
        if mal is not None:
            spec.verdict.malicious_at = float(mal)
        if sus is not None:
            spec.verdict.suspicious_at = float(sus)
        return JSONResponse({"ok": True, "has_key": spec.key_present() if spec.key_env else True})

    @app.get("/ai", response_class=HTMLResponse)
    async def ai_page(request: Request) -> HTMLResponse:
        return page(request, "ai.html", nav="ai", ai=public_ai_settings())

    @app.get("/api/ai/settings")
    async def api_ai_settings() -> JSONResponse:
        return JSONResponse(public_ai_settings())

    @app.post("/api/ai/settings")
    async def api_ai_settings_save(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        prefs = {}
        current = public_ai_settings()
        base = str(body.get("base_url") or current["base_url"]).strip().rstrip("/")
        model = str(body.get("model") or current["model"]).strip()
        prompt = str(body.get("system_prompt") if body.get("system_prompt") is not None else current["system_prompt"])
        try:
            temperature = float(body.get("temperature") if body.get("temperature") not in (None, "") else current["temperature"])
        except (TypeError, ValueError):
            return JSONResponse({"error": "temperature must be a number"}, status_code=400)
        try:
            max_tokens = int(float(body.get("max_tokens") if body.get("max_tokens") not in (None, "") else current["max_tokens"]))
        except (TypeError, ValueError):
            return JSONResponse({"error": "max tokens must be a number"}, status_code=400)
        if not base.startswith("http://") and not base.startswith("https://"):
            return JSONResponse({"error": "base URL must start with http:// or https://"}, status_code=400)
        if not model:
            return JSONResponse({"error": "model is required"}, status_code=400)
        temperature = max(0.0, min(temperature, 2.0))
        max_tokens = max(64, min(max_tokens, 4000))
        prefs = {
            "base_url": base,
            "model": model,
            "system_prompt": prompt.strip(),
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        save_ai_prefs(prefs)
        if "api_key" in body and str(body.get("api_key") or "").strip():
            write_secret("AI_API_KEY", str(body.get("api_key")).strip())
        elif body.get("clear_key"):
            write_secret("AI_API_KEY", "")
        return JSONResponse(public_ai_settings())

    @app.post("/api/ai/test")
    async def api_ai_test() -> JSONResponse:
        try:
            text = await ai_mod.ping()
        except ai_mod.AIError as exc:
            return JSONResponse({"error": str(exc), "ai": ai_mod.backend_label()}, status_code=exc.status)
        return JSONResponse({"text": text, "ai": ai_mod.backend_label()})

    @app.get("/api/ai/status")
    async def api_ai_status() -> JSONResponse:
        return JSONResponse(ai_mod.backend_label())

    @app.post("/api/ai/assess")
    async def api_ai_assess(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        lookup_id = str(body.get("lookup_id") or "")
        pasted = str(body.get("pasted") or "")
        try:
            text = await ai_mod.assess(lookup_id, pasted)
        except ai_mod.AIError as exc:
            return JSONResponse({"error": str(exc), "ai": ai_mod.backend_label()}, status_code=exc.status)
        return JSONResponse({"text": text, "ai": ai_mod.backend_label()})

    @app.post("/api/ai/ticket")
    async def api_ai_ticket(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        lookup_id = str(body.get("lookup_id") or "")
        bundle = lookup_bundle(lookup_id)
        analyst = None
        if bundle:
            analyst = active_analyst_verdict(int(bundle["indicator"]["id"]))
        try:
            text = await ai_mod.draft_ticket(lookup_id, analyst)
        except ai_mod.AIError as exc:
            return JSONResponse({"error": str(exc), "ai": ai_mod.backend_label()}, status_code=exc.status)
        return JSONResponse({"text": text, "ai": ai_mod.backend_label()})

    @app.post("/api/ai/explain")
    async def api_ai_explain(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        rid = body.get("result_id")
        provider = str(body.get("provider") or "")
        raw = ""
        if rid not in (None, "", 0, "0", "null"):
            try:
                raw = result_raw(int(rid)) or ""
            except (TypeError, ValueError):
                raw = ""
        if not raw:
            raw = str(body.get("raw") or "")
        if not raw:
            return JSONResponse({"error": "no raw response"}, status_code=404)
        try:
            text = await ai_mod.explain_raw(provider, raw)
        except ai_mod.AIError as exc:
            return JSONResponse({"error": str(exc), "ai": ai_mod.backend_label()}, status_code=exc.status)
        return JSONResponse({"text": text, "ai": ai_mod.backend_label()})

    @app.post("/api/ai/explain-summary")
    async def api_ai_explain_summary(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        ids = body.get("lookup_ids") or []
        if isinstance(ids, str):
            ids = [x for x in ids.split(",") if x]
        ids = [str(x) for x in ids if str(x).strip()]
        if not ids and body.get("lookup_id"):
            ids = [str(body.get("lookup_id"))]
        try:
            text = await ai_mod.explain_summary(ids)
        except ai_mod.AIError as exc:
            return JSONResponse({"error": str(exc), "ai": ai_mod.backend_label()}, status_code=exc.status)
        return JSONResponse({"text": text, "ai": ai_mod.backend_label()})

    @app.get("/api/results/{result_id}/raw")
    async def api_result_raw(result_id: int) -> JSONResponse:
        raw = result_raw(result_id)
        if raw is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse({"raw": raw})

    @app.get("/api/indicators/{indicator_id}/verdict")
    async def api_get_verdict(indicator_id: int) -> JSONResponse:
        return JSONResponse(
            {
                "active": active_analyst_verdict(indicator_id),
                "history": analyst_history(indicator_id),
            }
        )

    @app.post("/api/indicators/{indicator_id}/verdict")
    async def api_set_verdict(indicator_id: int, request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        v = str(body.get("verdict") or "")
        try:
            AnalystVerdict(v)
        except ValueError:
            return JSONResponse({"error": "verdict must be escalated, false_positive, benign, or monitoring"}, status_code=400)
        note = str(body.get("note") or "")[:2000]
        row = add_analyst_verdict(indicator_id, v, note)
        return JSONResponse({"ok": True, "active": row, "history": analyst_history(indicator_id)})

    @app.get("/api/pivots/verdicts")
    async def api_pivot_verdicts(q: str = "") -> JSONResponse:
        # q = "ip:1.2.3.4,domain:evil.com"
        pairs = []
        for part in q.split(","):
            if ":" not in part:
                continue
            t, _, v = part.partition(":")
            pairs.append((t.strip(), v.strip()))
        return JSONResponse({"verdicts": verdicts_for_values(pairs)})

    @app.post("/api/maintain/integrity")
    async def api_integrity() -> JSONResponse:
        return JSONResponse(integrity_check())

    @app.post("/api/maintain/reindex")
    async def api_reindex() -> JSONResponse:
        return JSONResponse(rebuild_fts())

    @app.post("/api/maintain/snapshot")
    async def api_snapshot() -> JSONResponse:
        return JSONResponse(snapshot_db("manual"))

    @app.post("/api/maintain/prune")
    async def api_prune(request: Request) -> JSONResponse:
        body = await _json_or_form(request)
        return JSONResponse(
            prune(
                older_than_days=int(body.get("days") or 30),
                strip_raw=bool(body.get("strip_raw")),
                delete_lookups=bool(body.get("delete_lookups")),
                dry_run=body.get("dry_run", True) not in {False, "0", "false", 0},
            )
        )

    @app.get("/api/export")
    async def api_export(fmt: str = "json"):
        body = export_history("csv" if fmt == "csv" else "json")
        if fmt == "csv":
            return PlainTextResponse(body, media_type="text/csv; charset=utf-8")
        return PlainTextResponse(body, media_type="application/json; charset=utf-8")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"ok": True, "name": APP_NAME, "version": APP_VERSION})

    @app.get("/download.zip")
    async def download_zip() -> Response:
        """Project snapshot for Colab / local — never includes secrets or history."""
        import io
        import zipfile

        root = Path(__file__).resolve().parent.parent
        buf = io.BytesIO()
        skip_dirs = {"data/app", "__pycache__", ".git", "node_modules", "screenshots", "artifacts"}
        skip_names = {".env", "secrets.env", "session.secret", "osint.sqlite3"}
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel in [
                "requirements.txt",
                "run.py",
                "run_local.py",
                "sources.yaml",
                "notebooks/OSINT_Desk_Colab.ipynb",
            ]:
                p = root / rel
                if p.is_file():
                    zf.write(p, rel)
            for dirpath, dirnames, filenames in os.walk(root / "osint"):
                dirnames[:] = [d for d in dirnames if d != "__pycache__"]
                for name in filenames:
                    if name in skip_names or name.endswith(".pyc"):
                        continue
                    full = Path(dirpath) / name
                    arc = full.relative_to(root).as_posix()
                    if any(part in arc for part in skip_dirs):
                        continue
                    zf.write(full, arc)
            for dirpath, dirnames, filenames in os.walk(root / "tests"):
                dirnames[:] = [d for d in dirnames if d != "__pycache__"]
                for name in filenames:
                    full = Path(dirpath) / name
                    zf.write(full, full.relative_to(root).as_posix())
        return Response(
            buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=osint-desk.zip"},
        )

    @app.get("/favicon.svg")
    async def favicon_svg():
        return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")

    @app.get("/favicon.ico")
    async def favicon_ico():
        return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")

    return app


def _ind_pub(i) -> dict[str, Any]:
    return {
        "type": i.type.value,
        "value": i.value,
        "original": i.original,
        "hash_algo": i.hash_algo,
        "origin": getattr(i, "origin", "regex"),
        "email_domain": i.email_domain,
        "url_host": i.url_host,
    }


async def _json_or_form(request: Request) -> dict:
    ctype = request.headers.get("content-type", "")
    if "application/json" in ctype:
        try:
            data = await request.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    try:
        form = await request.form()
        return {k: form.get(k) for k in form.keys()}
    except Exception:
        return {}


app = create_app()
