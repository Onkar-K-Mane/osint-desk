"""Lookup orchestrator: cache, quota, fetch, parse, persist, stream."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from osint.bus import BUS
from osint.db import (
    compress_raw,
    create_lookup,
    finish_lookup,
    get_conn,
    init_db,
    latest_cached,
    link_cached_result,
    persist_result,
    row_to_result,
    upsert_indicator,
)
from osint.detect import extract_indicators
from osint.models import (
    Fact,
    Indicator,
    IndicatorType,
    LookupTrigger,
    PolicyDecision,
    ProviderResult,
    ResultStatus,
    Rollup,
    Verdict,
    utcnow,
)
from osint.policy import evaluate
from osint.providers.base import Ctx, expires_for, get_provider, status_from_http
from osint.rate_limit import RateLimiter
from osint.registry import SourceSpec, get_registry
from osint.verdict import map_verdict

# user-initiated > pivot click > auto child > manual refresh
_PRIORITY = {
    LookupTrigger.MANUAL: 0,
    LookupTrigger.PIVOT: 1,
    LookupTrigger.AUTO_CHILD: 2,
    LookupTrigger.REFRESH: 3,
}

_inflight: dict[tuple[str, str, str], asyncio.Future] = {}
_inflight_lock = asyncio.Lock()
_semaphores: dict[str, asyncio.Semaphore] = {}
_http: httpx.AsyncClient | None = None
_limiter = RateLimiter()


def http_client() -> httpx.AsyncClient:
    global _http
    if _http is None or _http.is_closed:
        _http = httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(20.0),
            headers={"User-Agent": "OSINT-Desk/0.4 (personal-lab; local)"},
        )
    return _http


def _sem(provider_id: str) -> asyncio.Semaphore:
    if provider_id not in _semaphores:
        _semaphores[provider_id] = asyncio.Semaphore(2)
    return _semaphores[provider_id]


def deeplink_for(spec: SourceSpec, ind: Indicator) -> str | None:
    tmpl = spec.deeplink.get(ind.type.value)
    if not tmpl:
        return None
    host = ind.url_host or ind.email_domain or ""
    from osint.detect import url_sha256

    return tmpl.format(
        value=ind.value,
        value_urlenc=quote(ind.value, safe=""),
        url_sha256=url_sha256(ind.value) if ind.type == IndicatorType.URL else "",
        host=host,
    )


def compute_rollup(results: list[ProviderResult], specs: dict[str, SourceSpec]) -> Rollup:
    r = Rollup()
    tag_hits: dict[str, set[str]] = {}
    for item in results:
        spec = specs.get(item.provider)
        mode = spec.mode if spec else "api"
        if mode == "link_only" or item.skip_reason == "link_only":
            r.link_only += 1
            continue
        st = item.status
        if st == ResultStatus.OK:
            r.answered += 1
            v = item.verdict
            if v == Verdict.MALICIOUS:
                r.malicious += 1
            elif v == Verdict.SUSPICIOUS:
                r.suspicious += 1
            elif v == Verdict.BENIGN:
                r.benign += 1
            elif v == Verdict.INFO:
                r.info += 1
            else:
                # reputation "no detections" counts as info in the banner
                if item.style == "reputation":
                    r.info += 1
                else:
                    r.unknown += 1
            for t in item.tags:
                tl = t.lower().strip()
                if tl:
                    tag_hits.setdefault(tl, set()).add(item.provider)
        elif st == ResultStatus.NOT_FOUND:
            r.not_found += 1
        elif st == ResultStatus.RATE_LIMITED:
            r.rate_limited += 1
            r.errors += 1
        elif st == ResultStatus.NO_KEY:
            r.no_key += 1
        elif st == ResultStatus.SKIPPED:
            r.skipped += 1
        elif st == ResultStatus.ERROR:
            r.errors += 1
    r.disagreement = r.malicious > 0 and r.benign > 0
    r.consensus = [f"{t} ({len(ps)} sources)" for t, ps in tag_hits.items() if len(ps) >= 2][:8]
    n = sum(1 for i in results if i.skip_reason != "link_only")
    bits = [f"{r.malicious + r.suspicious + r.benign + r.info + r.not_found} of {max(n, 1)} sources checked"]
    if r.rate_limited:
        bits.append(f"{r.rate_limited} rate-limited")
    if r.no_key:
        bits.append(f"{r.no_key} missing key")
    if r.skipped:
        bits.append(f"{r.skipped} skipped")
    if r.errors:
        bits.append(f"{r.errors} error")
    if r.link_only:
        bits.append(f"{r.link_only} link-only")
    r.coverage = ", ".join(bits) + "."
    flags = []
    if r.disagreement:
        flags.append("sources disagree (malicious + benign)")
    r.context_flags = flags
    r.total_api = n
    return r


def _policy_card(ind: Indicator, policy: PolicyDecision) -> ProviderResult:
    return ProviderResult(
        provider="policy",
        provider_name="Local policy",
        status=ResultStatus.OK,
        verdict=Verdict.INFO,
        summary=policy.local_summary or policy.reason or "Local-only",
        facts=[Fact("Reason", policy.reason or "blocked")],
        tags=policy.tags,
        skip_reason=None,
        style="informational",
        tier="facts",
    )


def _decorate(res: ProviderResult, spec: SourceSpec | None) -> ProviderResult:
    if spec:
        res.style = spec.verdict.style
        res.tier = spec.tier
    return res


async def start_lookups(
    text: str,
    *,
    trigger: LookupTrigger = LookupTrigger.MANUAL,
    parent_lookup_id: str | None = None,
    force: bool = False,
    force_full: bool = False,
    only_provider: str | None = None,
    extra: list[Indicator] | None = None,
) -> list[dict[str, Any]]:
    init_db()
    indicators = extract_indicators(text)
    if extra:
        seen = {i.key for i in indicators}
        for ind in extra:
            if ind.key not in seen:
                indicators.append(ind)
                seen.add(ind.key)
    out = []
    for ind in indicators:
        lookup_id = uuid.uuid4().hex
        asyncio.create_task(
            run_lookup(
                lookup_id,
                ind,
                trigger=trigger,
                parent_lookup_id=parent_lookup_id,
                force=force,
                force_full=force_full,
                only_provider=only_provider,
            )
        )
        out.append(
            {
                "lookup_id": lookup_id,
                "type": ind.type.value,
                "value": ind.value,
                "original": ind.original,
                "origin": getattr(ind, "origin", "regex"),
                "hash_algo": ind.hash_algo,
                "url_host": ind.url_host,
                "email_domain": ind.email_domain,
            }
        )
    return out


async def run_lookup(
    lookup_id: str,
    ind: Indicator,
    *,
    trigger: LookupTrigger,
    parent_lookup_id: str | None = None,
    force: bool = False,
    force_full: bool = False,
    only_provider: str | None = None,
) -> None:
    init_db()
    registry = get_registry()
    indicator_id = upsert_indicator(ind)
    create_lookup(lookup_id, indicator_id, trigger.value, parent_lookup_id)
    policy = evaluate(ind)
    specs = registry.for_type(ind.type)
    if only_provider:
        specs = [s for s in specs if s.id == only_provider]
        force = True

    planned = []
    for s in specs:
        planned.append(
            {
                "id": s.id,
                "name": s.name,
                "mode": s.mode,
                "auto_query": s.auto_query,
            }
        )

    await BUS.publish(
        lookup_id,
        "lookup_started",
        {
            "lookup_id": lookup_id,
            "indicator": {
                "type": ind.type.value,
                "value": ind.value,
                "original": ind.original,
                "hash_algo": ind.hash_algo,
            },
            "trigger": trigger.value,
            "policy": {
                "allow_external": policy.allow_external,
                "lightweight": policy.lightweight,
                "reason": policy.reason,
            },
            "providers": planned,
        },
    )

    results: list[ProviderResult] = []

    # Auto-child for URL host and email domain
    child_task = None
    child_ind = None
    if not only_provider:
        if ind.type == IndicatorType.URL and ind.url_host:
            child_type = ind.url_host_type or IndicatorType.DOMAIN
            child_ind = Indicator(type=child_type, value=ind.url_host, original=ind.url_host)
        elif ind.type == IndicatorType.EMAIL and ind.email_domain:
            child_ind = Indicator(type=IndicatorType.DOMAIN, value=ind.email_domain, original=ind.email_domain)
    if child_ind:
        child_id = uuid.uuid4().hex
        await BUS.publish(
            lookup_id,
            "child_started",
            {"lookup_id": child_id, "value": child_ind.value, "type": child_ind.type.value},
        )
        child_task = asyncio.create_task(
            run_lookup(
                child_id,
                child_ind,
                trigger=LookupTrigger.AUTO_CHILD,
                parent_lookup_id=lookup_id,
                force_full=force_full,
            )
        )

    # Link-only first — but never for private/internal indicators (a click would leak them).
    if policy.allow_external:
        for spec in specs:
            if spec.mode != "link_only":
                continue
            res = ProviderResult(
                provider=spec.id,
                provider_name=spec.name,
                status=ResultStatus.SKIPPED,
                skip_reason="link_only",
                summary="Open this source — no API. The indicator is already in the URL.",
                open_source_url=deeplink_for(spec, ind),
                style=spec.verdict.style,
                tier=spec.tier,
            )
            persist_result(indicator_id, lookup_id, res)
            results.append(res)
            await BUS.publish(lookup_id, "provider_result", res.to_public_dict())

    if not policy.allow_external:
        card = _policy_card(ind, policy)
        persist_result(indicator_id, lookup_id, card)
        results.append(card)
        await BUS.publish(lookup_id, "provider_result", card.to_public_dict())
        await _finish(lookup_id, results, {s.id: s for s in specs}, policy)
        if child_task:
            await child_task
        return

    work = []
    for spec in specs:
        if spec.mode == "link_only":
            continue
        if spec.mode == "local":
            work.append(spec)
            continue
        if policy.lightweight and not force_full and spec.mode == "api":
            # lightweight: skip paid/quota APIs; still run no-key informational APIs? Architecture:
            # "mark as lightweight (offer a manual full lookup)"
            # Skip auto-query APIs that consume quota. Still run no-key local-ish APIs.
            if spec.key_env or spec.id in {
                "virustotal",
                "abuseipdb",
                "otx",
                "greynoise_community",
                "urlscan_search",
                "ipqualityscore",
                "apivoid",
                "hybrid_analysis",
                "triage",
                "hunter",
            }:
                res = ProviderResult(
                    provider=spec.id,
                    provider_name=spec.name,
                    status=ResultStatus.SKIPPED,
                    skip_reason="lightweight",
                    summary="Skipped: allowlisted target (lightweight). Run a full lookup to query this source.",
                    open_source_url=deeplink_for(spec, ind),
                )
                persist_result(indicator_id, lookup_id, res)
                results.append(res)
                await BUS.publish(lookup_id, "provider_result", res.to_public_dict())
                continue
        if not spec.auto_query and trigger != LookupTrigger.REFRESH and not only_provider:
            res = ProviderResult(
                provider=spec.id,
                provider_name=spec.name,
                status=ResultStatus.SKIPPED,
                skip_reason="on_demand",
                summary="On-demand source — not auto-queried.",
                open_source_url=deeplink_for(spec, ind),
            )
            persist_result(indicator_id, lookup_id, res)
            results.append(res)
            await BUS.publish(lookup_id, "provider_result", res.to_public_dict())
            continue
        work.append(spec)

    async def run_one(spec: SourceSpec) -> ProviderResult:
        return await _run_provider(spec, ind, indicator_id, lookup_id, force=force)

    gathered = await asyncio.gather(*[run_one(s) for s in work], return_exceptions=True)
    for spec, item in zip(work, gathered):
        if isinstance(item, Exception):
            res = ProviderResult(
                provider=spec.id,
                provider_name=spec.name,
                status=ResultStatus.ERROR,
                summary=str(item)[:200],
                open_source_url=deeplink_for(spec, ind),
            )
            persist_result(indicator_id, lookup_id, res)
            results.append(res)
            await BUS.publish(lookup_id, "provider_result", res.to_public_dict())
        else:
            results.append(item)

    await _finish(lookup_id, results, {s.id: s for s in specs}, policy)
    if child_task:
        await child_task


async def _finish(
    lookup_id: str,
    results: list[ProviderResult],
    specs: dict[str, SourceSpec],
    policy: PolicyDecision | None = None,
) -> None:
    roll = compute_rollup(results, specs)
    flags = list(roll.context_flags)
    if policy and policy.lightweight:
        flags.append("known benign infrastructure / top-ranked")
    roll.context_flags = flags
    finish_lookup(lookup_id)
    await BUS.publish(
        lookup_id,
        "summary",
        {
            "malicious": roll.malicious,
            "suspicious": roll.suspicious,
            "benign": roll.benign,
            "info": roll.info,
            "not_found": roll.not_found,
            "disagreement": roll.disagreement,
            "coverage": roll.coverage,
            "context_flags": roll.context_flags,
            "rate_limited": roll.rate_limited,
            "no_key": roll.no_key,
            "skipped": roll.skipped,
            "link_only": roll.link_only,
            "errors": roll.errors,
            "consensus": roll.consensus,
        },
    )
    await BUS.publish(lookup_id, "done", {"lookup_id": lookup_id})


async def _run_provider(
    spec: SourceSpec,
    ind: Indicator,
    indicator_id: int,
    lookup_id: str,
    *,
    force: bool,
) -> ProviderResult:
    name = spec.name
    link = deeplink_for(spec, ind)

    async def emit(res: ProviderResult) -> ProviderResult:
        _decorate(res, spec)
        persist_result(indicator_id, lookup_id, res)
        await BUS.publish(lookup_id, "provider_result", res.to_public_dict())
        return res

    if spec.mode == "api" and spec.key_env and not spec.key_present():
        return await emit(
            ProviderResult(
                provider=spec.id,
                provider_name=name,
                status=ResultStatus.NO_KEY,
                skip_reason="no_key",
                summary="No API key configured.",
                open_source_url=link,
            )
        )

    if not force:
        cached = latest_cached(indicator_id, spec.id)
        if cached:
            res = row_to_result(cached, name)
            res.cached = True
            res.open_source_url = res.open_source_url or link
            _decorate(res, spec)
            link_cached_result(lookup_id, int(cached["id"]))
            await BUS.publish(lookup_id, "provider_result", res.to_public_dict())
            return res

    if spec.mode == "api":
        allowed, reason, snap = _limiter.check(spec, force=force)
        if not allowed and reason == "rate_limited":
            waited = await _maybe_wait_quota(spec, lookup_id, name, snap)
            if waited:
                allowed, reason, snap = _limiter.check(spec, force=force)
        if not allowed:
            status = ResultStatus.RATE_LIMITED if reason == "rate_limited" else ResultStatus.SKIPPED
            return await emit(
                ProviderResult(
                    provider=spec.id,
                    provider_name=name,
                    status=status,
                    skip_reason=reason,
                    summary=f"Skipped: {reason.replace('_', ' ')}." if reason else "Skipped.",
                    open_source_url=link,
                    quota=snap.windows,
                )
            )

    impl = get_provider(spec.id)
    if impl is None:
        return await emit(
            ProviderResult(
                provider=spec.id,
                provider_name=name,
                status=ResultStatus.ERROR,
                summary="Provider module missing.",
                open_source_url=link,
            )
        )

    dedupe_key = (spec.id, ind.type.value, ind.value)
    async with _inflight_lock:
        existing = _inflight.get(dedupe_key)
        if existing is None:
            loop = asyncio.get_running_loop()
            fut: asyncio.Future = loop.create_future()
            _inflight[dedupe_key] = fut
            owner = True
        else:
            owner = False
            fut = existing

    if not owner:
        raw_res = await fut
        return raw_res

    try:
        async with _sem(spec.id):
            if spec.mode == "api":
                _limiter.consume(spec)
            ctx = Ctx(http_client(), spec)
            raw = await impl.fetch(ind, ctx)
            if raw.status_code == 429:
                retry = raw.headers.get("retry-after")
                try:
                    sec = int(retry) if retry else 60
                except ValueError:
                    sec = 60
                _limiter.cooldown(spec.id, sec)
                res = await emit(
                    ProviderResult(
                        provider=spec.id,
                        provider_name=name,
                        status=ResultStatus.RATE_LIMITED,
                        skip_reason="rate_limited",
                        summary=f"Rate limited. Retry after {sec}s.",
                        open_source_url=link,
                        raw=compress_raw(raw.body or raw.error),
                    )
                )
                fut.set_result(res)
                return res

            parsed = impl.parse(raw, ind)
            status = parsed.status
            if raw.error and raw.status_code == 0:
                status = ResultStatus.ERROR
                _limiter.record_failure(spec.id)
            elif status == ResultStatus.ERROR:
                _limiter.record_failure(spec.id)
            else:
                _limiter.record_success(spec.id)

            remaining = _header_int(raw.headers, "x-ratelimit-remaining") or _header_int(
                raw.headers, "x-rate-limit-remaining"
            )
            limit = _header_int(raw.headers, "x-ratelimit-limit") or _header_int(
                raw.headers, "x-rate-limit-limit"
            )
            if remaining is not None and limit is not None:
                _limiter.sync_from_headers(spec, remaining, limit)

            verdict = map_verdict(spec, parsed, status)
            res = await emit(
                ProviderResult(
                    provider=spec.id,
                    provider_name=name,
                    status=status,
                    verdict=verdict,
                    summary=parsed.summary,
                    facts=parsed.facts,
                    tags=parsed.tags,
                    first_seen=parsed.first_seen,
                    last_seen=parsed.last_seen,
                    related=parsed.related,
                    open_source_url=link,
                    expires_at=expires_for(spec, parsed, status),
                    raw=compress_raw(raw.body if raw.body else (raw.error or "")),
                    quota=_limiter.snapshot(spec).windows if spec.limits else None,
                )
            )
            fut.set_result(res)
            return res
    except Exception as exc:
        _limiter.record_failure(spec.id)
        res = await emit(
            ProviderResult(
                provider=spec.id,
                provider_name=name,
                status=ResultStatus.ERROR,
                summary=str(exc)[:240],
                open_source_url=link,
            )
        )
        if not fut.done():
            fut.set_result(res)
        return res
    finally:
        async with _inflight_lock:
            _inflight.pop(dedupe_key, None)


def _header_int(headers: dict, name: str) -> int | None:
    v = headers.get(name)
    if v is None:
        return None
    try:
        return int(str(v).split(",")[0].strip())
    except ValueError:
        return None


async def _maybe_wait_quota(spec: SourceSpec, lookup_id: str, name: str, snap) -> bool:
    """Wait for a short minute-window reset instead of silently dropping the query."""
    minute = (snap.windows or {}).get("minute") if snap else None
    if not minute:
        return False
    reset = minute.get("reset")
    if not reset:
        return False
    try:
        dt = datetime.fromisoformat(str(reset).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            from datetime import timezone

            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    wait = (dt - utcnow()).total_seconds()
    if wait <= 0 or wait > 75:
        return False
    queued = ProviderResult(
        provider=spec.id,
        provider_name=name,
        status=ResultStatus.QUEUED,
        skip_reason="queued",
        summary=f"Queued — {name} minute quota. Retry in {int(wait)}s.",
        quota=snap.windows,
    )
    _decorate(queued, spec)
    await BUS.publish(lookup_id, "provider_result", queued.to_public_dict())
    await asyncio.sleep(wait + 0.35)
    return True
