"""Provider interface and shared HTTP / mapping helpers."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any
from urllib.parse import quote

from osint.detect import url_sha256
from osint.models import (
    Indicator,
    IndicatorType,
    ParsedResult,
    ProviderResult,
    RawResponse,
    ResultStatus,
    utcnow,
)
from osint.registry import SourceSpec
from osint.ttl import parse_duration
from osint.verdict import map_verdict

PARSER_VERSION = 1
USER_AGENT = "OSINT-Desk/0.4 (personal-lab; local)"


class Ctx:
    def __init__(self, http, spec: SourceSpec) -> None:
        self.http = http
        self.spec = spec


class Provider:
    id: str = ""

    def deeplink(self, spec: SourceSpec, ind: Indicator) -> str | None:
        tmpl = spec.deeplink.get(ind.type.value)
        if not tmpl:
            return None
        host = ind.url_host or ind.email_domain or (
            ind.value if ind.type in {IndicatorType.DOMAIN, IndicatorType.IP} else ""
        )
        return tmpl.format(
            value=ind.value,
            value_urlenc=quote(ind.value, safe=""),
            url_sha256=url_sha256(ind.value) if ind.type == IndicatorType.URL else "",
            host=host or "",
        )

    async def fetch(self, ind: Indicator, ctx: Ctx) -> RawResponse:
        raise NotImplementedError

    def parse(self, raw: RawResponse, ind: Indicator) -> ParsedResult:
        raise NotImplementedError


_REGISTRY_IMPL: dict[str, Provider] = {}


def register(provider: Provider) -> Provider:
    _REGISTRY_IMPL[provider.id] = provider
    return provider


def get_provider(sid: str) -> Provider | None:
    if not _REGISTRY_IMPL:
        _load_all()
    return _REGISTRY_IMPL.get(sid)


def all_providers() -> dict[str, Provider]:
    if not _REGISTRY_IMPL:
        _load_all()
    return _REGISTRY_IMPL


def _load_all() -> None:
    # Local imports so modules register themselves.
    from osint.providers import (  # noqa: F401
        abuseipdb,
        apivoid,
        crtsh,
        disposable,
        dmarc,
        dns,
        geoasn,
        greynoise,
        hashlookup,
        hunter,
        hybrid_analysis,
        internetdb,
        ipqualityscore,
        malwarebazaar,
        otx,
        popularity,
        rdap,
        threatfox,
        triage,
        urlhaus,
        urlscan,
        virustotal,
    )


def expires_for(spec: SourceSpec, parsed: ParsedResult, status: ResultStatus):
    if status == ResultStatus.NOT_FOUND:
        delta = parse_duration(spec.ttl.not_found, timedelta(hours=1))
    elif parsed and parsed.score and spec.ttl.malicious and (parsed.score >= (spec.verdict.malicious_at or 9999)):
        delta = parse_duration(spec.ttl.malicious, timedelta(hours=24))
    else:
        delta = parse_duration(spec.ttl.default, timedelta(hours=6))
    return utcnow() + delta


def json_body(raw: RawResponse) -> Any:
    if not raw.body:
        return None
    try:
        return json.loads(raw.text())
    except json.JSONDecodeError:
        return None


async def http_get(ctx: Ctx, url: str, *, headers: dict | None = None, params=None) -> RawResponse:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        resp = await ctx.http.get(url, headers=hdrs, params=params, timeout=ctx.spec.timeout_s)
        return RawResponse(
            status_code=resp.status_code,
            body=resp.content,
            headers={k.lower(): v for k, v in resp.headers.items()},
            url=_redact_url(str(resp.url), ctx.spec),
        )
    except Exception as exc:
        return RawResponse(status_code=0, body=b"", url=_redact_url(url, ctx.spec), error=str(exc)[:300])


async def http_post(ctx: Ctx, url: str, *, data=None, json_payload=None, headers=None) -> RawResponse:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        resp = await ctx.http.post(
            url,
            headers=hdrs,
            data=data,
            json=json_payload,
            timeout=ctx.spec.timeout_s,
        )
        return RawResponse(
            status_code=resp.status_code,
            body=resp.content,
            headers={k.lower(): v for k, v in resp.headers.items()},
            url=_redact_url(str(resp.url), ctx.spec),
        )
    except Exception as exc:
        return RawResponse(status_code=0, body=b"", url=_redact_url(url, ctx.spec), error=str(exc)[:300])


def _redact_url(url: str, spec: SourceSpec) -> str:
    if spec.key_env:
        import os

        key = os.environ.get(spec.key_env, "")
        if key:
            url = url.replace(key, "***")
    return url


def status_from_http(raw: RawResponse) -> ResultStatus:
    if raw.error and raw.status_code == 0:
        return ResultStatus.ERROR
    if raw.status_code == 404:
        return ResultStatus.NOT_FOUND
    if raw.status_code == 429:
        return ResultStatus.RATE_LIMITED
    if raw.status_code in (401, 403):
        return ResultStatus.ERROR
    if raw.status_code >= 500:
        return ResultStatus.ERROR
    if raw.status_code >= 400:
        return ResultStatus.ERROR
    return ResultStatus.OK
