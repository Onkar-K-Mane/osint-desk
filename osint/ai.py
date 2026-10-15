"""OpenAI-compatible AI backend. No silent fallback between providers."""

from __future__ import annotations

import json
from typing import Any

import httpx

from osint.config import ai_settings
from osint.db import decompress_raw, lookup_bundle
from osint.detect import classify_one
from osint.models import Indicator


class AIError(Exception):
    def __init__(self, message: str, *, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


def backend_label() -> dict[str, str]:
    s = ai_settings()
    return {"label": str(s["label"]), "model": str(s["model"]), "local": str(s["local"])}


async def chat(messages: list[dict[str, str]], *, max_tokens: int = 900, temperature: float = 0.2) -> str:
    s = ai_settings()
    base = str(s["base_url"])
    model = str(s["model"])
    key = s["api_key"]
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    # Smaller context for local/small models
    local = s["local"] == "1"
    if local:
        max_tokens = min(max_tokens, 700)
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    url = base + "/chat/completions"
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
    except httpx.ConnectError as exc:
        raise AIError(
            f"AI backend unreachable at {base}. Start Ollama or set AI_BASE_URL. ({exc.__class__.__name__})",
            status=503,
        ) from exc
    except httpx.HTTPError as exc:
        raise AIError(f"AI backend error: {exc}", status=503) from exc
    if resp.status_code >= 400:
        raise AIError(
            f"AI backend returned HTTP {resp.status_code}: {resp.text[:240]}",
            status=resp.status_code if resp.status_code in {401, 404, 429} else 502,
        )
    try:
        data = resp.json()
    except json.JSONDecodeError as exc:
        raise AIError("AI backend returned non-JSON.") from exc
    choices = data.get("choices") or []
    if not choices:
        raise AIError("AI backend returned no choices.")
    content = (choices[0].get("message") or {}).get("content") or ""
    if not str(content).strip():
        raise AIError("AI backend returned an empty reply.")
    return str(content).strip()


def _temperature() -> float:
    s = ai_settings()
    try:
        t = float(s["temperature"] or 0.2)
    except (TypeError, ValueError):
        t = 0.2
    return max(0.0, min(t, 2.0))


def _max_tokens(cap: int | None = None) -> int:
    s = ai_settings()
    try:
        n = int(float(s["max_tokens"] or 700))
    except (TypeError, ValueError):
        n = 700
    n = max(64, min(n, 4000))
    if cap is not None:
        n = min(n, cap)
    if s["local"] == "1":
        n = min(n, 700)
    return n


def _system_prompt() -> str:
    return str(ai_settings()["system_prompt"] or "")


def _budget_chars() -> int:
    s = ai_settings()
    return 6000 if s["local"] == "1" else 18000


async def extract_with_ai(text: str) -> list[Indicator]:
    """Ask the model for leftover IOCs; re-validate every item through classify_one."""
    prompt = (
        "Extract network indicators of compromise from the text. "
        "Return a JSON array of objects {type, value} where type is one of "
        "ip, domain, url, hash, email. No commentary. If none, return [].\n\n"
        + text[:4000]
    )
    raw = await chat(
        [
            {"role": "system", "content": "You extract IOCs. Output JSON only."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=400,
        temperature=0,
    )
    start = raw.find("[")
    end = raw.rfind("]")
    if start < 0 or end < 0:
        return []
    try:
        arr = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return []
    out: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    for item in arr:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        ind = classify_one(value)
        if not ind:
            continue
        if item.get("type") and ind.type.value != str(item["type"]).lower():
            # still accept if detector disagrees — detector wins
            pass
        if ind.key in seen:
            continue
        seen.add(ind.key)
        ind.origin = "ai"
        out.append(ind)
    return out


def _bundle_context(lookup_id: str) -> tuple[str, dict[str, Any]]:
    bundle = lookup_bundle(lookup_id)
    if not bundle:
        raise AIError("Lookup not found.", status=404)
    ind = dict(bundle["indicator"])
    parts = [
        f"Indicator type={ind.get('type')} value={ind.get('value')} original={ind.get('original')}",
        f"Lookup started {bundle['lookup']['started_at']}",
    ]
    budget = _budget_chars()
    used = sum(len(p) for p in parts)
    for row in bundle["results"]:
        block = [
            f"\n## {row['provider']} status={row['status']} verdict={row['verdict']}",
            f"summary: {row['summary']}",
            f"facts: {row['facts_json']}",
            f"tags: {row['tags_json']}",
        ]
        raw = decompress_raw(row["raw"]) if row["raw"] else ""
        if raw:
            remain = max(400, budget - used - 200)
            block.append("raw: " + raw[:remain])
        chunk = "\n".join(block)
        if used + len(chunk) > budget:
            parts.append(chunk[: max(0, budget - used)])
            break
        parts.append(chunk)
        used += len(chunk)
    return "\n".join(parts), ind


async def assess(lookup_id: str, pasted: str = "") -> str:
    ctx, ind = _bundle_context(lookup_id)
    extra = f"\nAnalyst pasted search text:\n{pasted[:1500]}" if pasted else ""
    return await chat(
        [
            {
                "role": "system",
                "content": (
                    "You are an OSINT analyst assistant. Never issue a blended authoritative verdict. "
                    "Attribute every claim to a named source. Structure the reply as: "
                    "Overall lean, Key evidence (source-attributed), Gaps/conflicts, Suggested next step."
                ),
            },
            {
                "role": "user",
                "content": f"Synthesize this investigation. Indicator {ind.get('type')} {ind.get('value')}.\n{ctx}{extra}",
            },
        ]
    )


async def draft_ticket(lookup_id: str, analyst: dict | None = None) -> str:
    ctx, ind = _bundle_context(lookup_id)
    av = ""
    if analyst:
        av = f"\nAnalyst verdict: {analyst.get('verdict')} note: {analyst.get('note') or ''}"
    return await chat(
        [
            {
                "role": "system",
                "content": (
                    "Write a pasteable incident ticket note in markdown. Include: title, indicator (defanged), "
                    "what sources reported, analyst verdict if present, recommended action. "
                    "Do not invent detections. Attribute sources by name."
                ),
            },
            {"role": "user", "content": ctx + av},
        ]
    )


async def explain_raw(provider: str, raw: str) -> str:
    return await chat(
        [
            {"role": "system", "content": _system_prompt()},
            {
                "role": "user",
                "content": (
                    "Explain this single source card for a SOC analyst. "
                    "Use only the data below.\n"
                    f"Provider: {provider}\n{raw[:12000]}"
                ),
            },
        ],
        max_tokens=_max_tokens(800),
        temperature=_temperature(),
    )


async def explain_summary(lookup_ids: list[str]) -> str:
    chunks: list[str] = []
    for lid in lookup_ids[:12]:
        try:
            ctx, _ind = _bundle_context(lid)
        except AIError:
            continue
        if ctx:
            chunks.append(ctx)
    if not chunks:
        raise AIError("Nothing to explain yet.", status=404)
    body = "\n\n".join(chunks)
    budget = _budget_chars()
    return await chat(
        [
            {"role": "system", "content": _system_prompt()},
            {
                "role": "user",
                "content": (
                    "Explain this investigation summary for a SOC analyst. "
                    "The block below is the underlying source data for the summary card. "
                    "Do not invent a blended verdict.\n\n" + body[:budget]
                ),
            },
        ],
        max_tokens=_max_tokens(900),
        temperature=_temperature(),
    )


async def ping() -> str:
    return await chat(
        [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": "Reply with exactly: OK"},
        ],
        max_tokens=32,
        temperature=0,
    )
