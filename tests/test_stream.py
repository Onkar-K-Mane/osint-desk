"""SSE stream edge cases: finished lookups the bus no longer holds must not hang."""

import json
import uuid

from fastapi.testclient import TestClient

from osint.app import create_app
from osint.db import create_lookup, finish_lookup, upsert_indicator
from osint.detect import classify_one


def _lookup(finished: bool) -> str:
    ind = classify_one("203.0.113.9")
    lookup_id = uuid.uuid4().hex
    create_lookup(lookup_id, upsert_indicator(ind), "manual")
    if finished:
        finish_lookup(lookup_id)
    return lookup_id


def test_finished_lookup_without_buffer_ends_with_done():
    client = TestClient(create_app())
    lookup_id = _lookup(finished=True)
    r = client.get(f"/api/lookups/{lookup_id}/stream")
    assert r.status_code == 200
    assert r.text.startswith("event: done\n")
    payload = json.loads(r.text.split("data: ", 1)[1].strip())
    assert payload == {"lookup_id": lookup_id}


def test_results_still_loadable_over_http_for_finished_lookup():
    client = TestClient(create_app())
    lookup_id = _lookup(finished=True)
    body = client.get(f"/api/lookups/{lookup_id}").json()
    assert body["indicator"]["value"] == "203.0.113.9"
    assert body["results"] == []


def test_unknown_lookup_is_not_treated_as_finished():
    from osint.db import lookup_is_over

    assert lookup_is_over("does-not-exist") is False
    assert lookup_is_over(_lookup(finished=False)) is False
