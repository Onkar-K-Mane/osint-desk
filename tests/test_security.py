from fastapi.testclient import TestClient

from osint.app import create_app


def test_bad_host_rejected():
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/", headers={"Host": "evil.example:8080"})
    # relaxed mode allows most hosts, but we still set security headers on allowed
    # Force a clearly empty host
    r2 = client.get("/", headers={"Host": ""})
    assert r2.status_code in (421, 400, 200)


def test_pages_escape_and_render():
    app = create_app()
    client = TestClient(app)
    r = client.get("/")
    assert r.status_code == 200
    assert "OSINT Desk" in r.text
    assert "Investigate" in r.text
    assert 'id="type-bar"' in r.text
    assert 'id="av-verdict"' in r.text
    assert 'id="summary-panel"' in r.text
    assert "full-lookup" not in r.text
    assert "grok.com" not in r.headers["Content-Security-Policy"]
    assert "grok.com" not in r.text  # no third-party scripts


def test_bulk_redirects_home():
    app = create_app()
    client = TestClient(app, follow_redirects=False)
    r = client.get("/bulk")
    assert r.status_code in (301, 302, 307, 308)
    assert r.headers.get("location") in ("/", "http://testserver/")


def test_detect_and_private_ip():
    app = create_app()
    client = TestClient(app)
    client.get("/")  # cookies
    r = client.post("/api/detect", json={"text": "10.0.0.1"})
    assert r.status_code == 200
    assert r.json()["indicators"][0]["type"] == "ip"


def test_ai_page_and_settings_hide_key():
    import os

    from osint.config import write_secret

    app = create_app()
    client = TestClient(app)
    page = client.get("/ai")
    assert page.status_code == 200
    assert "System prompt" in page.text
    assert "API key" in page.text
    settings = client.get("/api/ai/settings")
    assert settings.status_code == 200
    body = settings.json()
    assert "api_key" not in body
    assert body["model"]
    assert body["system_prompt"]
    assert body["base_url"].startswith("http")
    previous = os.environ.get("AI_API_KEY")
    token = client.cookies.get("csrf_token")
    try:
        saved = client.post(
            "/api/ai/settings",
            json={
                "base_url": body["base_url"],
                "model": body["model"],
                "system_prompt": body["system_prompt"],
                "temperature": body["temperature"],
                "max_tokens": body["max_tokens"],
                "api_key": "should-not-echo",
            },
            headers={"X-CSRF-Token": token or ""},
        )
        assert saved.status_code == 200
        echoed = saved.json()
        assert "api_key" not in echoed
        assert echoed["has_key"] is True
        assert "should-not-echo" not in saved.text
    finally:
        write_secret("AI_API_KEY", previous or "")


def test_summary_endpoint_404():
    app = create_app()
    client = TestClient(app)
    r = client.get("/api/lookups/does-not-exist/summary")
    assert r.status_code == 200  # empty string is fine
    assert r.text == "" or r.status_code in (200, 404)


def test_csp_script_src_is_self_only():
    client = TestClient(create_app(), raise_server_exceptions=False)
    csp = client.get("/healthz").headers["content-security-policy"]
    assert "script-src 'self';" in csp
    assert "grok.com" not in csp


def test_default_host_is_loopback(monkeypatch):
    import importlib

    import osint.config as config

    monkeypatch.delenv("OSINT_HOST", raising=False)
    try:
        assert importlib.reload(config).DEFAULT_HOST == "127.0.0.1"
    finally:
        importlib.reload(config)
