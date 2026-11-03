"""UI contract tests. No browser: render pages, check static assets and the
keyboard/accessibility hooks CLAUDE.md requires."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from osint.app import create_app

STATIC = Path(__file__).resolve().parents[1] / "osint" / "static"
JS = (STATIC / "js" / "app.js").read_text()
CSS = (STATIC / "css" / "app.css").read_text()
PAGES = ["/", "/history", "/graph", "/providers", "/ai", "/maintain"]


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


@pytest.mark.parametrize("path", PAGES)
def test_pages_render_with_shell(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert 'class="skip"' in r.text  # skip-to-content link
    assert 'id="rail-toggle"' in r.text and "aria-expanded" in r.text
    assert 'id="main"' in r.text


@pytest.mark.parametrize("path", PAGES)
def test_no_third_party_scripts(client, path):
    srcs = re.findall(r'<script[^>]+src="([^"]+)"', client.get(path).text)
    assert all(s.startswith("/") for s in srcs), srcs


def test_static_assets_served(client):
    for p in ["/static/js/app.js", "/static/css/app.css", "/favicon.svg"]:
        assert client.get(p).status_code == 200, p


def test_bulk_redirects(client):
    r = client.get("/bulk", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_app_js_parses():
    out = subprocess.run(["node", "--check", str(STATIC / "js" / "app.js")], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_keyboard_shortcuts_present():
    assert 'e.key === "/"' in JS  # focus search
    assert 'e.key === "Escape"' in JS  # close modal
    assert 'e.key === "["' in JS  # collapse rail
    assert re.search(r'e\.key === "Enter" && \(e\.metaKey \|\| e\.ctrlKey\)', JS)  # submit


def test_outcome_kinds_clean_separate_from_info():
    # Hard rule 8: clean / no detections is its own outcome, with text + icon, not colour only.
    assert re.search(r'clean:\s*\{[^}]*mark:[^}]*text: "No detections"', JS)
    assert re.search(r'info:\s*\{[^}]*mark:[^}]*text: "Info"', JS)
    for kind in ("malicious", "suspicious", "error"):
        assert re.search(rf"\b{kind}:\s*\{{[^}}]*mark:", JS), kind


def test_css_accessibility_and_theming():
    assert ":focus-visible" in CSS
    assert "prefers-reduced-motion: reduce" in CSS
    assert '[data-theme="light"]' in CSS
    assert "var(--" in CSS


def test_extracted_tray_hidden_by_default(client):
    # Hard rule 7: tray shown only when >1 IOC; markup must start hidden.
    assert 'id="extracted" class="extracted hidden"' in client.get("/").text
