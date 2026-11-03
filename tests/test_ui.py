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
@pytest.mark.parametrize("name", ["app.js", "ux.js", "boot.js"])
def test_js_parses(name):
    out = subprocess.run(["node", "--check", str(STATIC / "js" / name)], capture_output=True, text=True)
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


def test_defang_filter_matches_client_rules():
    from osint.app import defang_text

    assert defang_text("http://evil.com/a") == "hxxp://evil[.]com/a"
    assert defang_text("https://a.b") == "hxxps://a[.]b"
    assert defang_text("bad@evil.com") == "bad[@]evil[.]com"
    assert defang_text(None) == ""


@pytest.mark.parametrize("path,label", [("/", "Investigate"), ("/history", "History"), ("/providers", "Providers")])
def test_active_nav_item_has_aria_current(client, path, label):
    html = client.get(path).text
    assert re.findall(r'aria-label="([^"]+)" aria-current="page"', html) == [label]


def test_topbar_controls_are_labelled(client):
    html = client.get("/").text
    for ident in ("cmdk-open", "density-toggle", "theme-toggle", "help-open"):
        assert re.search(rf'id="{ident}"[^>]*aria-', html), ident
    assert 'id="detect-chips"' in html and 'aria-live="polite"' in html


def test_no_inline_scripts_so_csp_holds(client):
    for path in PAGES:
        # JSON data blocks are not executable; anything else without src= would break the CSP.
        for tag in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", client.get(path).text):
            assert 'type="application/json"' in tag, (path, tag)


def test_theme_boot_script_loads_before_css(client):
    html = client.get("/").text
    assert html.index("/static/js/boot.js") < html.index("/static/css/app.css")


def test_ux_layer_exposes_documented_features():
    ux = (STATIC / "js" / "ux.js").read_text()
    for needle in ("openPalette", "openHelp", "toggleDensity", "downloadReport", "osint:stream", "deepDefang"):
        assert needle in ux, needle
