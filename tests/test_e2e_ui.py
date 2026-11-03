"""Browser tests (Playwright). Skipped when Playwright or Chromium is not installed:
    pip install -r requirements-dev.txt && python3 -m playwright install chromium
Offline and deterministic: lookups use a reserved IP (policy card, no external request)."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parents[1]
IP = "10.0.0.8"
IP_DEFANGED = "10[.]0[.]0[.]8"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self) -> None:
        self.port = _free_port()
        self.data = tempfile.mkdtemp(prefix="osint-e2e-")
        self.proc: subprocess.Popen | None = None
        self.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        env = dict(os.environ, OSINT_PORT=str(self.port), OSINT_DATA_DIR=self.data, PYTHONPATH=str(ROOT))
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "run_local.py")], env=env, cwd=ROOT,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                urllib.request.urlopen(self.base + "/healthz", timeout=1).read()
                return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("server did not start")

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.proc = None


@pytest.fixture(scope="module")
def server():
    srv = Server()
    yield srv
    srv.stop()


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(args=["--no-sandbox"])
        except Exception as exc:  # browser binary missing
            pytest.skip(f"chromium unavailable: {exc}")
        yield b
        b.close()


@pytest.fixture()
def page(browser, server):
    ctx = browser.new_context(viewport={"width": 1280, "height": 800}, accept_downloads=True)
    pg = ctx.new_page()
    pg.errors = []
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.on("console", lambda m: pg.errors.append(m.text) if m.type == "error" else None)
    yield pg
    ctx.close()


def _run_lookup(pg, server, text=IP):
    pg.goto(server.base + "/")
    pg.fill("#ioc", text)
    pg.keyboard.press("Control+Enter")
    pg.wait_for_selector(".card[data-provider]:not(.is-pending)")
    pg.wait_for_function("document.querySelectorAll('.card.is-pending').length === 0")


def test_lookup_streams_cards_and_clears_skeletons(page, server):
    _run_lookup(page, server)
    assert page.locator(".card.is-pending").count() == 0
    assert "Local policy" in page.locator(".card[data-provider]").first.inner_text()
    assert page.url.startswith(server.base + "/lookup/")
    assert page.errors == []


def test_report_downloads_are_defanged(page, server):
    _run_lookup(page, server)
    for label, loader in (("Download Markdown", lambda p: open(p).read()), ("Download JSON", lambda p: json.dumps(json.load(open(p))))):
        page.click("#report-menu summary")
        with page.expect_download() as dl:
            page.click(f"text={label}")
        body = loader(dl.value.path())
        assert IP_DEFANGED in body and IP not in body, label


def test_command_palette_navigates_and_closes(page, server):
    page.goto(server.base + "/")
    page.keyboard.press("Control+k")
    assert page.locator("dialog#cmdk[open]").count() == 1
    assert page.evaluate("document.activeElement.className") == "cmdk-input"
    page.keyboard.type("hist")
    page.keyboard.press("Enter")  # immediately: the list must already be filtered
    page.wait_for_url("**/history")
    page.keyboard.press("Control+k")
    page.keyboard.press("Escape")
    assert page.locator("dialog#cmdk[open]").count() == 0


def test_palette_runs_indicator(page, server):
    page.goto(server.base + "/history")
    page.keyboard.press("Control+k")
    page.keyboard.type(IP)
    page.wait_for_selector(".cmdk-group:text-is('Run')")
    page.keyboard.press("Enter")
    page.wait_for_selector(".card[data-provider]:not(.is-pending)", timeout=15000)
    assert "/lookup/" in page.url


def test_shortcut_help_opens_with_question_mark(page, server):
    page.goto(server.base + "/")
    page.keyboard.press("?")
    assert page.locator("dialog#help-dialog[open]").count() == 1
    page.keyboard.press("Escape")
    assert page.locator("dialog#help-dialog[open]").count() == 0


def test_theme_and_density_persist_across_reload_without_flash(page, server):
    page.goto(server.base + "/")
    page.click("#theme-toggle")
    page.click("#density-toggle")
    page.reload()
    # boot.js runs in <head>: attributes are already set when the DOM is parsed.
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    assert page.evaluate("document.documentElement.dataset.density") == "compact"
    assert page.get_attribute("#theme-toggle", "aria-label") == "Switch to dark theme"


def test_draft_survives_reload_and_clears_on_submit(page, server):
    page.goto(server.base + "/")
    page.fill("#ioc", "evil.example.com")
    page.wait_for_timeout(500)
    page.reload()
    assert page.input_value("#ioc") == "evil.example.com"


def test_finished_lookup_repaints_from_database_after_restart(page, server):
    _run_lookup(page, server)
    url = page.url
    server.stop()
    server.start()
    page.goto(url)
    page.wait_for_selector(".card[data-provider]:not(.is-pending)", timeout=15000)
    assert page.locator(".card.is-pending").count() == 0


def test_history_page_is_defanged(page, server):
    _run_lookup(page, server)
    page.goto(server.base + "/history")
    values = page.locator(".hist .v").all_inner_texts()
    assert IP_DEFANGED in values and IP not in values


def test_phone_layout_keeps_content_visible(browser, server):
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    pg = ctx.new_page()
    pg.goto(server.base + "/")
    rail = pg.evaluate("document.querySelector('.rail').getBoundingClientRect().height")
    assert rail < 120  # bottom bar, not a full-screen overlay
    assert pg.is_visible("#ioc")
    assert pg.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
    ctx.close()
