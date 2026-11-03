/* OSINT Desk UX layer: command palette, shortcut help, density, report export,
 * connection banner, draft persistence. Vanilla JS, no dependencies. Depends only on
 * the small window.OSINT surface exposed by app.js. Provider text is always textContent. */
(function () {
  "use strict";
  const O = window.OSINT;
  if (!O) return;
  const el = O.el;
  const $ = (sel, root) => (root || document).querySelector(sel);
  const root = document.documentElement;

  const SVG_NS = "http://www.w3.org/2000/svg";
  function icon(d) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.8");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("width", "16");
    svg.setAttribute("height", "16");
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.appendChild(path);
    return svg;
  }
  const ICON = {
    go: "M5 12h14M13 6l6 6-6 6",
    search: "M11 4.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM16 16l4.5 4.5",
    clock: "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM12 8v5l3 2",
    theme: "M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z",
    rows: "M4 7h16M4 12h16M4 17h16",
    rail: "M15 6l-6 6 6 6",
    help: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17zM9.6 9.4a2.4 2.4 0 1 1 3.4 2.2c-.7.4-1 .8-1 1.6M12 16.6v.1",
    copy: "M9 9h10v10H9zM5 15V5h10",
    down: "M12 4v12M7 11l5 5 5-5M5 20h14",
    refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6",
  };

  function store(key, val) {
    try {
      if (val === undefined) return localStorage.getItem(key);
      localStorage.setItem(key, val);
    } catch (e) {}
    return null;
  }

  /* ---------- Density ---------- */
  function initDensity() {
    const btn = $("#density-toggle");
    function paint() {
      const compact = root.getAttribute("data-density") === "compact";
      if (!btn) return;
      btn.setAttribute("aria-pressed", compact ? "true" : "false");
      btn.setAttribute("aria-label", compact ? "Switch to comfortable density" : "Switch to compact density");
      btn.setAttribute("title", compact ? "Comfortable density" : "Compact density");
    }
    toggleDensity.paint = paint;
    paint();
    if (btn) btn.addEventListener("click", toggleDensity);
  }
  function toggleDensity() {
    const compact = root.getAttribute("data-density") === "compact";
    if (compact) root.removeAttribute("data-density");
    else root.setAttribute("data-density", "compact");
    store("osint-density", compact ? "comfortable" : "compact");
    if (toggleDensity.paint) toggleDensity.paint();
    O.toast(compact ? "Comfortable density" : "Compact density");
  }

  /* ---------- Dialog helper ---------- */
  function makeDialog(id, label) {
    let d = document.getElementById(id);
    if (d) return d;
    d = el("dialog", { id: id, class: "dlg", "aria-label": label });
    d.addEventListener("click", (ev) => {
      if (ev.target === d) d.close(); // backdrop click
    });
    document.body.appendChild(d);
    return d;
  }
  function openDialog(d) {
    if (typeof d.showModal === "function") {
      if (!d.open) d.showModal();
    } else {
      d.setAttribute("open", "");
    }
  }

  /* ---------- Keyboard help ---------- */
  const SHORTCUTS = [
    [["/"], "Focus search / input"],
    [["Ctrl", "Enter"], "Run lookup"],
    [["Ctrl", "K"], "Command palette"],
    [["?"], "This help"],
    [["["], "Collapse / expand navigation"],
    [["1", "…", "6"], "Filter extracted IOCs by type"],
    [["Esc"], "Close dialog or modal"],
    [["Enter"], "Flip focused card (explain with AI)"],
  ];
  function openHelp() {
    const d = makeDialog("help-dialog", "Keyboard shortcuts");
    d.textContent = "";
    const panel = el("div", { class: "dlg-panel" });
    const head = el("div", { class: "dlg-head" }, el("h2", { text: "Keyboard shortcuts" }));
    const close = el("button", { type: "button", class: "icon-btn", "aria-label": "Close" });
    close.appendChild(icon("M6 6l12 12M18 6 6 18"));
    close.addEventListener("click", () => d.close());
    head.appendChild(close);
    const grid = el("div", { class: "kbd-grid" });
    SHORTCUTS.forEach(([keys, label]) => {
      const k = el("span", { class: "keys" });
      keys.forEach((x) => k.appendChild(el("kbd", { text: x })));
      grid.appendChild(el("div", { class: "kbd-row" }, el("span", { text: label }), k));
    });
    panel.appendChild(head);
    panel.appendChild(grid);
    d.appendChild(panel);
    openDialog(d);
  }

  /* ---------- Command palette ---------- */
  const PAGES = [
    ["Investigate", "/", ICON.search],
    ["History", "/history", ICON.clock],
    ["Graph", "/graph", "M6 9.6a2.4 2.4 0 1 0 0 4.8 2.4 2.4 0 0 0 0-4.8zM18 3.6a2.4 2.4 0 1 0 0 4.8 2.4 2.4 0 0 0 0-4.8zM18 15.6a2.4 2.4 0 1 0 0 4.8 2.4 2.4 0 0 0 0-4.8zM8.2 11.2l7.4-4M8.2 12.8l7.4 4"],
    ["Providers", "/providers", ICON.rows],
    ["AI", "/ai", "M12 3l1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6L12 3z"],
    ["Maintain", "/maintain", "M4 4h16v16H4zM8 12h8M12 8v8"],
  ];
  const pal = { dlg: null, input: null, list: null, items: [], sel: 0, seq: 0, timer: 0 };

  function clickIf(sel) {
    const b = $(sel);
    if (b && !b.disabled) b.click();
    else O.toast("Run an investigation first");
  }
  function staticCommands() {
    const cmds = PAGES.map(([name, href, ic]) => ({ group: "Go to", label: name, icon: ic, run: () => (location.href = href) }));
    cmds.push(
      { group: "Actions", label: "Focus search", hint: "/", icon: ICON.search, run: () => (focusInput() ? 0 : (location.href = "/")) },
      { group: "Actions", label: "Toggle theme", icon: ICON.theme, run: () => $("#theme-toggle") && $("#theme-toggle").click() },
      { group: "Actions", label: "Toggle compact density", icon: ICON.rows, run: toggleDensity },
      { group: "Actions", label: "Collapse / expand navigation", hint: "[", icon: ICON.rail, run: () => $("#rail-toggle") && $("#rail-toggle").click() },
      { group: "Actions", label: "Keyboard shortcuts", hint: "?", icon: ICON.help, run: openHelp }
    );
    if ($("#toolbar") && !$("#toolbar").classList.contains("hidden")) {
      cmds.push(
        { group: "This investigation", label: "Download report (Markdown)", icon: ICON.down, run: () => downloadReport("md") },
        { group: "This investigation", label: "Download report (JSON)", icon: ICON.down, run: () => downloadReport("json") },
        { group: "This investigation", label: "Copy report as Markdown", icon: ICON.copy, run: () => O.writeClip(buildMarkdown()) },
        { group: "This investigation", label: "Copy IOCs (defanged)", icon: ICON.copy, run: () => clickIf("#copy-iocs") },
        { group: "This investigation", label: "Refresh all sources", icon: ICON.refresh, run: () => clickIf("#refresh-all") }
      );
    }
    return cmds;
  }
  function focusInput() {
    const t = $("#ioc") || $("#hist-q");
    if (t) t.focus();
    return !!t;
  }
  function runIoc(value) {
    const input = $("#ioc");
    if (input && $("#investigate-form")) {
      input.value = value;
      O.liveDetect();
      $("#investigate-form").requestSubmit();
    } else {
      location.href = "/?run=1&prefill=" + encodeURIComponent(value);
    }
  }

  function paintPalette(entries) {
    pal.items = entries;
    pal.sel = 0;
    pal.list.textContent = "";
    if (!entries.length) {
      pal.list.appendChild(el("li", { class: "cmdk-empty", role: "presentation", text: "No matches" }));
      pal.input.removeAttribute("aria-activedescendant");
      return;
    }
    let group = "";
    entries.forEach((e, i) => {
      if (e.group !== group) {
        group = e.group;
        pal.list.appendChild(el("li", { class: "cmdk-group", role: "presentation", text: group }));
      }
      const li = el("li", { class: "cmdk-item", role: "option", id: "cmdk-opt-" + i, "aria-selected": i === 0 ? "true" : "false" });
      li.appendChild(icon(e.icon || ICON.go));
      li.appendChild(el("span", { class: "lbl" + (e.mono ? " mono" : ""), text: e.label }));
      if (e.hint) li.appendChild(el("span", { class: "hint-r", text: e.hint }));
      li.addEventListener("click", () => choose(i));
      li.addEventListener("mousemove", () => select(i, false));
      pal.list.appendChild(li);
    });
    pal.input.setAttribute("aria-activedescendant", "cmdk-opt-0");
  }
  function select(i, scroll) {
    if (!pal.items.length) return;
    pal.sel = (i + pal.items.length) % pal.items.length;
    pal.list.querySelectorAll(".cmdk-item").forEach((n, idx) => n.setAttribute("aria-selected", idx === pal.sel ? "true" : "false"));
    pal.input.setAttribute("aria-activedescendant", "cmdk-opt-" + pal.sel);
    const n = document.getElementById("cmdk-opt-" + pal.sel);
    if (n && scroll !== false) n.scrollIntoView({ block: "nearest" });
  }
  function choose(i) {
    const e = pal.items[i];
    if (!e) return;
    pal.dlg.close();
    setTimeout(() => e.run(), 0);
  }

  function localMatches(q) {
    const needle = q.toLowerCase();
    return staticCommands().filter((c) => !needle || c.label.toLowerCase().includes(needle) || c.group.toLowerCase().includes(needle));
  }

  async function refreshPalette() {
    const q = pal.input.value.trim();
    const seq = ++pal.seq;
    const cmds = localMatches(q);
    paintPalette(cmds);
    // Indicators found in the typed text, then matching history.
    const extra = [];
    try {
      if (q.length >= 3) {
        const det = await O.api("/api/detect", { method: "POST", json: { text: q } });
        if (seq !== pal.seq) return;
        const inds = det.indicators || [];
        if (inds.length) {
          extra.push({
            group: "Run",
            label: inds.length === 1 ? "Run lookup: " + O.defang(inds[0].value) : "Run lookup for " + inds.length + " indicators",
            mono: true,
            icon: ICON.search,
            hint: inds.length === 1 ? inds[0].type : "",
            run: () => runIoc(q),
          });
        }
      }
      const hist = await O.api("/api/search" + (q ? "?q=" + encodeURIComponent(q) : ""));
      if (seq !== pal.seq) return;
      (hist.items || []).slice(0, q ? 6 : 5).forEach((it) =>
        extra.push({ group: q ? "History" : "Recent", label: O.defang(it.value || ""), mono: true, icon: ICON.clock, hint: it.type, run: () => runIoc(it.value) })
      );
    } catch (e) {
      /* palette still works offline for pages and actions */
    }
    if (seq !== pal.seq) return;
    paintPalette(extra.filter((e) => e.group === "Run").concat(cmds, extra.filter((e) => e.group !== "Run")));
  }

  function openPalette() {
    if (!pal.dlg) {
      const d = makeDialog("cmdk", "Command palette");
      const panel = el("div", { class: "dlg-panel" });
      pal.input = el("input", {
        type: "text",
        class: "cmdk-input",
        placeholder: "Type an IOC to look up, search history, or jump to a page…",
        role: "combobox",
        "aria-expanded": "true",
        "aria-controls": "cmdk-list",
        "aria-label": "Command palette",
        autocomplete: "off",
        spellcheck: "false",
      });
      pal.list = el("ul", { class: "cmdk-list", id: "cmdk-list", role: "listbox", "aria-label": "Results" });
      const foot = el("div", { class: "cmdk-foot" });
      [["↑↓", "navigate"], ["↵", "select"], ["Esc", "close"]].forEach(([k, t]) => foot.appendChild(el("span", {}, el("kbd", { text: k }), document.createTextNode(t))));
      panel.appendChild(pal.input);
      panel.appendChild(pal.list);
      panel.appendChild(foot);
      d.appendChild(panel);
      pal.dlg = d;
      pal.input.addEventListener("input", () => {
        // Filter pages/actions instantly so Enter never acts on a stale list; only the
        // network lookups (detect + history) are debounced.
        paintPalette(localMatches(pal.input.value.trim()));
        clearTimeout(pal.timer);
        pal.timer = setTimeout(refreshPalette, 120);
      });
      pal.input.addEventListener("keydown", (e) => {
        if (e.key === "ArrowDown") (e.preventDefault(), select(pal.sel + 1));
        else if (e.key === "ArrowUp") (e.preventDefault(), select(pal.sel - 1));
        else if (e.key === "Home") (e.preventDefault(), select(0));
        else if (e.key === "End") (e.preventDefault(), select(pal.items.length - 1));
        else if (e.key === "Enter") (e.preventDefault(), choose(pal.sel));
      });
    }
    pal.input.value = "";
    openDialog(pal.dlg);
    pal.input.focus();
    refreshPalette();
  }

  /* ---------- Report export (always defanged: hard rule 11) ---------- */
  function lookupsForReport() {
    const st = O.state;
    const lus = st.lookups && st.lookups.length ? st.lookups : st.current ? [{ lookup_id: st.current, type: "", value: "" }] : [];
    return lus.map((lu) => ({ type: lu.type || "", value: lu.value || "", results: (st.results[lu.lookup_id] || []).filter((r) => r.skip_reason !== "link_only") }));
  }
  function outcome(r) {
    const k = O.badgeKind(r);
    return (O.BADGE[k] || O.BADGE.info).text;
  }
  function cell(v) {
    return O.defang(String(v == null ? "" : v)).replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ").trim();
  }
  function buildMarkdown() {
    const lus = lookupsForReport();
    const lines = ["# OSINT Desk report", "", "Generated " + new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC · " + lus.length + " indicator" + (lus.length === 1 ? "" : "s"), "", "> Each source is reported separately. There is no blended score; the analyst decides.", ""];
    lus.forEach((lu) => {
      lines.push("## " + (lu.type ? lu.type + " · " : "") + O.defang(lu.value || "indicator"), "");
      if (!lu.results.length) {
        lines.push("_No source results captured yet._", "");
        return;
      }
      lines.push("| Source | Outcome | Summary |", "| --- | --- | --- |");
      lu.results.forEach((r) => lines.push("| " + cell(r.provider_name || r.provider) + " | " + outcome(r) + " | " + cell(r.summary) + " |"));
      lines.push("");
      lu.results.forEach((r) => {
        const facts = (r.facts || []).slice(0, 6);
        const tags = (r.tags || []).slice(0, 8);
        if (!facts.length && !tags.length) return;
        lines.push("**" + cell(r.provider_name || r.provider) + "**");
        facts.forEach((f) => lines.push("- " + cell(f.label) + ": " + cell(f.value)));
        if (tags.length) lines.push("- tags: " + tags.map(cell).join(", "));
        lines.push("");
      });
    });
    return lines.join("\n");
  }
  function deepDefang(v) {
    if (typeof v === "string") return O.defang(v);
    if (Array.isArray(v)) return v.map(deepDefang);
    if (v && typeof v === "object") {
      const out = {};
      Object.keys(v).forEach((k) => (out[k] = deepDefang(v[k])));
      return out;
    }
    return v;
  }
  function buildJson() {
    return JSON.stringify(
      deepDefang({
        tool: "OSINT Desk",
        generated: new Date().toISOString(),
        note: "Per-source results. No blended score. Values are defanged.",
        indicators: lookupsForReport().map((lu) => ({
          type: lu.type,
          value: lu.value,
          sources: lu.results.map((r) => ({
            source: r.provider_name || r.provider,
            outcome: outcome(r),
            status: r.status,
            verdict: r.verdict,
            summary: r.summary,
            facts: r.facts || [],
            tags: r.tags || [],
            queried_at: r.queried_at,
            cached: !!r.cached,
          })),
        })),
      }),
      null,
      2
    );
  }
  function downloadReport(fmt) {
    const has = lookupsForReport().some((l) => l.results.length);
    if (!has) return O.toast("No results to export yet");
    const body = fmt === "json" ? buildJson() : buildMarkdown();
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    const blob = new Blob([body], { type: fmt === "json" ? "application/json" : "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: "osint-desk-report-" + stamp + "." + fmt });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    O.toast("Report downloaded (defanged)");
  }
  function initReportMenu() {
    const bar = $("#toolbar");
    if (!bar || $("#report-menu")) return;
    const menu = el("details", { class: "menu", id: "report-menu" });
    const sum = el("summary", { class: "btn", "aria-haspopup": "menu" }, document.createTextNode("Report"));
    sum.appendChild(icon("M6 9l6 6 6-6"));
    const list = el("div", { class: "menu-list", role: "menu" });
    [
      ["Download Markdown", "md", () => downloadReport("md")],
      ["Download JSON", "json", () => downloadReport("json")],
      ["Copy as Markdown", "", () => O.writeClip(buildMarkdown())],
    ].forEach(([label, ext, fn]) => {
      const b = el("button", { type: "button", class: "menu-item", role: "menuitem" }, document.createTextNode(label));
      if (ext) b.appendChild(el("small", { text: "." + ext }));
      b.addEventListener("click", () => {
        menu.open = false;
        fn();
      });
      list.appendChild(b);
    });
    menu.appendChild(sum);
    menu.appendChild(list);
    bar.insertBefore(menu, bar.firstChild);
    document.addEventListener("click", (e) => {
      if (menu.open && !menu.contains(e.target)) menu.open = false;
    });
    menu.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && menu.open) {
        menu.open = false;
        sum.focus();
      }
    });
  }

  /* ---------- Connection banner ---------- */
  let banner = null;
  let bannerTimer = 0;
  function showBanner(text, kind, action) {
    clearTimeout(bannerTimer);
    if (!banner) {
      banner = el("div", { class: "conn-banner", role: "status", "aria-live": "polite" });
      document.body.appendChild(banner);
    }
    banner.className = "conn-banner" + (kind === "err" ? " err" : "");
    banner.textContent = "";
    banner.appendChild(el("span", { text: text }));
    if (action) {
      const b = el("button", { type: "button", class: "btn", text: action.label });
      b.addEventListener("click", action.run);
      banner.appendChild(b);
    }
  }
  function hideBanner() {
    clearTimeout(bannerTimer);
    if (banner) {
      banner.remove();
      banner = null;
    }
  }
  function initConnection() {
    document.addEventListener("osint:stream", (e) => {
      const s = e.detail && e.detail.state;
      if (s === "reconnecting") showBanner("Live connection interrupted. Reconnecting…", "warn");
      else if (s === "failed") {
        showBanner("Live stream lost. Showing saved results.", "err");
        bannerTimer = setTimeout(hideBanner, 8000);
      } else if (s === "open") hideBanner();
    });
    window.addEventListener("offline", () => showBanner("You are offline. Sources cannot be queried until the connection returns.", "err"));
    window.addEventListener("online", () => {
      hideBanner();
      O.toast("Back online");
    });
    let lastErr = 0;
    window.addEventListener("unhandledrejection", (e) => {
      const now = Date.now();
      if (now - lastErr < 3000) return;
      lastErr = now;
      const msg = e.reason && e.reason.message ? e.reason.message : "unexpected error";
      O.toast("Something went wrong: " + msg);
    });
  }

  /* ---------- Composer draft (per tab, survives reload) ---------- */
  function initDraft() {
    const input = $("#ioc");
    const form = $("#investigate-form");
    if (!input || !form) return;
    const KEY = "osint-draft";
    const params = new URLSearchParams(location.search);
    const resuming = document.body.hasAttribute("data-resume");
    if (!input.value && !params.get("prefill") && !input.dataset.seed && !resuming) {
      try {
        const saved = sessionStorage.getItem(KEY);
        if (saved) {
          input.value = saved;
          O.liveDetect();
        }
      } catch (e) {}
    }
    let t = 0;
    input.addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(() => {
        try {
          if (input.value) sessionStorage.setItem(KEY, input.value);
          else sessionStorage.removeItem(KEY);
        } catch (e) {}
      }, 300);
    });
    form.addEventListener("submit", () => {
      try {
        sessionStorage.removeItem(KEY);
      } catch (e) {}
    });
  }

  /* ---------- Global keys ---------- */
  function initKeys() {
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (pal.dlg && pal.dlg.open) pal.dlg.close();
        else openPalette();
        return;
      }
      const tag = (document.activeElement && document.activeElement.tagName) || "";
      const typing = tag === "TEXTAREA" || tag === "INPUT" || tag === "SELECT";
      if (e.key === "?" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        openHelp();
      }
    });
    const open = $("#cmdk-open");
    if (open) open.addEventListener("click", openPalette);
    const help = $("#help-open");
    if (help) help.addEventListener("click", openHelp);
    // Ctrl vs Cmd label
    if (/Mac|iPhone|iPad/.test(navigator.platform || "")) {
      document.querySelectorAll(".cmdk-trigger kbd:first-child, .btn-primary kbd:first-of-type").forEach((k) => {
        if (k.textContent === "Ctrl") k.textContent = "⌘";
      });
    }
  }

  function boot() {
    initDensity();
    initKeys();
    initConnection();
    initDraft();
    initReportMenu();
    // ?run=1&prefill=… from the palette: run the lookup once app.js has bound the form
    // (its DOMContentLoaded handler runs after this deferred script, so wait for "load").
    const params = new URLSearchParams(location.search);
    if (params.get("run") === "1" && params.get("prefill") && $("#investigate-form")) {
      const go = () => {
        history.replaceState({}, "", "/");
        $("#investigate-form").requestSubmit();
      };
      if (document.readyState === "complete") go();
      else window.addEventListener("load", go, { once: true });
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
