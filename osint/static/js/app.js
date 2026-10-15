/* OSINT Desk client. Provider strings are always textContent — never innerHTML. */
(function () {
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function csrf() {
    const m = document.querySelector('meta[name="csrf-token"]');
    return (m && m.content) || cookie("csrf_token") || "";
  }
  function cookie(name) {
    const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : "";
  }
  function aiLabel() {
    const m = document.querySelector('meta[name="ai-label"]');
    return (m && m.content) || "AI";
  }
  async function api(url, opts) {
    const headers = Object.assign({ "X-CSRF-Token": csrf() }, (opts && opts.headers) || {});
    if (opts && opts.json) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.json);
      delete opts.json;
    }
    const res = await fetch(url, Object.assign({ credentials: "same-origin" }, opts, { headers }));
    const ct = res.headers.get("content-type") || "";
    const body = ct.includes("application/json") ? await res.json() : await res.text();
    if (!res.ok) {
      const err = typeof body === "object" && body && body.error ? body.error : res.statusText;
      throw new Error(err);
    }
    return body;
  }
  function el(tag, attrs) {
    const n = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach((k) => {
        const v = attrs[k];
        if (v == null || v === false) return;
        if (k === "class") n.className = v;
        else if (k === "text") n.textContent = v;
        else if (k === "html") n.innerHTML = v;
        else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, v === true ? "" : String(v));
      });
    }
    for (let i = 2; i < arguments.length; i++) {
      const c = arguments[i];
      if (c == null) continue;
      n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return n;
  }
  function toast(msg) {
    let t = $(".toast");
    if (!t) {
      t = el("div", { class: "toast", role: "status" });
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), 2400);
  }

  function defang(v) {
    if (!v) return v;
    return v.replace(/https:\/\//gi, "hxxps://").replace(/http:\/\//gi, "hxxp://").replace(/\./g, "[.]").replace(/@/g, "[@]");
  }

  function relTime(iso) {
    if (!iso) return "";
    const dt = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
    if (isNaN(dt)) return iso;
    const s = (Date.now() - dt.getTime()) / 1000;
    let label = "just now";
    if (s >= 86400) label = Math.floor(s / 86400) + "d ago";
    else if (s >= 3600) label = Math.floor(s / 3600) + "h ago";
    else if (s >= 60) label = Math.floor(s / 60) + "m ago";
    return { label, title: dt.toISOString().replace("T", " ").slice(0, 16) + " UTC" };
  }

  function badgeKind(data) {
    if (data.skip_reason === "link_only") return "link";
    if (data.status === "not_found") return "notfound";
    if (data.status === "queued") return "queued";
    if (data.skip_reason === "quota_reserved") return "throttled";
    if (data.status === "error") return "error";
    if (data.status === "rate_limited") return "throttled";
    if (data.status === "no_key" || data.status === "skipped") return "skipped";
    const v = data.verdict;
    if (v === "malicious") return "malicious";
    if (v === "suspicious") return "suspicious";
    if (v === "benign") return "benign";
    if (v === "info" || data.style === "informational") return "info";
    if (data.status === "ok") return "clean";
    return "info";
  }

  const BADGE = {
    malicious: { cls: "malicious", mark: "▲", text: "Malicious" },
    suspicious: { cls: "suspicious", mark: "●", text: "Suspicious" },
    benign: { cls: "benign", mark: "✓", text: "Benign" },
    clean: { cls: "clean", mark: "○", text: "No detections" },
    info: { cls: "info", mark: "ℹ", text: "Info" },
    notfound: { cls: "notfound", mark: "—", text: "Not found" },
    link: { cls: "link", mark: "↗", text: "Link only" },
    throttled: { cls: "error", mark: "⏱", text: "Throttled" },
    queued: { cls: "info", mark: "…", text: "Queued" },
    error: { cls: "error", mark: "✕", text: "Error" },
    skipped: { cls: "skipped", mark: "✕", text: "Skipped" },
  };

  function verdictBadge(data) {
    const k = badgeKind(data);
    const meta = BADGE[k] || BADGE.info;
    const b = el("span", { class: "verdict " + meta.cls });
    b.appendChild(document.createTextNode(meta.mark + " " + meta.text));
    return b;
  }

  function hiddenCard(data) {
    if (data.skip_reason === "link_only") return true;
    if (data.status === "rate_limited" || data.status === "queued") return false;
    if (data.skip_reason === "quota_reserved") return false;
    const k = badgeKind(data);
    return k === "error" || k === "skipped";
  }

  const state = {
    lookups: [],
    results: {},
    current: null,
    indicatorId: null,
    filter: "all",
    typeFilter: "all",
    focusLookup: null,
    infoExpanded: false,
    pivotVerdicts: {},
    pasted: "",
    bulkLookups: [],
    consensus: new Set(),
    aiCache: {},
    aiPending: {},
    flippedProviders: {},
  };

  function factInSummary(summary, value) {
    if (!summary || value == null) return false;
    const s = String(summary).toLowerCase();
    const v = String(value).toLowerCase().trim();
    if (v.length < 2) return false;
    return s.indexOf(v) >= 0;
  }

  function svgIcon(d) {
    const ns = "http://www.w3.org/2000/svg";
    const s = document.createElementNS(ns, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("aria-hidden", "true");
    s.setAttribute("class", "ico");
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    p.setAttribute("fill", "none");
    p.setAttribute("stroke", "currentColor");
    p.setAttribute("stroke-width", "1.8");
    p.setAttribute("stroke-linecap", "round");
    p.setAttribute("stroke-linejoin", "round");
    s.appendChild(p);
    return s;
  }
  const ICO = {
    refresh: "M21 12a9 9 0 1 1-2.6-6.4M21 3v6h-6",
    copy: "M8 8h12v12H8zM4 16V4h12",
    ext: "M14 4h6v6M20 4 10 14",
    flip: "M4 7h11M15 7l-3-3M15 7l-3 3M20 17H9M9 17l3-3M9 17l3 3",
    raw: "M8 6h13M8 12h13M8 18h13M4 6v.01M4 12v.01M4 18v.01",
  };

  function uniqueFacts(data) {
    const out = [];
    const seen = new Set();
    (data.facts || []).forEach((f) => {
      if (!f || f.value == null) return;
      const val = String(f.value).trim();
      if (!val || /^(n\/a|none|-|unknown|null)$/i.test(val)) return;
      const key = (f.label || "").toLowerCase() + ":" + val.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ label: f.label, value: val });
    });
    return out.slice(0, 8);
  }

  function uniqueTags(data, facts) {
    const blob = (facts || []).map((f) => String(f.value).toLowerCase()).join(" ");
    const out = [];
    const seen = new Set();
    (data.tags || []).forEach((t) => {
      const s = String(t).trim();
      const k = s.toLowerCase();
      if (!s || seen.has(k) || k === "ok") return;
      if (blob.indexOf(k) >= 0) return;
      seen.add(k);
      out.push(s);
    });
    return out.slice(0, 6);
  }

  const GENERIC_SUMMARY = /^(no detections|not found|skipped|link-only|open this source|no api key|queued|throttled|cached|link only)/i;

  const PLAYBOOK = {
    virustotal: "Multi-engine file/URL/IP scan. Several independent engines agreeing is a strong malicious signal; a single generic hit is often a packer heuristic. Check the last-analysis date — stale hits on rotating C2 are common.",
    abuseipdb: "Community IP abuse reports. High confidence plus recent reports usually means scanner, brute-force, or C2. Usage type (hosting vs ISP) and whitelist status change how hard you block.",
    greynoise_community: "Internet-wide scanner noise. Classification 'malicious' vs 'benign-scanner' tells you if this is background internet chatter or targeted. Do not page on GreyNoise-only benign scanners.",
    otx: "AlienVault pulses. A pulse is a human-curated grouping, not an engine verdict. Read the pulse name/tags — they tell you the campaign, not just 'listed'.",
    threatfox: "abuse.ch C2/IOC feed. A hit here is usually malware C2 or payload hosting. Note the malware family — that is the ticket title.",
    urlhaus: "abuse.ch malware URL feed. Treat as hostile download infrastructure. Pair with the hash of the payload if you have one.",
    malwarebazaar: "abuse.ch sample corpus. Family + file type are the decision fields. First-seen tells you if this is fresh.",
    urlscan_search: "Public URL scan index. Use the screenshot/DOM as evidence; the verdict is community plus engines, not authoritative alone.",
    internetdb: "Shodan InternetDB — ports, hostnames, CVEs. Open ports and CVEs are exposure, not malice. Unexpected services on a workstation IP are the tell.",
    geoasn: "Network ownership. ASN/org/country identify the provider. Cloud/hosting ranges are easier to rotate; residential ISP is a different story.",
    rdap: "Registration/WHOIS. Creation date and registrar matter for newly stood-up domains. Privacy-protected names are normal, not a verdict.",
    dns: "Live DNS. Compare A/AAAA/MX/NS to what the alert claimed. Fast-flux or brand-new records support suspicion.",
    crtsh: "Certificate Transparency. Many certs on a young domain, or names that do not match the site, are useful for impersonation cases.",
    apivoid: "Risk scoring across blacklists. Use the score with other sources; it is a blend, not an independent engine.",
    ipqualityscore: "Fraud/proxy/VPN scoring. High fraud score on a login source is phishing-infra adjacent. Hosting + proxy together is a common C2 pattern.",
    hybrid_analysis: "Sandbox detonation. Family, signatures, and network IOCs from the run are high-value. No detonation ≠ clean.",
    triage: "Hatching Triage sandbox. Signatures and extracted config (C2, mutex) are the fields to copy into the ticket.",
    hunter: "Email-to-domain intelligence. Use to confirm whether an address is a real mailbox vs a lookalike.",
    dmarc: "SPF/DMARC/DKIM for the domain. Fail/none on a brand domain in a phishing mail is the tell; fail on a random domain is expected.",
    hashlookup: "CIRCL known-file hash. A hit means the sample was seen before — not automatically malware. Pair with VT/Bazaar.",
    disposable: "Disposable mailbox list. A hit supports phishing/throwaway infra, not malware on the host.",
    popularity: "Local top-sites list. Popular domains are rarely the threat themselves; they are often redirect or open-redirect abuse.",
  };

  function findingLines(data) {
    const kind = badgeKind(data);
    const meta = BADGE[kind] || BADGE.info;
    const name = data.provider_name || data.provider || "Source";
    const lines = [name + " · " + meta.text];
    const sum = data.summary ? String(data.summary).trim() : "";
    if (sum && !GENERIC_SUMMARY.test(sum)) lines.push(sum);
    uniqueFacts(data).forEach((f) => lines.push(f.label + ": " + f.value));
    const tags = uniqueTags(data, uniqueFacts(data));
    if (tags.length) lines.push("Tags: " + tags.join(", "));
    if (kind === "malicious") lines.push("So what: this source treats the indicator as hostile.");
    else if (kind === "suspicious") lines.push("So what: weak/unconfirmed hit — correlate before blocking.");
    else if (kind === "benign" || kind === "clean") lines.push("So what: this source is clean. Confirm it is not dual-use.");
    else if (kind === "notfound") lines.push("So what: not listed. New infra often looks like this.");
    else if (kind === "link") lines.push("So what: no API — open the vendor page to confirm.");
    else if (kind === "info") lines.push("So what: enrichment, not a detection.");
    else if (kind === "throttled" || kind === "queued") lines.push("So what: not queried yet — do not read as clean.");
    return lines;
  }

  function findingText(data) {
    return findingLines(data).join("\n");
  }

  function iconBtn(label, d, onClick) {
    const b = el("button", { type: "button", class: "icon-btn", title: label, "aria-label": label });
    b.appendChild(svgIcon(d));
    b.addEventListener("click", (ev) => {
      ev.stopPropagation();
      onClick(ev);
    });
    return b;
  }

  function renderCard(data, lookupId) {
    const kind = badgeKind(data);
    const card = el("article", {
      class: "card accent-" + kind + (kind === "link" ? " card-link" : ""),
      "data-provider": data.provider,
      "data-kind": kind,
      tabindex: "0",
      title: "Click to flip — finding summary",
    });
    const inner = el("div", { class: "card-inner" });
    const front = el("div", { class: "card-face front" });
    const head = el("div", { class: "card-head" });
    const title = el("h3", { text: data.provider_name || data.provider });
    if (kind === "malicious" || kind === "suspicious" || kind === "benign") {
      title.classList.add("tone-" + kind);
    }
    head.appendChild(title);
    head.appendChild(verdictBadge(data));
    front.appendChild(head);
    const when = relTime(data.queried_at);
    if (when) {
      const label = data.cached ? when.label + " · cache" : when.label;
      front.appendChild(el("time", { class: "cache-age", datetime: data.queried_at, title: when.title, text: label }));
    }
    if ((kind === "malicious" || kind === "suspicious") && data.queried_at) {
      const ageH = (Date.now() - new Date(data.queried_at).getTime()) / 3600000;
      if (ageH >= 24) {
        const days = Math.max(1, Math.floor(ageH / 24));
        front.appendChild(el("p", { class: "stale", text: "Flagged " + days + "d ago — consider refresh." }));
      }
    }
    const facts = uniqueFacts(data);
    const showSummary = data.summary && !GENERIC_SUMMARY.test(String(data.summary).trim()) && kind !== "link";
    if (showSummary) {
      const s = String(data.summary).trim();
      const covered = facts.some((f) => s.toLowerCase() === String(f.value).toLowerCase());
      if (!covered) front.appendChild(el("p", { class: "summary", text: s }));
    }
    if (facts.length && kind !== "link") {
      const ul = el("ul", { class: "facts" });
      facts.forEach((f) => {
        const li = el("li");
        li.appendChild(el("span", { class: "k", text: f.label }));
        li.appendChild(el("span", { class: "v", text: f.value }));
        ul.appendChild(li);
      });
      front.appendChild(ul);
    }
    const tags = uniqueTags(data, facts);
    if (tags.length && kind !== "link") {
      const wrap = el("div", { class: "tags" });
      tags.forEach((t) => {
        const agreed = state.consensus.has(String(t).toLowerCase());
        wrap.appendChild(el("span", { class: "tag" + (agreed ? " consensus" : ""), text: t, title: agreed ? "Independent sources agree" : "" }));
      });
      front.appendChild(wrap);
    }
    function flipCard(ev) {
      if (ev) ev.stopPropagation();
      card.classList.toggle("flipped");
      if (card.classList.contains("flipped")) {
        state.flippedProviders[data.provider] = true;
        loadCardExplain(card, data);
      } else {
        delete state.flippedProviders[data.provider];
      }
    }
    const foot = el("div", { class: "card-foot" });
    if (data.open_source_url) {
      const a = el("a", { href: data.open_source_url, target: "_blank", rel: "noopener noreferrer", class: "icon-btn", title: "Open source", "aria-label": "Open source" });
      a.appendChild(svgIcon(ICO.ext));
      a.addEventListener("click", (ev) => ev.stopPropagation());
      foot.appendChild(a);
    }
    if (kind !== "link") {
      foot.appendChild(iconBtn(data.status === "queued" || data.skip_reason === "quota_reserved" ? "Run" : "Refresh", ICO.refresh, () => refreshProvider(lookupId, data.provider)));
    }
    if (data.id) {
      const raw = el("button", { type: "button", class: "btn raw-btn", text: "Raw" });
      raw.addEventListener("click", (ev) => {
        ev.stopPropagation();
        showRaw(data.id, data.provider_name);
      });
      foot.appendChild(raw);
      foot.appendChild(iconBtn("Copy raw", ICO.copy, () => copyRaw(data.id)));
    }
    foot.appendChild(iconBtn("Flip finding", ICO.flip, flipCard));
    front.appendChild(foot);

    const back = el("div", { class: "card-face back" });
    const bhead = el("div", { class: "card-head" });
    bhead.appendChild(el("h3", { text: "AI" }));
    const slot = el("div", { class: "ai-explain", text: "Flip to explain this source." });
    bhead.appendChild(iconBtn("Copy explanation", ICO.copy, () => writeClip(slot.textContent || "")));
    back.appendChild(bhead);
    back.appendChild(el("p", { class: "back-src", text: data.provider_name || data.provider }));
    back.appendChild(slot);
    const again = el("button", { type: "button", class: "btn raw-btn", text: "Again" });
    again.addEventListener("click", (ev) => {
      ev.stopPropagation();
      delete state.aiCache[explainKey(data)];
      delete state.aiPending[explainKey(data)];
      loadCardExplain(card, data, true);
    });
    back.appendChild(again);
    back.appendChild(el("p", { class: "back-hint", text: "Click the card to return" }));

    inner.appendChild(front);
    inner.appendChild(back);
    card.appendChild(inner);
    if (state.flippedProviders[data.provider]) {
      card.classList.add("flipped");
      const cached = state.aiCache[explainKey(data)];
      if (cached) slot.textContent = cached;
      else if (state.aiPending[explainKey(data)]) slot.textContent = "Asking " + aiLabel() + "…";
    }
    card.addEventListener("click", (ev) => {
      if (ev.target.closest("a,button,input,select,textarea")) return;
      flipCard(ev);
    });
    card.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        flipCard(ev);
      }
    });
    return card;
  }

  function applyFilters() {
    const type = state.typeFilter || "all";
    $$(".case-section").forEach((sec) => {
      const showType = type === "all" || sec.getAttribute("data-type") === type;
      sec.classList.toggle("filtered-out", !showType);
    });
    $$(".ioc-chip").forEach((c) => {
      const showType = type === "all" || c.getAttribute("data-type") === type;
      c.classList.toggle("filtered-out", !showType);
    });
    $$(".case-section .card, #cards .card").forEach((c) => {
      const k = c.getAttribute("data-kind");
      const show = state.filter === "all" || k === state.filter;
      c.classList.toggle("filtered-out", !show);
    });
    const line = $("#ioc-line");
    if (line && (state.lookups || []).length) {
      const vis = (state.lookups || []).filter((l) => type === "all" || l.type === type);
      line.textContent = vis.length + " of " + state.lookups.length + " indicators" + (type === "all" ? "" : " · " + type);
      line.classList.remove("hidden");
    }
  }

  function applyFilter() {
    applyFilters();
  }

  function consensusTags(results) {
    const m = {};
    (results || []).forEach((r) => {
      (r.tags || []).forEach((t) => {
        const k = String(t).toLowerCase();
        if (!m[k]) m[k] = new Set();
        m[k].add(r.provider);
      });
    });
    const agreed = new Set();
    Object.keys(m).forEach((k) => {
      if (m[k].size >= 2) agreed.add(k);
    });
    return agreed;
  }

  function applyConsensus(results) {
    state.consensus = consensusTags(results);
    $$(".tag").forEach((tag) => {
      const agreed = state.consensus.has((tag.textContent || "").toLowerCase());
      tag.classList.toggle("consensus", agreed);
      if (agreed) tag.setAttribute("title", "Independent sources agree");
    });
  }

  function renderPivots(results, lookupId) {
    const host = $("#pivots");
    if (!host) return;
    host.innerHTML = "";
    const seen = new Set();
    const items = [];
    results.forEach((r) => {
      (r.related || []).forEach((rel) => {
        const k = rel.type + ":" + rel.value;
        if (seen.has(k)) return;
        seen.add(k);
        items.push(rel);
      });
    });
    if (!items.length) {
      host.classList.add("hidden");
      return;
    }
    host.classList.remove("hidden");
    host.appendChild(el("div", { class: "section-label", text: "Pivots" }));
    const row = el("div", { class: "pivot-row" });
    items.slice(0, 24).forEach((item) => {
      const key = item.type + ":" + item.value;
      const av = state.pivotVerdicts[key];
      const b = el("button", { class: "pivot" + (av ? " tagged av-" + av.verdict : ""), type: "button" });
      b.appendChild(el("small", { text: item.relation.replace(/_/g, " ") }));
      b.appendChild(el("span", { class: "v", text: defang(item.value) }));
      if (av) b.appendChild(el("span", { class: "av-tag", text: "🏷 " + av.verdict.replace(/_/g, " ") }));
      b.addEventListener("click", () => {
        const input = $("#ioc");
        if (input) input.value = item.value;
        submitLookup({ trigger: "pivot", text: item.value });
      });
      row.appendChild(b);
    });
    host.appendChild(row);
    const q = items.map((i) => i.type + ":" + i.value).join(",");
    if (host.dataset.q !== q) {
      host.dataset.q = q;
      api("/api/pivots/verdicts?q=" + encodeURIComponent(q))
        .then((d) => {
          state.pivotVerdicts = d.verdicts || {};
          if (Object.keys(state.pivotVerdicts).length) renderPivots(results, lookupId);
        })
        .catch(() => {});
    }
  }

  function renderLinks(results) {
    const host = $("#link-only");
    if (!host) return;
    const seen = new Set();
    const all = [];
    (results || []).forEach((r) => {
      if (r.skip_reason !== "link_only" || !r.open_source_url) return;
      if (seen.has(r.provider)) return;
      seen.add(r.provider);
      all.push(r);
    });
    host.innerHTML = "";
    if (!all.length) {
      host.classList.add("hidden");
      return;
    }
    host.classList.remove("hidden");
    host.appendChild(el("p", { class: "section-label", text: "Query in source" }));
    all.forEach((r) => {
      const a = el("a", {
        class: "link-row",
        href: r.open_source_url,
        target: "_blank",
        rel: "noopener noreferrer",
        title: "Open " + (r.provider_name || r.provider) + " with this IOC",
      });
      a.appendChild(el("span", { class: "link-name", text: r.provider_name || r.provider }));
      a.appendChild(el("span", { class: "link-go", text: "Open" }));
      host.appendChild(a);
    });
  }

  function decisionStance(results) {
    const vis = (results || []).filter((r) => !hiddenCard(r));
    const mal = vis.filter((r) => badgeKind(r) === "malicious");
    const sus = vis.filter((r) => badgeKind(r) === "suspicious");
    const policy = vis.find((r) => r.skip_reason === "private" || /blocked/i.test(r.summary || "") || (r.tags || []).indexOf("policy-block") >= 0);
    if (policy && vis.every((r) => r.skip_reason === "private" || hiddenCard(r) || r.provider === policy.provider)) {
      return { cls: "info", title: "Local only", why: "Private or reserved indicator — nothing left this machine. Do not treat silence as clean; just do not query it." };
    }
    if (mal.length) {
      return { cls: "malicious", title: "Escalate", why: mal.length + " source" + (mal.length === 1 ? "" : "s") + " independently marked this malicious. Pivot related infra and check logs before blocking shared services." };
    }
    if (sus.length) {
      return { cls: "suspicious", title: "Investigate", why: "Suspicious hits only — not enough to block alone. Correlate with process, user, or mail telemetry." };
    }
    const answered = vis.filter((r) => r.skip_reason !== "link_only" && badgeKind(r) !== "link");
    if (answered.length) {
      return { cls: "benign", title: "Likely benign", why: "No malicious or suspicious reputation hits. Confirm it is not dual-use (DNS, CDN, mail) before closing." };
    }
    return { cls: "info", title: "Context only", why: "No reputation answers yet. New infrastructure often looks like this." };
  }

  function dedupeHits(hits) {
    const by = {};
    hits.forEach((r) => {
      const s = String(r.summary || r.verdict || "").replace(/\s+/g, " ").trim();
      const key = s.toLowerCase();
      if (!by[key]) by[key] = { summary: s, names: [] };
      const n = r.provider_name || r.provider;
      if (by[key].names.indexOf(n) < 0) by[key].names.push(n);
    });
    return Object.keys(by).map((k) => by[k]);
  }

  const KEY_FACT_LABELS = ["asn", "as", "org", "isp", "country", "fraud score", "detections", "family", "open ports", "first seen", "registrar", "netblock", "hostnames"];

  function keyFacts(results) {
    const picked = [];
    const seenL = new Set();
    const seenV = new Set();
    (results || []).forEach((r) => {
      if (hiddenCard(r) || r.skip_reason === "link_only") return;
      (r.facts || []).forEach((f) => {
        const lab = String(f.label || "").toLowerCase();
        const val = String(f.value || "").trim();
        if (!val || seenV.has(val.toLowerCase()) || seenL.has(lab)) return;
        const want = KEY_FACT_LABELS.some((k) => lab.indexOf(k) >= 0);
        if (!want && picked.length >= 6) return;
        if (!want) return;
        seenL.add(lab);
        seenV.add(val.toLowerCase());
        picked.push({ label: f.label, value: val });
      });
    });
    return picked.slice(0, 8);
  }

  function explainKey(data) {
    return "card:" + (data.provider || data.id || "");
  }

  function paintExplain(provider, text) {
    const live = document.querySelector('.card[data-provider="' + provider + '"] .ai-explain');
    if (live) live.textContent = text;
  }

  async function loadCardExplain(card, data, force) {
    const slot = card.querySelector(".ai-explain");
    if (!slot) return;
    const key = explainKey(data);
    if (!force && state.aiCache[key]) {
      slot.textContent = state.aiCache[key];
      return;
    }
    if (state.aiPending[key]) {
      slot.textContent = "Asking " + aiLabel() + "…";
      return;
    }
    state.aiPending[key] = true;
    slot.textContent = "Asking " + aiLabel() + "…";
    const payload = {
      provider: data.provider_name || data.provider || "",
      result_id: data.id || null,
      raw: JSON.stringify({
        provider: data.provider,
        verdict: data.verdict,
        status: data.status,
        summary: data.summary,
        facts: data.facts || [],
        tags: data.tags || [],
      }),
    };
    try {
      const d = await api("/api/ai/explain", { method: "POST", json: payload });
      state.aiCache[key] = d.text;
      paintExplain(data.provider, d.text);
    } catch (e) {
      const msg = e.message + " — open the AI tab to set the model and key.";
      state.aiCache[key] = msg;
      paintExplain(data.provider, msg);
    } finally {
      delete state.aiPending[key];
    }
  }

  function renderSummaryPanel(results) {
    const host = $("#summary-panel");
    if (!host) return;
    const vis = (results || []).filter((r) => !hiddenCard(r));
    if (!vis.length) {
      host.classList.add("hidden");
      return;
    }
    const wasFlipped = host.classList.contains("flipped");
    host.classList.remove("hidden");
    host.innerHTML = "";
    host.classList.add("is-flip");
    host.setAttribute("tabindex", "0");
    host.setAttribute("title", "Click to flip — AI explanation");
    const stance = decisionStance(vis);
    host.classList.remove("malicious", "suspicious", "benign", "info");
    host.classList.add(stance.cls);
    const inner = el("div", { class: "card-inner" });
    const front = el("div", { class: "card-face front" });
    const head = el("div", { class: "sum-head" });
    head.appendChild(el("p", { class: "sum-kicker", text: "Decision" }));
    head.appendChild(iconBtn("Copy summary", ICO.copy, () => copyLocalSummary(vis)));
    front.appendChild(head);
    front.appendChild(el("h2", { text: stance.title }));
    front.appendChild(el("p", { class: "sum-why", text: stance.why }));
    const hits = vis.filter((r) => badgeKind(r) === "malicious" || badgeKind(r) === "suspicious");
    const deduped = dedupeHits(hits);
    if (deduped.length) {
      front.appendChild(el("div", { class: "section-label", text: "Why" }));
      deduped.slice(0, 6).forEach((h) => {
        front.appendChild(el("p", { class: "sum-hit", text: h.names.join(", ") + (h.summary ? " — " + h.summary : "") }));
      });
    }
    const agreed = Array.from(consensusTags(vis));
    if (agreed.length) {
      front.appendChild(el("div", { class: "section-label", text: "Agreement" }));
      const wrap = el("div", { class: "tags" });
      agreed.slice(0, 8).forEach((t) => wrap.appendChild(el("span", { class: "tag consensus", text: t })));
      front.appendChild(wrap);
    }
    const kf = keyFacts(vis);
    if (kf.length) {
      front.appendChild(el("div", { class: "section-label", text: "Context" }));
      const ul = el("ul", { class: "facts" });
      kf.forEach((f) => {
        const li = el("li");
        li.appendChild(el("span", { class: "k", text: f.label }));
        li.appendChild(el("span", { class: "v", text: f.value }));
        ul.appendChild(li);
      });
      front.appendChild(ul);
    }
    const back = el("div", { class: "card-face back" });
    const bhead = el("div", { class: "card-head" });
    bhead.appendChild(el("h3", { text: "AI" }));
    const slot = el("div", { class: "ai-explain", text: "Flip to explain this summary." });
    bhead.appendChild(iconBtn("Copy explanation", ICO.copy, () => writeClip(slot.textContent || "")));
    back.appendChild(bhead);
    back.appendChild(slot);
    const again = el("button", { type: "button", class: "btn raw-btn", text: "Again" });
    again.addEventListener("click", (ev) => {
      ev.stopPropagation();
      delete state.aiCache.summary;
      delete state.aiPending.summary;
      loadSummaryExplain(slot, true);
    });
    back.appendChild(again);
    back.appendChild(el("p", { class: "back-hint", text: "Click the card to return" }));
    inner.appendChild(front);
    inner.appendChild(back);
    host.appendChild(inner);
    if (wasFlipped) {
      host.classList.add("flipped");
      if (state.aiCache.summary) slot.textContent = state.aiCache.summary;
      else if (state.aiPending.summary) slot.textContent = "Asking " + aiLabel() + "…";
      else loadSummaryExplain(slot, false);
    }
    function flipSum(ev) {
      if (ev) ev.stopPropagation();
      host.classList.toggle("flipped");
      if (host.classList.contains("flipped")) loadSummaryExplain(slot, false);
    }
    host.onclick = (ev) => {
      if (ev.target.closest("a,button,input,select,textarea")) return;
      flipSum(ev);
    };
    host.onkeydown = (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        flipSum(ev);
      }
    };
  }

  async function loadSummaryExplain(slot, force) {
    if (!slot) return;
    if (!force && state.aiCache.summary) {
      slot.textContent = state.aiCache.summary;
      return;
    }
    if (state.aiPending.summary) {
      slot.textContent = "Asking " + aiLabel() + "…";
      return;
    }
    state.aiPending.summary = true;
    slot.textContent = "Asking " + aiLabel() + "…";
    const ids = (state.lookups || []).map((l) => l.lookup_id);
    if (!ids.length && state.current) ids.push(state.current);
    try {
      const d = await api("/api/ai/explain-summary", { method: "POST", json: { lookup_ids: ids } });
      state.aiCache.summary = d.text;
    } catch (e) {
      state.aiCache.summary = e.message + " — open the AI tab to set the model and key.";
    } finally {
      delete state.aiPending.summary;
      const live = document.querySelector("#summary-panel .ai-explain");
      if (live && state.aiCache.summary) live.textContent = state.aiCache.summary;
    }
  }

  function allResults() {
    const ids = (state.lookups || []).map((l) => l.lookup_id);
    if (!ids.length && state.current) ids.push(state.current);
    const all = [];
    ids.forEach((id) => (state.results[id] || []).forEach((r) => all.push(r)));
    return all;
  }

  function setRollup(s, results) {
    const box = $("#rollup");
    if (!box) return;
    box.classList.remove("hidden");
    const vis = (results && results.length ? results : allResults()) || [];
    const counts = {
      malicious: s.malicious || 0,
      suspicious: s.suspicious || 0,
      benign: s.benign || 0,
      clean: 0,
      info: s.info || 0,
      notfound: s.not_found || 0,
      error: s.errors || 0,
      link: s.link_only || 0,
    };
    if (vis.length) {
      counts.malicious = vis.filter((r) => badgeKind(r) === "malicious").length;
      counts.suspicious = vis.filter((r) => badgeKind(r) === "suspicious").length;
      counts.benign = vis.filter((r) => badgeKind(r) === "benign").length;
      counts.clean = vis.filter((r) => badgeKind(r) === "clean").length;
      counts.info = vis.filter((r) => badgeKind(r) === "info").length;
      counts.notfound = vis.filter((r) => badgeKind(r) === "notfound").length;
      counts.error = vis.filter((r) => badgeKind(r) === "error" || r.status === "rate_limited" || badgeKind(r) === "throttled" || badgeKind(r) === "queued").length;
      counts.link = vis.filter((r) => badgeKind(r) === "link" || r.skip_reason === "link_only").length;
    }
    box.innerHTML = "";
    const queried = vis.filter((r) => r.skip_reason !== "link_only" && !hiddenCard(r)).length;
    const total = vis.length || queried || 1;
    const allBtn = el("button", {
      type: "button",
      class: "stat filter-pill" + (state.filter === "all" ? " on" : ""),
      "data-filter": "all",
    });
    allBtn.appendChild(el("div", { class: "n", text: queried + "/" + total }));
    allBtn.appendChild(el("div", { class: "l", text: "Sources" }));
    allBtn.addEventListener("click", () => {
      state.filter = "all";
      paintPills();
      applyFilters();
    });
    box.appendChild(allBtn);
    [
      ["malicious", "Malicious", counts.malicious],
      ["suspicious", "Suspicious", counts.suspicious],
      ["benign", "Benign", counts.benign],
      ["clean", "No detections", counts.clean],
      ["info", "Info", counts.info],
      ["link", "Link-only", counts.link],
      ["notfound", "Not found", counts.notfound],
      ["error", "Throttled / error", counts.error],
    ].forEach(([k, label, n]) => {
      if (!n) return;
      const b = el("button", {
        type: "button",
        class: "stat " + k + " filter-pill" + (state.filter === k ? " on" : ""),
        "data-filter": k,
      });
      b.appendChild(el("div", { class: "n", text: String(n) }));
      b.appendChild(el("div", { class: "l", text: label }));
      b.addEventListener("click", () => {
        state.filter = state.filter === k ? "all" : k;
        paintPills();
        applyFilters();
      });
      box.appendChild(b);
    });
    function paintPills() {
      $$(".filter-pill", box).forEach((p) => {
        p.classList.toggle("on", p.getAttribute("data-filter") === state.filter);
      });
    }
    const cov = $("#coverage");
    if (cov) {
      const parts = [];
      parts.push(queried + " of " + total + " sources on screen");
      if (counts.link) parts.push(counts.link + " link-only always listed");
      const disagree = !!(s.disagreement && ((s.malicious || counts.malicious) && (s.benign || counts.benign)));
      if (disagree) parts.push("Sources disagree");
      if (s.consensus && s.consensus.length) parts.push("Agreement: " + s.consensus.join("; "));
      if (s.context_flags && s.context_flags.length) {
        const flags = s.context_flags.filter((f) => !/disagree/i.test(f));
        if (flags.length) parts.push(flags.join("; "));
      }
      cov.textContent = parts.join(" · ");
    }
    const qline = $("#quota-line");
    if (qline && vis.length) {
      const bits = [];
      vis.forEach((r) => {
        if (!r.quota) return;
        Object.keys(r.quota).forEach((w) => {
          const q = r.quota[w];
          if (q && q.limit) bits.push(r.provider_name + " " + w + " " + q.used + "/" + q.limit);
        });
      });
      if (bits.length) {
        qline.textContent = "Quota: " + bits.slice(0, 4).join(" · ");
        qline.classList.remove("hidden");
      }
    }
    $("#toolbar") && $("#toolbar").classList.remove("hidden");
    $("#analyst") && $("#analyst").classList.remove("hidden");
  }

  function attachStream(lookupId, mount) {
    const es = new EventSource("/api/lookups/" + lookupId + "/stream");
    const grid = mount || $("#cards");
    state.results[lookupId] = state.results[lookupId] || [];
    es.addEventListener("lookup_started", (ev) => {
      const d = JSON.parse(ev.data);
      const line = $("#ioc-line");
      if (line) {
        const n = (state.lookups || []).length;
        if (n > 1) {
          line.textContent = n + " indicators running";
        } else {
          line.textContent = (d.indicator.type || "") + "  " + defang(d.indicator.value);
        }
        line.classList.remove("hidden");
      }
      $("#empty-state") && $("#empty-state").classList.add("hidden");
      $("#recent-chips") && $("#recent-chips").classList.add("hidden");
      $("#live") && $("#live").classList.remove("hidden");
      if (grid && !grid.dataset.ready) {
        grid.innerHTML = "";
        grid.dataset.ready = "1";
      }
    });
    es.addEventListener("provider_result", (ev) => {
      const d = JSON.parse(ev.data);
      const list = state.results[lookupId];
      const idx = list.findIndex((x) => x.provider === d.provider);
      if (idx >= 0) list[idx] = d;
      else list.push(d);
      if (grid && !hiddenCard(d)) {
        const existing = grid.querySelector('[data-provider="' + d.provider + '"]');
        const node = renderCard(d, lookupId);
        if (state.filter !== "all" && node.getAttribute("data-kind") !== state.filter) node.classList.add("filtered-out");
        if (existing) existing.replaceWith(node);
        else {
          // reputation/sandbox before facts
          const tier = d.tier || "reputation";
          if (tier === "facts" || tier === "identity") grid.appendChild(node);
          else {
            const factsFirst = grid.querySelector('[data-kind="info"],[data-kind="clean"]');
            if (factsFirst) grid.insertBefore(node, factsFirst);
            else grid.appendChild(node);
          }
        }
      }
      renderPivots(list, lookupId);
      if (!state.focusLookup || lookupId === state.focusLookup) renderLinks(list);
      renderSummaryPanel(allResults());
      applyConsensus(allResults());
      setRollup({}, allResults());
      applyFilters();
      paintBulkRollup();
      refreshQuota();
    });
    es.addEventListener("summary", (ev) => {
      const s = JSON.parse(ev.data);
      setRollup(s, allResults());
    });
    es.addEventListener("child_started", (ev) => {
      const d = JSON.parse(ev.data);
      const parentSec = grid && grid.closest ? grid.closest(".case-section") : null;
      const holder = parentSec || $("#child");
      if (!holder) return;
      holder.classList.remove("hidden");
      let childHost = holder.querySelector(".child-block");
      if (!childHost) {
        childHost = el("div", { class: "child-block" });
        holder.appendChild(childHost);
      }
      childHost.classList.remove("hidden");
      childHost.innerHTML = "";
      childHost.appendChild(el("div", { class: "section-label", text: "Host / domain lookup (auto)" }));
      childHost.appendChild(el("p", { class: "ioc-line", text: defang(d.value) }));
      const childGrid = el("div", { class: "grid" });
      childHost.appendChild(childGrid);
      attachStream(d.lookup_id, childGrid);
    });
    es.addEventListener("done", () => es.close());
    return es;
  }

  function renderExtracted(lookups) {
    const host = $("#extracted");
    const tray = $("#ioc-tray");
    const bar = $("#type-bar");
    if (!host || !tray || !bar) return;
    if (!lookups || lookups.length < 2) {
      host.classList.add("hidden");
      return;
    }
    host.classList.remove("hidden");
    const counts = {};
    lookups.forEach((l) => {
      counts[l.type] = (counts[l.type] || 0) + 1;
    });
    bar.innerHTML = "";
    const types = ["all", "ip", "domain", "url", "hash", "email"];
    types.forEach((t) => {
      const n = t === "all" ? lookups.length : counts[t] || 0;
      if (t !== "all" && !n) return;
      const b = el("button", {
        type: "button",
        class: "type-pill" + (state.typeFilter === t ? " on" : ""),
        "data-type": t,
        role: "tab",
        "aria-selected": state.typeFilter === t ? "true" : "false",
      });
      b.appendChild(document.createTextNode(t === "all" ? "All" : t));
      b.appendChild(el("span", { class: "n", text: String(n) }));
      b.addEventListener("click", () => {
        state.typeFilter = t;
        $$(".type-pill", bar).forEach((p) => {
          const on = p.getAttribute("data-type") === t;
          p.classList.toggle("on", on);
          p.setAttribute("aria-selected", on ? "true" : "false");
        });
        applyFilters();
        const first = $(".case-section" + (t === "all" ? "" : '[data-type="' + t + '"]') + ":not(.filtered-out)");
        if (first) first.scrollIntoView({ behavior: "smooth", block: "start" });
      });
      bar.appendChild(b);
    });
    tray.innerHTML = "";
    lookups.forEach((lu) => {
      const b = el("div", {
        class: "ioc-chip" + (state.focusLookup === lu.lookup_id ? " on" : ""),
        "data-type": lu.type,
        "data-lookup": lu.lookup_id,
        role: "button",
        tabindex: "0",
      });
      b.appendChild(el("span", { class: "t", text: lu.type + (lu.origin === "ai" ? " · AI" : "") }));
      b.appendChild(el("span", { class: "v", text: defang(lu.value) }));
      b.appendChild(iconBtn("Copy " + lu.type, ICO.copy, () => writeClip(defang(lu.value))));
      b.addEventListener("click", () => focusLookup(lu));
      b.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          focusLookup(lu);
        }
      });
      tray.appendChild(b);
    });
  }

  function focusLookup(lu) {
    state.current = lu.lookup_id;
    state.focusLookup = lu.lookup_id;
    $$(".ioc-chip").forEach((c) => c.classList.toggle("on", c.getAttribute("data-lookup") === lu.lookup_id));
    const focus = $("#analyst-focus");
    if (focus) focus.textContent = lu.type + "  " + defang(lu.value);
    const sec = document.getElementById("sec-" + lu.lookup_id);
    if (sec) sec.scrollIntoView({ behavior: "smooth", block: "start" });
    renderLinks(state.results[lu.lookup_id] || []);
    fetch("/api/lookups/" + lu.lookup_id)
      .then((r) => r.json())
      .then((b) => {
        if (b.indicator) {
          state.indicatorId = b.indicator.id;
          renderAnalyst(b.analyst, b.analyst_history);
        }
        if (b.results && b.results.length) {
          state.results[lu.lookup_id] = b.results;
          renderLinks(b.results);
        }
      })
      .catch(() => {});
  }

  function renderHunt(pack) {
    state.hunt = pack || null;
    const host = $("#hunt-panel");
    if (host) host.classList.add("hidden");
  }

  function renderCaseBoard(lookups) {
    const board = $("#case-board");
    if (!board) return;
    board.innerHTML = "";
    lookups.forEach((lu) => {
      const sec = el("section", {
        class: "case-section",
        id: "sec-" + lu.lookup_id,
        "data-lookup": lu.lookup_id,
        "data-type": lu.type,
      });
      const head = el("div", { class: "case-head" });
      const line = el("button", { type: "button", class: "ioc-line case-jump", text: lu.type + "  " + defang(lu.value) });
      line.addEventListener("click", () => focusLookup(lu));
      head.appendChild(line);
      head.appendChild(iconBtn("Copy", ICO.copy, () => writeClip(defang(lu.value))));
      if (lookups.length === 1) head.classList.add("hidden");
      sec.appendChild(head);
      const grid = el("div", { class: "grid" });
      sec.appendChild(grid);
      board.appendChild(sec);
      attachStream(lu.lookup_id, grid);
    });
  }

  async function submitLookup(opts) {
    opts = opts || {};
    const input = $("#ioc");
    const text = opts.text != null ? opts.text : input ? input.value : "";
    if (!text || !text.trim()) return;
    state.pasted = text;
    state.typeFilter = "all";
    state.filter = "all";
    const payload = { text: text, trigger: opts.trigger || "manual" };
    if (opts.force_full) payload.force_full = true;
    if ($("#use-ai") && $("#use-ai").checked) payload.use_ai = true;
    const data = await api("/api/lookups", { method: "POST", json: payload });
    if (!data.lookups || !data.lookups.length) {
      toast("No indicators found");
      return;
    }
    state.lookups = data.lookups;
    state.bulkLookups = data.lookups;
    state.current = data.lookups[0].lookup_id;
    state.focusLookup = state.current;
    state.results = {};
    state.aiCache = {};
    state.aiPending = {};
    state.flippedProviders = {};
    const grid = $("#cards");
    if (grid) {
      grid.innerHTML = "";
      grid.classList.add("hidden");
    }
    ["pivots", "link-only", "child", "ai-out", "hunt-panel"].forEach((id) => {
      const n = document.getElementById(id);
      if (n) n.classList.add("hidden");
    });
    $("#empty-state") && $("#empty-state").classList.add("hidden");
    $("#recent-chips") && $("#recent-chips").classList.add("hidden");
    $("#live") && $("#live").classList.remove("hidden");
    renderExtracted(data.lookups);
    renderCaseBoard(data.lookups);
    renderHunt(data.hunt);
    focusLookup(data.lookups[0]);
    history.replaceState({}, "", "/lookup/" + state.current);
  }

  async function refreshProvider(lookupId, provider) {
    const data = await api("/api/lookups/" + lookupId + "/refresh", { method: "POST", json: { provider: provider } });
    if (data.lookups && data.lookups[0]) attachStream(data.lookups[0].lookup_id, $("#cards"));
  }

  async function showRaw(id, name) {
    try {
      const d = await api("/api/results/" + id + "/raw");
      const raw = d.raw;
      const text = typeof raw === "string" ? raw : JSON.stringify(raw, null, 2);
      showModal((name || "Source") + " — raw", text || "(empty)");
    } catch (e) {
      toast(e.message);
    }
  }

  async function copyRaw(id) {
    try {
      const d = await api("/api/results/" + id + "/raw");
      const raw = d.raw;
      const text = typeof raw === "string" ? raw : JSON.stringify(raw, null, 2);
      writeClip(text || "");
    } catch (e) {
      toast(e.message);
    }
  }

  async function explainCard(id, provider) {
    const out = $("#ai-out");
    if (out) {
      out.classList.remove("hidden");
      out.textContent = "Asking " + aiLabel() + "…";
    }
    try {
      const d = await api("/api/ai/explain", { method: "POST", json: { result_id: id, provider: provider } });
      if (out) out.textContent = (d.ai && d.ai.label ? d.ai.label + "\n\n" : "") + d.text;
    } catch (e) {
      if (out) out.textContent = e.message;
    }
  }

  function showModal(title, text) {
    let m = document.getElementById("summary-modal");
    if (m) m.remove();
    m = el("div", { id: "summary-modal", class: "modal" });
    const panel = el("div", { class: "modal-panel" });
    panel.appendChild(el("h2", { text: title }));
    const pre = el("pre", { class: "summary-pre" });
    pre.textContent = text;
    panel.appendChild(pre);
    const row = el("div", { class: "composer-actions" });
    const copy = el("button", { class: "btn btn-primary", type: "button", text: "Copy" });
    copy.addEventListener("click", () => writeClip(text));
    const close = el("button", { class: "btn", type: "button", text: "Close" });
    close.addEventListener("click", () => m.remove());
    row.appendChild(copy);
    row.appendChild(close);
    panel.appendChild(row);
    m.appendChild(panel);
    m.addEventListener("click", (ev) => {
      if (ev.target === m) m.remove();
    });
    document.body.appendChild(m);
  }

  async function writeClip(str) {
    try {
      await navigator.clipboard.writeText(str);
      toast("Copied");
    } catch (e) {
      const ta = el("textarea", { class: "sr-only" });
      ta.value = str;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        toast("Copied");
      } catch (e2) {
        showModal("Copy", str);
      }
      ta.remove();
    }
  }

  function copyLocalSummary(results) {
    const vis = results && results.length ? results : allResults();
    const tlp = ($("#tlp") && $("#tlp").value) || "CLEAR";
    const stance = decisionStance(vis);
    const lines = ["TLP:" + tlp, "", stance.title, stance.why];
    const hits = vis.filter((r) => badgeKind(r) === "malicious" || badgeKind(r) === "suspicious");
    const deduped = dedupeHits(hits);
    if (deduped.length) {
      lines.push("", "Why");
      deduped.forEach((h) => lines.push("- " + h.names.join(", ") + (h.summary ? " — " + h.summary : "")));
    }
    const kf = keyFacts(vis);
    if (kf.length) {
      lines.push("", "Context");
      kf.forEach((f) => lines.push("- " + f.label + ": " + f.value));
    }
    writeClip(lines.join("\n"));
  }

  function openGraph() {
    const lu = (state.lookups || []).find((l) => l.lookup_id === state.focusLookup) || (state.lookups || [])[0];
    if (!lu) {
      toast("Run a lookup first");
      return;
    }
    window.location.href = "/graph?type=" + encodeURIComponent(lu.type) + "&value=" + encodeURIComponent(lu.value);
  }

  function paintHistory(items) {
    const list = $("#hist-list");
    if (!list) return;
    list.innerHTML = "";
    if (!items || !items.length) {
      list.appendChild(el("div", { class: "empty compact" }, el("p", { text: "No matches." })));
      return;
    }
    items.forEach((it) => {
      const a = el("a", { class: "hist", href: "/?prefill=" + encodeURIComponent(it.value) });
      a.appendChild(el("span", { class: "t", text: it.type || "" }));
      a.appendChild(el("span", { class: "v", text: defang(it.value || "") }));
      const when = relTime(it.last_seen);
      let meta = (it.lookup_count || 0) + " lookup" + (it.lookup_count === 1 ? "" : "s");
      if (when && when.label) meta += " · " + when.label;
      if (it.analyst && it.analyst.verdict) meta += " · " + String(it.analyst.verdict).replace(/_/g, " ");
      a.appendChild(el("span", { class: "meta", text: meta }));
      list.appendChild(a);
    });
  }

  function initHistory() {
    const q = $("#hist-q");
    const type = $("#hist-type");
    if (!q && !type) return;
    const form = $("#hist-form");
    if (form) {
      form.addEventListener("submit", (e) => e.preventDefault());
    }
    let t = 0;
    function go() {
      const qs = new URLSearchParams();
      if (q && q.value.trim()) qs.set("q", q.value.trim());
      if (type && type.value) qs.set("type", type.value);
      const url = "/api/search" + (qs.toString() ? "?" + qs.toString() : "");
      api(url)
        .then((d) => paintHistory(d.items || []))
        .catch((e) => toast(e.message));
      const next = "/history" + (qs.toString() ? "?" + qs.toString() : "");
      history.replaceState({}, "", next);
    }
    if (q) {
      q.addEventListener("input", () => {
        clearTimeout(t);
        t = setTimeout(go, 180);
      });
    }
    if (type) type.addEventListener("change", go);
  }

  async function copyIocs() {
    const lookups = state.lookups || [];
    if (!lookups.length) {
      toast("Run an investigation first");
      return;
    }
    const type = state.typeFilter || "all";
    const rows = lookups
      .filter((l) => type === "all" || l.type === type)
      .map((l) => l.type + "\t" + defang(l.value));
    writeClip(rows.join("\n"));
  }

  async function copyHunt() {
    const pack = state.hunt;
    if (!pack) {
      toast("Run an investigation first");
      return;
    }
    const bits = [];
    if (pack.splunk) bits.push("Splunk:\n" + pack.splunk);
    if (pack.kql) bits.push("KQL:\n" + pack.kql);
    if (pack.elastic) bits.push("Elastic:\n" + pack.elastic);
    if (pack.grep) bits.push("grep:\n" + pack.grep);
    writeClip(bits.join("\n\n") || pack.defanged || "");
  }

  async function copySummary() {
    const vis = allResults();
    if (!state.current && !vis.length) {
      toast("Run an investigation first");
      return;
    }
    const tlp = ($("#tlp") && $("#tlp").value) || "CLEAR";
    const extra = (state.lookups || []).slice(1).map((l) => l.lookup_id).join(",");
    if (!state.current) {
      copyLocalSummary(vis);
      return;
    }
    try {
      const qs = "format=md&tlp=" + encodeURIComponent(tlp) + (extra ? "&extra=" + encodeURIComponent(extra) : "");
      const text = await api("/api/lookups/" + state.current + "/summary?" + qs);
      writeClip(typeof text === "string" ? text : String(text));
    } catch (e) {
      copyLocalSummary(vis);
    }
  }

  function renderAnalyst(active, history) {
    const sel = $("#av-verdict");
    const note = $("#av-note");
    if (sel) {
      sel.disabled = !state.indicatorId;
      sel.value = (active && active.verdict) || "";
    }
    if (note) {
      note.disabled = !state.indicatorId;
      note.value = active ? active.note || "" : "";
    }
    const hist = $("#av-history");
    if (!hist) return;
    hist.innerHTML = "";
    if (active) {
      hist.appendChild(el("p", { text: active.verdict.replace(/_/g, " ") + (active.note ? " — " + active.note : "") }));
    }
    (history || []).slice(0, 4).forEach((h) => {
      const t = relTime(h.created_at);
      hist.appendChild(el("p", { class: "tos", text: (t.label || "") + " · " + h.verdict.replace(/_/g, " ") + (h.note ? " — " + h.note : "") }));
    });
  }

  async function saveVerdict(v) {
    if (!state.indicatorId) {
      toast("Wait for the lookup to start");
      return;
    }
    const note = ($("#av-note") && $("#av-note").value) || "";
    const d = await api("/api/indicators/" + state.indicatorId + "/verdict", {
      method: "POST",
      json: { verdict: v, note: note },
    });
    renderAnalyst(d.active, d.history);
    toast("Verdict saved");
  }

  function autosizeIoc() {
    const ta = $("#ioc");
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = Math.min(Math.max(ta.scrollHeight, 40), 220) + "px";
  }

  let detectTimer;
  function liveDetect() {
    const input = $("#ioc");
    if (!input) return;
    autosizeIoc();
    clearTimeout(detectTimer);
    detectTimer = setTimeout(async () => {
      const text = input.value;
      const hint = $("#extract-hint");
      if (!text.trim()) {
        if (hint) hint.textContent = "";
        return;
      }
      try {
        const data = await api("/api/detect", { method: "POST", json: { text: text } });
        const n = (data.indicators || []).length;
        if (hint) {
          if (!n) hint.textContent = "";
          else if (n === 1) hint.textContent = data.indicators[0].type;
          else hint.textContent = n + " indicators";
        }
      } catch (e) {}
    }, 220);
  }

  async function saveKey(id) {
    const input = document.querySelector('[data-key-for="' + id + '"]');
    if (!input || !input.value) return;
    await api("/api/providers", { method: "PUT", json: { id: id, key: input.value } });
    input.value = "";
    toast("Key saved locally");
    setTimeout(() => location.reload(), 400);
  }

  function initGraph() {
    const canvas = $("#graph-svg");
    if (!canvas) return;
    const blob = document.getElementById("graph-data");
    const raw = blob ? blob.textContent : canvas.getAttribute("data-graph");
    if (!raw) return;
    let data;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      return;
    }
    const nodes = data.nodes || [];
    const edges = data.edges || [];
    if (!nodes.length) return;
    const w = canvas.clientWidth || 800;
    const h = canvas.clientHeight || 520;
    canvas.setAttribute("viewBox", "0 0 " + w + " " + h);
    const pts = nodes.map((n, i) => {
      const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
      const r = Math.min(w, h) * 0.32;
      return { id: n.id, x: w / 2 + Math.cos(a) * r, y: h / 2 + Math.sin(a) * r, n: n };
    });
    const byId = {};
    pts.forEach((p) => (byId[p.id] = p));
    const ns = "http://www.w3.org/2000/svg";
    function svg(name, attrs) {
      const e = document.createElementNS(ns, name);
      Object.keys(attrs || {}).forEach((k) => e.setAttribute(k, attrs[k]));
      return e;
    }
    while (canvas.firstChild) canvas.removeChild(canvas.firstChild);
    const stroke = getComputedStyle(document.documentElement).getPropertyValue("--fg").trim() || "#eceae4";
    edges.forEach((e) => {
      const a = byId[e.from],
        b = byId[e.to];
      if (!a || !b) return;
      canvas.appendChild(svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: stroke, "stroke-opacity": "0.2", "stroke-width": "1" }));
    });
    pts.forEach((p, i) => {
      const g = svg("g", { style: "cursor:pointer" });
      g.appendChild(svg("circle", { cx: p.x, cy: p.y, r: 6, fill: stroke }));
      const t = svg("text", {
        x: String(p.x + 10),
        y: String(p.y + 4 + (i % 3 - 1) * 12),
        class: "node-label",
        fill: stroke,
      });
      t.textContent = defang(p.n.value || "").slice(0, 28);
      g.appendChild(t);
      g.addEventListener("click", () => {
        window.location.href = "/?prefill=" + encodeURIComponent(p.n.value);
      });
      canvas.appendChild(g);
    });
  }

  function initRail() {
    const btn = $("#rail-toggle");
    function apply(collapsed) {
      document.body.classList.toggle("rail-collapsed", collapsed);
      if (btn) {
        btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
        btn.setAttribute("aria-label", collapsed ? "Expand navigation" : "Collapse navigation");
        btn.setAttribute("title", collapsed ? "Expand navigation" : "Collapse navigation");
      }
      try {
        localStorage.setItem("osint-rail", collapsed ? "collapsed" : "open");
      } catch (e) {}
      document.cookie = "osint_rail=" + (collapsed ? "collapsed" : "open") + "; path=/; max-age=31536000; samesite=lax";
    }
    if (btn) {
      btn.addEventListener("click", () => apply(!document.body.classList.contains("rail-collapsed")));
    }
  }

  function initAi() {
    const form = $("#ai-form");
    if (!form) return;
    const out = $("#ai-out");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        base_url: $("#ai-base").value.trim(),
        model: $("#ai-model").value.trim(),
        system_prompt: $("#ai-prompt").value,
        temperature: $("#ai-temp").value,
        max_tokens: $("#ai-tokens").value,
        clear_key: !!($("#ai-clear-key") && $("#ai-clear-key").checked),
      };
      const key = $("#ai-key").value.trim();
      if (key) payload.api_key = key;
      try {
        const d = await api("/api/ai/settings", { method: "POST", json: payload });
        $("#ai-key").value = "";
        if ($("#ai-clear-key")) $("#ai-clear-key").checked = false;
        toast(d.has_key ? "AI saved · key set" : "AI saved");
        if (out) {
          out.classList.remove("hidden");
          out.textContent = "Saved. " + (d.label || d.model);
        }
      } catch (err) {
        toast(err.message);
      }
    });
    $("#ai-test") &&
      $("#ai-test").addEventListener("click", async () => {
        if (out) {
          out.classList.remove("hidden");
          out.textContent = "Testing…";
        }
        try {
          const d = await api("/api/ai/test", { method: "POST", json: {} });
          if (out) out.textContent = (d.ai && d.ai.label ? d.ai.label + "\n\n" : "") + d.text;
        } catch (err) {
          if (out) out.textContent = err.message;
        }
      });
    $("#ai-reset-prompt") &&
      $("#ai-reset-prompt").addEventListener("click", () => {
        const raw = $("#ai-default-prompt");
        if (!raw || !$("#ai-prompt")) return;
        try {
          $("#ai-prompt").value = JSON.parse(raw.textContent);
        } catch (e) {
          $("#ai-prompt").value = raw.textContent;
        }
      });
  }

  function initTheme() {
    const saved = localStorage.getItem("osint-theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    const btn = $("#theme-toggle");
    if (!btn) return;
    btn.textContent = saved === "light" ? "Dark theme" : "Light theme";
    btn.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("osint-theme", next);
      btn.textContent = next === "light" ? "Dark theme" : "Light theme";
    });
  }

  function paintBulkRollup() {
    const box = $("#bulk-rollup");
    if (!box) return;
    const ids = (state.bulkLookups || []).map((l) => l.lookup_id);
    const all = [];
    ids.forEach((id) => (state.results[id] || []).forEach((r) => all.push(r)));
    const mal = all.filter((r) => badgeKind(r) === "malicious").length;
    const sus = all.filter((r) => badgeKind(r) === "suspicious").length;
    const thr = all.filter((r) => badgeKind(r) === "throttled" || badgeKind(r) === "queued").length;
    box.innerHTML = "";
    box.appendChild(el("div", { class: "stat", text: ids.length + " indicators" }));
    if (mal) {
      const s = el("div", { class: "stat malicious" });
      s.appendChild(el("div", { class: "n", text: String(mal) }));
      s.appendChild(el("div", { class: "l", text: "Malicious" }));
      box.appendChild(s);
    }
    if (sus) {
      const s = el("div", { class: "stat suspicious" });
      s.appendChild(el("div", { class: "n", text: String(sus) }));
      s.appendChild(el("div", { class: "l", text: "Suspicious" }));
      box.appendChild(s);
    }
    if (thr) {
      const s = el("div", { class: "stat error" });
      s.appendChild(el("div", { class: "n", text: String(thr) }));
      s.appendChild(el("div", { class: "l", text: "Throttled" }));
      box.appendChild(s);
    }
  }

  async function copyBulk() {
    const ids = (state.bulkLookups || []).map((l) => l.lookup_id);
    if (!ids.length) {
      toast("Run a bulk investigation first");
      return;
    }
    const tlp = ($("#bulk-tlp") && $("#bulk-tlp").value) || "CLEAR";
    try {
      const text = await api("/api/summary?ids=" + encodeURIComponent(ids.join(",")) + "&format=md&tlp=" + encodeURIComponent(tlp));
      writeClip(typeof text === "string" ? text : String(text));
    } catch (e) {
      toast(e.message);
    }
  }

  let quotaTimer = 0;
  async function refreshQuota() {
    const now = Date.now();
    if (now - quotaTimer < 4000) return;
    quotaTimer = now;
    const hosts = [$("#quota-line"), $("#bulk-quota")].filter(Boolean);
    if (!hosts.length) return;
    try {
      const d = await api("/api/quota");
      const tight = (d.providers || []).filter((p) => p.tight || p.blocked || p.reserved);
      const bits = tight.map((p) => {
        const w = p.windows || {};
        const parts = Object.keys(w).map((k) => k + " " + w[k].used + "/" + w[k].limit);
        return p.name + (parts.length ? " " + parts.join(" ") : "");
      });
      hosts.forEach((el) => {
        if (!bits.length) {
          el.classList.add("hidden");
          return;
        }
        el.textContent = "Quota: " + bits.slice(0, 6).join(" · ");
        el.classList.remove("hidden");
      });
    } catch (e) {}
  }

  function hydrateTimes() {
    $$("time[datetime]").forEach((t) => {
      const r = relTime(t.getAttribute("datetime"));
      if (r && r.label) {
        t.textContent = r.label;
        t.setAttribute("title", r.title);
      }
    });
  }

  function bindKeys() {
    document.addEventListener("keydown", (e) => {
      const tag = (document.activeElement && document.activeElement.tagName) || "";
      const typing = tag === "TEXTAREA" || tag === "INPUT" || tag === "SELECT";
      if (e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey && !typing) {
        e.preventDefault();
        const target = $("#ioc") || $("#hist-q") || document.querySelector("input[type=search], input[name=q]");
        if (target) target.focus();
      }
      if (!typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const map = { 1: "all", 2: "ip", 3: "domain", 4: "url", 5: "hash", 6: "email" };
        if (map[e.key]) {
          const btn = document.querySelector('#type-bar [data-type="' + map[e.key] + '"]');
          if (btn) {
            e.preventDefault();
            btn.click();
          }
        }
      }
      if (e.key === "Escape") {
        const m = document.getElementById("summary-modal");
        if (m) {
          e.preventDefault();
          m.remove();
          return;
        }
      }
      if ((e.key === "[" || e.key === "b") && !e.metaKey && !e.ctrlKey && !e.altKey && !typing) {
        const t = $("#rail-toggle");
        if (t) {
          e.preventDefault();
          t.click();
        }
      }
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && tag === "TEXTAREA") {
        e.preventDefault();
        if ($("#investigate-form") && $("#ioc")) submitLookup();
        else if ($("#bulk-form")) $("#bulk-form").requestSubmit();
      }
    });
  }

  function initBulk() {
    const form = $("#bulk-form");
    if (!form) return;
    const list = $("#bulk-list");
    const run = $("#bulk-run");
    async function extract(useAi) {
      const text = $("#bulk-text").value;
      if (!text.trim()) return;
      list.textContent = "Extracting…";
      try {
        const data = await api("/api/detect", { method: "POST", json: { text: text, use_ai: !!useAi } });
        list.innerHTML = "";
        (data.indicators || []).forEach((ind) => {
          const row = el("label", { class: "bulk-row" });
          const cb = el("input", { type: "checkbox", checked: true, "data-value": ind.value });
          row.appendChild(cb);
          row.appendChild(el("span", { class: "t", text: ind.type }));
          row.appendChild(el("span", { class: "v", text: defang(ind.value) }));
          if (ind.origin === "ai") row.appendChild(el("span", { class: "tag ai-tag", text: "AI · re-validated" }));
          list.appendChild(row);
        });
        if (!(data.indicators || []).length) list.appendChild(el("p", { text: "Nothing extracted." }));
        run.classList.toggle("hidden", !(data.indicators || []).length);
        if (useAi && data.ai) toast(data.ai.label);
      } catch (e) {
        list.textContent = e.message;
      }
    }
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      extract(false);
    });
    $("#bulk-ai") && $("#bulk-ai").addEventListener("click", () => extract(true));
    run &&
      run.addEventListener("click", async () => {
        const selected = $$("#bulk-list input[type=checkbox]:checked").map((c) => c.getAttribute("data-value"));
        if (!selected.length) return;
        const data = await api("/api/lookups", { method: "POST", json: { text: selected.join("\n"), trigger: "bulk", selected: selected } });
        if (!data.lookups || !data.lookups.length) {
          toast("No indicators found");
          return;
        }
        state.bulkLookups = data.lookups;
        const live = $("#bulk-live");
        const host = $("#bulk-sections");
        if (live) live.classList.remove("hidden");
        if (host) host.innerHTML = "";
        data.lookups.forEach((lu) => {
          const sec = el("section", { class: "bulk-section", "data-lookup": lu.lookup_id });
          sec.appendChild(el("p", { class: "ioc-line", text: lu.type + "  " + defang(lu.value) }));
          const grid = el("div", { class: "grid" });
          sec.appendChild(grid);
          if (host) host.appendChild(sec);
          attachStream(lu.lookup_id, grid);
        });
        paintBulkRollup();
        refreshQuota();
      });
  }

  function initMaintain() {
    const out = $("#m-out");
    if (!out) return;
    async function run(url, body) {
      out.textContent = "Working…";
      try {
        const d = await api(url, { method: "POST", json: body || {} });
        out.textContent = JSON.stringify(d, null, 2);
      } catch (e) {
        out.textContent = e.message;
      }
    }
    $("#m-integrity") && $("#m-integrity").addEventListener("click", () => run("/api/maintain/integrity"));
    $("#m-reindex") && $("#m-reindex").addEventListener("click", () => run("/api/maintain/reindex"));
    $("#m-snap") && $("#m-snap").addEventListener("click", () => run("/api/maintain/snapshot"));
    $("#m-prune-dry") &&
      $("#m-prune-dry").addEventListener("click", () =>
        run("/api/maintain/prune", { days: Number($("#prune-days").value) || 30, dry_run: true, strip_raw: true })
      );
    $("#m-prune-raw") &&
      $("#m-prune-raw").addEventListener("click", () =>
        run("/api/maintain/prune", { days: Number($("#prune-days").value) || 30, dry_run: false, strip_raw: true })
      );
    $("#m-prune-del") &&
      $("#m-prune-del").addEventListener("click", () =>
        run("/api/maintain/prune", { days: Number($("#prune-days").value) || 30, dry_run: false, delete_lookups: true })
      );
  }

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initRail();
    initAi();
    $$("[data-ai-label]").forEach((n) => {
      if (n.tagName === "SMALL" || n.classList.contains("ai-pill")) {
        if (!n.textContent.trim() || n.hasAttribute("data-ai-label")) n.textContent = n.textContent.trim() || aiLabel();
      }
    });
    const form = $("#investigate-form");
    if (form) {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        submitLookup();
      });
      $("#ioc") && $("#ioc").addEventListener("input", liveDetect);
      $$(".js-example").forEach((b) =>
        b.addEventListener("click", () => {
          const input = $("#ioc");
          if (input) input.value = b.getAttribute("data-value") || "";
          liveDetect();
          submitLookup();
        })
      );
      $("#copy-iocs") && $("#copy-iocs").addEventListener("click", copyIocs);
      $("#open-graph") && $("#open-graph").addEventListener("click", openGraph);
      $("#refresh-all") && $("#refresh-all").addEventListener("click", () => submitLookup({ force_full: true, trigger: "refresh" }));
      $("#av-verdict") &&
        $("#av-verdict").addEventListener("change", () => {
          const v = $("#av-verdict").value;
          if (v) saveVerdict(v);
        });
      $("#av-note") &&
        $("#av-note").addEventListener("change", () => {
          const v = $("#av-verdict").value;
          if (v) saveVerdict(v);
        });
      $("#ai-assess") &&
        $("#ai-assess").addEventListener("click", async () => {
          const out = $("#ai-out");
          if (!state.current) return toast("Run an investigation first");
          out.classList.remove("hidden");
          out.textContent = "Asking " + aiLabel() + "…";
          try {
            const d = await api("/api/ai/assess", { method: "POST", json: { lookup_id: state.current, pasted: state.pasted } });
            out.textContent = (d.ai && d.ai.label ? d.ai.label + "\n\n" : "") + d.text;
          } catch (e) {
            out.textContent = e.message;
          }
        });
      $("#ai-ticket") &&
        $("#ai-ticket").addEventListener("click", async () => {
          const out = $("#ai-out");
          if (!state.current) return toast("Run an investigation first");
          out.classList.remove("hidden");
          out.textContent = "Asking " + aiLabel() + "…";
          try {
            const d = await api("/api/ai/ticket", { method: "POST", json: { lookup_id: state.current } });
            out.textContent = (d.ai && d.ai.label ? d.ai.label + "\n\n" : "") + d.text;
          } catch (e) {
            out.textContent = e.message;
          }
        });
      autosizeIoc();
    }
    bindKeys();
    hydrateTimes();
    $("#bulk-copy") && $("#bulk-copy").addEventListener("click", copyBulk);
    $$(".js-save-key").forEach((b) => b.addEventListener("click", () => saveKey(b.getAttribute("data-id"))));
    const prefill = new URLSearchParams(location.search).get("prefill");
    if (prefill && $("#ioc")) {
      $("#ioc").value = prefill;
      liveDetect();
    }
    const seedEl = $("#ioc");
    if (seedEl && seedEl.dataset.seed && !seedEl.value) seedEl.value = seedEl.dataset.seed;
    const resume = document.body.getAttribute("data-resume");
    if (resume) {
      state.current = resume;
      state.indicatorId = document.body.getAttribute("data-indicator-id");
      $("#live") && $("#live").classList.remove("hidden");
      $("#empty-state") && $("#empty-state").classList.add("hidden");
      fetch("/api/lookups/" + resume)
        .then((r) => r.json())
        .then((b) => {
          const ind = b.indicator || {};
          const lu = { lookup_id: resume, type: ind.type || "ip", value: ind.value || "", origin: "regex" };
          state.lookups = [lu];
          renderExtracted([lu]);
          renderCaseBoard([lu]);
          if (b.analyst) renderAnalyst(b.analyst, b.analyst_history);
        })
        .catch(() => attachStream(resume, $("#cards")));
    }
    initGraph();
    initBulk();
    initMaintain();
    initHistory();
    refreshQuota();
  });
})();
