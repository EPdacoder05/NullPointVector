// NullPoint console — vanilla JS only (no framework, no CDN).
(function () {
  "use strict";

  var channel = document.body.getAttribute("data-channel") || "phishing";
  var feedFilter = "all";

  // Theme: Deck (default) / Terminal / Blackout — persisted per browser.
  function applyTheme(name) {
    if (name) document.body.setAttribute("data-theme", name);
    else document.body.removeAttribute("data-theme");
    document.querySelectorAll(".theme-opt").forEach(function (b) {
      b.classList.toggle("active", (b.getAttribute("data-theme-opt") || "") === (name || ""));
    });
  }
  function initTheme() {
    var saved = "";
    try { saved = localStorage.getItem("np_theme") || ""; } catch (e) { /* private mode */ }
    applyTheme(saved);
    var bar = document.getElementById("theme-switch");
    if (!bar) return;
    bar.addEventListener("click", function (e) {
      var btn = e.target.closest(".theme-opt");
      if (!btn) return;
      var name = btn.getAttribute("data-theme-opt") || "";
      applyTheme(name);
      try { localStorage.setItem("np_theme", name); } catch (e2) { /* ignore */ }
    });
  }
  initTheme();

  function toast(msg, tone) {
    var root = document.getElementById("toast-root");
    if (!root) return;
    var el = document.createElement("div");
    el.className = "toast toast-" + (tone || "warn");
    el.textContent = msg;
    root.appendChild(el);
    setTimeout(function () { el.remove(); }, 4200);
  }

  function bindCmdEnter(form, handler) {
    if (!form) return;
    form.addEventListener("keydown", function (e) {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        if (handler) handler(e);
        else form.requestSubmit();
      }
    });
  }

  function submitAnalyze(e) {
    e.preventDefault();
    var form = document.getElementById("analyze-form");
    var result = document.getElementById("result");
    var btn = form.querySelector("button[type=submit]");
    var data = new FormData(form);
    if (!String(data.get("content") || "").trim()) return;
    btn.disabled = true;
    result.innerHTML = '<div class="verdict empty"><span class="spin"></span>&nbsp; Analyzing…</div>';
    fetch("/app/analyze", { method: "POST", body: data, headers: { Accept: "text/html" } })
      .then(function (r) { return r.text(); })
      .then(function (html) {
        result.innerHTML = html;
        var threat = result.querySelector(".tone-danger");
        toast(threat ? "Threat detected" : "Analysis complete", threat ? "danger" : "safe");
      })
      .catch(function () {
        result.innerHTML = '<div class="verdict empty">Analysis unavailable. Try again.</div>';
        toast("Analysis failed", "danger");
      })
      .finally(function () { btn.disabled = false; refreshFeed(); });
  }

  function submitScreen(e) {
    e.preventDefault();
    var form = document.getElementById("screen-form");
    var slot = document.getElementById("screen-result");
    var btn = form.querySelector("button[type=submit]");
    var data = new FormData(form);
    if (!String(data.get("caller_id") || "").trim()) return;
    btn.disabled = true;
    slot.innerHTML = '<div class="verdict empty"><span class="spin"></span>&nbsp; Screening…</div>';
    fetch("/app/screen", { method: "POST", body: data, headers: { Accept: "text/html" } })
      .then(function (r) { return r.text(); })
      .then(function (html) {
        slot.innerHTML = html;
        var block = slot.querySelector(".tone-danger");
        var warn = slot.querySelector(".tone-warn");
        if (block) toast("Call action: BLOCK", "danger");
        else if (warn) toast("Call action: review", "warn");
        else toast("Call cleared", "safe");
      })
      .catch(function () {
        slot.innerHTML = '<div class="verdict empty">Screening unavailable.</div>';
      })
      .finally(function () { btn.disabled = false; });
  }

  function applyFeedFilter() {
    var feed = document.getElementById("feed");
    if (!feed) return;
    feed.querySelectorAll(".feed-item").forEach(function (item) {
      var isThreat = item.getAttribute("data-threat") === "1";
      var show = feedFilter === "all" ||
        (feedFilter === "threat" && isThreat) ||
        (feedFilter === "clear" && !isThreat);
      item.classList.toggle("hidden", !show);
    });
  }

  function refreshFeed() {
    var feed = document.getElementById("feed");
    if (!feed) return;
    fetch("/app/feed?channel=" + encodeURIComponent(channel), { headers: { Accept: "text/html" } })
      .then(function (r) { return r.text(); })
      .then(function (html) { feed.innerHTML = html; applyFeedFilter(); })
      .catch(function () { /* keep last good feed */ });
  }

  function initSmsPreview() {
    var sender = document.getElementById("sender");
    var content = document.getElementById("content");
    var fromDisp = document.getElementById("sms-from-display");
    var bubble = document.getElementById("sms-bubble");
    if (!content || !bubble) return;
    function sync() {
      if (fromDisp) fromDisp.textContent = (sender && sender.value.trim()) || "Unknown sender";
      var txt = content.value.trim();
      bubble.textContent = txt || "Paste SMS body to preview the thread.";
    }
    content.addEventListener("input", sync);
    if (sender) sender.addEventListener("input", sync);
  }

  function initBillingToggle() {
    var toggle = document.getElementById("billing-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", function (e) {
      var btn = e.target.closest(".bill-opt");
      if (!btn) return;
      var period = btn.getAttribute("data-period");
      toggle.querySelectorAll(".bill-opt").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      document.querySelectorAll(".price-val").forEach(function (el) {
        el.textContent = el.getAttribute(period === "annual" ? "data-annual" : "data-monthly");
      });
      document.querySelectorAll(".price-period").forEach(function (el) {
        el.textContent = period === "annual" ? "year" : "month";
      });
    });
  }

  function initFeedFilters() {
    var bar = document.getElementById("feed-filters");
    if (!bar) return;
    bar.addEventListener("click", function (e) {
      var btn = e.target.closest(".feed-filter");
      if (!btn) return;
      feedFilter = btn.getAttribute("data-filter") || "all";
      bar.querySelectorAll(".feed-filter").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      applyFeedFilter();
    });
  }

  function initVishMode() {
    var bar = document.getElementById("vish-mode");
    if (!bar) return;
    var paste = document.getElementById("panel-paste");
    var screen = document.getElementById("panel-screen");
    bar.addEventListener("click", function (e) {
      var btn = e.target.closest(".mode-opt");
      if (!btn) return;
      var mode = btn.getAttribute("data-mode");
      bar.querySelectorAll(".mode-opt").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      if (paste) paste.hidden = mode !== "paste";
      if (screen) screen.hidden = mode !== "screen";
    });
  }

  function initInbox() {
    var tabs = document.getElementById("inbox-tabs");
    var list = document.getElementById("inbox-list");
    var search = document.getElementById("inbox-search");
    if (!list) return;
    var tab = "all";
    function apply() {
      var q = (search && search.value || "").toLowerCase().trim();
      list.querySelectorAll(".inbox-row").forEach(function (row) {
        var threat = row.getAttribute("data-threat") === "1";
        var matchTab = tab === "all" || (tab === "threat" && threat) || (tab === "clear" && !threat);
        var matchQ = !q || (row.getAttribute("data-q") || "").indexOf(q) !== -1;
        row.classList.toggle("hidden", !(matchTab && matchQ));
      });
    }
    if (tabs) {
      tabs.addEventListener("click", function (e) {
        var btn = e.target.closest(".inbox-tab");
        if (!btn) return;
        tab = btn.getAttribute("data-tab") || "all";
        tabs.querySelectorAll(".inbox-tab").forEach(function (b) {
          b.classList.toggle("active", b === btn);
        });
        apply();
      });
    }
    if (search) search.addEventListener("input", apply);
    var stream = document.getElementById("stream-mode");
    var label = document.getElementById("stream-label");
    if (stream) {
      stream.addEventListener("click", function (e) {
        var btn = e.target.closest(".mode-opt");
        if (!btn) return;
        stream.querySelectorAll(".mode-opt").forEach(function (b) {
          b.classList.toggle("active", b === btn);
        });
        if (label) label.textContent = btn.getAttribute("data-stream") || "live";
      });
    }
  }

  function initIdentity() {
    var form = document.getElementById("identity-form");
    var slot = document.getElementById("identity-result");
    if (!form || !slot) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var subject = (document.getElementById("subject") || {}).value || "";
      var consented = !!(document.getElementById("consented") || {}).checked;
      if (!subject.trim() || !consented) {
        toast("Consent and subject required", "warn");
        return;
      }
      slot.innerHTML = '<div class="verdict empty"><span class="spin"></span>&nbsp; Enriching…</div>';
      fetch("/app/identity/enrich", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ subject: subject.trim(), consented: true }),
      })
        .then(function (r) {
          return r.json().then(function (j) { return { ok: r.ok, status: r.status, j: j }; });
        })
        .then(function (res) {
          if (!res.ok) {
            slot.innerHTML = '<div class="verdict empty">Enrichment blocked (' + res.status + '): '
              + (res.j.detail || res.j.error || "consent") + "</div>";
            toast("Enrichment needs consent", "warn");
            return;
          }
          var html = "";
          (res.j.reports || []).forEach(function (rep) {
            var riskPct = Math.round((rep.risk || 0) * 100);
            html += '<div class="identity-report"><h4>' + (rep.layer || "") + " · " + (rep.vendor || "")
              + (rep.ok ? " · risk " + riskPct + "%" : "")
              + "</h4><div>" + (rep.ok ? "ok" : "fail") + (rep.error ? " — " + rep.error : "")
              + "</div><ul>" + (rep.findings || []).map(function (f) {
                return "<li>" + f + "</li>";
              }).join("") + "</ul></div>";
          });
          slot.innerHTML = html || '<div class="verdict empty">No vendor reports.</div>';
          toast("Enrichment complete", "safe");
        })
        .catch(function () {
          slot.innerHTML = '<div class="verdict empty">Enrichment unavailable.</div>';
        });
    });
  }

  function initConnectors() {
    document.querySelectorAll(".conn-env").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var provider = btn.getAttribute("data-provider");
        fetch("/app/connectors/env/" + encodeURIComponent(provider), { method: "POST" })
          .then(function (r) { return r.json(); })
          .then(function (j) {
            if (j.ok) {
              toast("Linked " + (j.account || provider), "safe");
              setTimeout(function () { location.reload(); }, 600);
            } else {
              toast(j.error || "Link failed", "danger");
            }
          })
          .catch(function () { toast("Link failed", "danger"); });
      });
    });
  }

  function initGrading() {
    document.addEventListener("click", function (e) {
      var btn = e.target.closest(".js-grade");
      if (btn) {
        var row = btn.closest(".inbox-row");
        if (!row) return;
        var kind = btn.getAttribute("data-kind") || "message";
        var verdict = btn.getAttribute("data-verdict") || "unsure";
        var body = new URLSearchParams();
        var url;
        if (kind === "call") {
          url = "/app/calls/grade";
          body.set("eid", row.getAttribute("data-eid") || "");
        } else {
          url = "/app/quarantine/grade";
          body.set("mid", row.getAttribute("data-mid") || "");
        }
        body.set("verdict", verdict);
        row.querySelectorAll(".js-grade").forEach(function (b) { b.disabled = true; });
        fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
          body: body.toString(),
        })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
          .then(function (res) {
            if (!res.ok || !res.j.ok) {
              toast(res.j.error || "Grade failed", "danger");
              row.querySelectorAll(".js-grade").forEach(function (b) { b.disabled = false; });
              return;
            }
            var msg = verdict === "block" ? "Blocked & reported — feeds retrain"
              : verdict === "safe" ? "Marked safe — feeds retrain"
              : "Held in quarantine";
            toast(msg, verdict === "block" ? "danger" : verdict === "safe" ? "safe" : "warn");
            row.classList.add("row-graded");
            // On the quarantine page a graded row leaves the queue.
            if (document.getElementById("quarantine-list") && verdict !== "unsure") {
              setTimeout(function () { row.remove(); }, 450);
              var total = document.getElementById("q-total");
              if (total) total.textContent = Math.max(0, (parseInt(total.textContent, 10) || 1) - 1);
            }
          })
          .catch(function () {
            toast("Grade failed", "danger");
            row.querySelectorAll(".js-grade").forEach(function (b) { b.disabled = false; });
          });
        return;
      }
      var tbtn = e.target.closest(".js-transcript");
      if (tbtn) {
        var block = tbtn.parentElement.querySelector(".call-transcript");
        if (!block) return;
        var hidden = block.classList.toggle("hidden");
        tbtn.textContent = hidden ? "Show transcription" : "Hide transcription";
      }
    });
  }

  var analyzeForm = document.getElementById("analyze-form");
  var screenForm = document.getElementById("screen-form");
  if (analyzeForm) {
    analyzeForm.addEventListener("submit", submitAnalyze);
    bindCmdEnter(analyzeForm);
  }
  if (screenForm) {
    screenForm.addEventListener("submit", submitScreen);
    bindCmdEnter(screenForm);
  }
  initSmsPreview();
  initBillingToggle();
  initFeedFilters();
  initVishMode();
  initInbox();
  initIdentity();
  initConnectors();
  initGrading();
  if (document.getElementById("feed")) {
    refreshFeed();
    setInterval(refreshFeed, 8000);
  }
  var clock = document.getElementById("dash-clock");
  if (clock) {
    function tick() { clock.textContent = new Date().toISOString().slice(11, 19) + "Z"; }
    tick();
    setInterval(tick, 1000);
  }
})();
