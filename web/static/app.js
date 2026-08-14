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

  function initTimezone() {
    var KEY = "np_tz";
    var HOUR_KEY = "np_hour12";
    function readCookie(name) {
      var m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
      return m ? decodeURIComponent(m[1]) : "";
    }
    function writeCookie(name, value) {
      document.cookie = name + "=" + encodeURIComponent(value)
        + "; path=/; max-age=31536000; SameSite=Lax";
    }
    var sel = document.getElementById("tz-select");
    var hourSel = document.getElementById("hour-select");
    var saved = "";
    try { saved = localStorage.getItem(KEY) || ""; } catch (e) { /* ignore */ }
    if (!saved) saved = readCookie(KEY) || "";
    if (!saved) {
      try { saved = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; } catch (e2) { saved = "UTC"; }
    }
    if (sel) {
      if (saved && !Array.prototype.some.call(sel.options, function (o) { return o.value === saved; })) {
        var opt = document.createElement("option");
        opt.value = saved;
        opt.textContent = saved;
        sel.appendChild(opt);
      }
      if (saved) sel.value = saved;
      // Keep cookie in sync with localStorage — server renders timestamps from cookie.
      // Without this, picker shows America/New_York while rows stay UTC.
      var cookieTz = readCookie(KEY) || "";
      if (saved && saved !== cookieTz) {
        writeCookie(KEY, saved);
        location.reload();
        return;
      }
      sel.addEventListener("change", function () {
        var z = sel.value || "UTC";
        try { localStorage.setItem(KEY, z); } catch (e3) { /* ignore */ }
        writeCookie(KEY, z);
        location.reload();
      });
    }
    var hourSaved = "";
    try { hourSaved = localStorage.getItem(HOUR_KEY) || ""; } catch (eH) { /* ignore */ }
    if (!hourSaved) hourSaved = readCookie(HOUR_KEY) || "0";
    if (hourSel) {
      hourSel.value = hourSaved === "1" ? "1" : "0";
      hourSel.addEventListener("change", function () {
        var v = hourSel.value === "1" ? "1" : "0";
        try { localStorage.setItem(HOUR_KEY, v); } catch (e4) { /* ignore */ }
        writeCookie(HOUR_KEY, v);
        location.reload();
      });
    }
    if (saved && readCookie(KEY) !== saved) writeCookie(KEY, saved);
    if (hourSaved && readCookie(HOUR_KEY) !== hourSaved) writeCookie(HOUR_KEY, hourSaved);
    try { if (saved) localStorage.setItem(KEY, saved); } catch (e5) { /* ignore */ }
    return saved || "UTC";
  }

  var npTz = initTimezone();

  function toast(msg, tone) {
    var root = document.getElementById("toast-root");
    if (!root) return;
    var el = document.createElement("div");
    el.className = "toast toast-" + (tone || "warn");
    el.textContent = msg;
    root.appendChild(el);
    setTimeout(function () { el.remove(); }, 4200);
  }

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? (meta.getAttribute("content") || "") : "";
  }

  function appFetch(url, options) {
    var opts = options ? Object.assign({}, options) : {};
    var method = String(opts.method || "GET").toUpperCase();
    if (["GET", "HEAD", "OPTIONS"].indexOf(method) === -1) {
      var headers = new Headers(opts.headers || {});
      var token = csrfToken();
      if (token) headers.set("X-CSRF-Token", token);
      opts.headers = headers;
    }
    return window.fetch(url, opts);
  }

  function bindCmdEnter(form, handler) {
    if (!form) return;
    // Only Cmd/Ctrl+Enter submits. Never touch A/C/V/X (select-all / copy / paste).
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
    appFetch("/app/analyze", { method: "POST", body: data, headers: { Accept: "text/html" } })
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
    appFetch("/app/screen", { method: "POST", body: data, headers: { Accept: "text/html" } })
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
    appFetch("/app/feed?channel=" + encodeURIComponent(channel), { headers: { Accept: "text/html" } })
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
        if (el.classList.contains("price-sales-only")) return;
        var next = el.getAttribute(period === "annual" ? "data-annual" : "data-monthly");
        if (next != null) el.textContent = next;
      });
      document.querySelectorAll(".price-period").forEach(function (el) {
        el.textContent = period === "annual" ? "year" : "month";
      });
      document.querySelectorAll(".js-checkout-link").forEach(function (a) {
        var plan = a.getAttribute("data-plan") || "essential";
        var trial = a.getAttribute("data-trial") === "1";
        var href = "/app/checkout?plan=" + encodeURIComponent(plan) + "&interval=" + period;
        if (trial) href += "&trial=1";
        a.setAttribute("href", href);
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
      appFetch("/app/identity/enrich", {
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
    var PROVIDER_HELP = {
      yahoo: {
        title: "Yahoo — IMAP app password",
        email: "you@yahoo.com",
        steps: [
          "Yahoo Account Security → generate an App Password (not your normal login password).",
          "Name it NullPoint. Copy the 16-character password once.",
          "Paste mailbox + app password below. Stored encrypted under your JWT subject.",
        ],
      },
      gmail: {
        title: "Gmail — IMAP app password",
        email: "you@gmail.com",
        steps: [
          "Google Account → Security → 2-Step Verification must be ON.",
          "Security → App passwords → Mail → Other (NullPoint) → Generate.",
          "Paste Gmail address + the 16-character app password below (not your Google password).",
        ],
      },
      microsoft: {
        title: "Microsoft / Outlook — IMAP app password",
        email: "you@outlook.com",
        steps: [
          "account.microsoft.com → Security → Advanced security options.",
          "Create a new app password (or use Outlook.com app password if MFA is on).",
          "Paste Outlook/Hotmail/Live address + app password below. IMAP host: outlook.office365.com.",
        ],
      },
    };
    function applyProviderHelp() {
      var sel = document.getElementById("ap-provider");
      var title = document.getElementById("ap-title");
      var steps = document.getElementById("ap-steps");
      var email = document.getElementById("ap-email");
      if (!sel || !steps) return;
      var help = PROVIDER_HELP[sel.value] || PROVIDER_HELP.yahoo;
      if (title) title.textContent = help.title;
      if (email) email.placeholder = help.email;
      steps.innerHTML = help.steps.map(function (s) { return "<li>" + s + "</li>"; }).join("");
    }
    var provSel = document.getElementById("ap-provider");
    if (provSel) {
      provSel.addEventListener("change", applyProviderHelp);
      applyProviderHelp();
    }

    document.querySelectorAll(".conn-env").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var provider = btn.getAttribute("data-provider");
        appFetch("/app/connectors/env/" + encodeURIComponent(provider), { method: "POST" })
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
    var apForm = document.getElementById("app-password-form");
    if (apForm) {
      apForm.addEventListener("submit", function (e) {
        e.preventDefault();
        var fd = new FormData(apForm);
        appFetch("/app/connectors/app-password", { method: "POST", body: fd, headers: { Accept: "application/json" } })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
          .then(function (res) {
            if (res.ok && res.j.ok) {
              toast("Saved " + (res.j.account || "mailbox") + " (encrypted)", "safe");
              setTimeout(function () { location.reload(); }, 700);
            } else {
              toast((res.j && res.j.error) || "Save failed", "danger");
            }
          })
          .catch(function () { toast("Save failed", "danger"); });
      });
    }
    var reqForm = document.getElementById("provider-request-form");
    if (reqForm) {
      reqForm.addEventListener("submit", function (e) {
        e.preventDefault();
        var fd = new FormData(reqForm);
        appFetch("/app/connectors/request-provider", { method: "POST", body: fd, headers: { Accept: "application/json" } })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
          .then(function (res) {
            if (res.ok && res.j.ok) {
              toast("Provider request logged", "safe");
              reqForm.reset();
            } else {
              toast((res.j && res.j.error) || "Request failed", "danger");
            }
          })
          .catch(function () { toast("Request failed", "danger"); });
      });
    }
    document.querySelectorAll(".js-oauth-consent").forEach(function (a) {
      a.addEventListener("click", function (e) {
        var id = a.getAttribute("data-consent");
        var box = id ? document.getElementById(id) : null;
        if (box && !box.checked) {
          e.preventDefault();
          toast("Confirm mailbox read consent first", "warn");
        }
      });
    });
  }

  function postGrade(row, verdict, alsoIds) {
    var kind = "message";
    var body = new URLSearchParams();
    var url = "/app/quarantine/grade";
    body.set("mid", row.getAttribute("data-mid") || "");
    body.set("verdict", verdict);
    if (alsoIds && alsoIds.length) {
      body.set("also_ids", alsoIds.join(","));
    } else {
      body.set("also_ids", "");
      body.set("cascade", "none");
    }
    row.querySelectorAll(".js-grade").forEach(function (b) { b.disabled = true; });
    var ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 45000) : null;
    return appFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: body.toString(),
      signal: ctrl ? ctrl.signal : undefined,
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
        var nudge = res.j.nudge;
        if (nudge && nudge.ok && nudge.plain) {
          msg = nudge.plain;
        } else if (nudge && nudge.deltas && nudge.deltas.length) {
          msg += " · Δ " + nudge.deltas.slice(0, 3).map(function (d) {
            return d.feature + " " + (d.delta > 0 ? "+" : "") + d.delta;
          }).join(", ");
        }
        var cascaded = res.j.cascaded || 0;
        if (cascaded > 0) {
          msg += " · also cleared " + cascaded + " from same sender";
        }
        if (res.j.provider_note) {
          msg += " · " + res.j.provider_note;
        }
        toast(msg, verdict === "block" ? "danger" : verdict === "safe" ? "safe" : "warn");
        if (verdict === "block" || verdict === "safe") {
          var ids = res.j.cascaded_ids || [row.getAttribute("data-mid")];
          var idSet = {};
          ids.forEach(function (id) { idSet[String(id)] = true; });
          document.querySelectorAll(".inbox-row[data-mid]").forEach(function (r) {
            var mid = r.getAttribute("data-mid");
            if (idSet[mid]) {
              r.classList.add("row-bubble-out");
              setTimeout(function () { r.remove(); }, 320);
            }
          });
          var total = document.getElementById("q-total");
          if (total) {
            var n = (ids && ids.length) ? ids.length : 1;
            total.textContent = Math.max(0, (parseInt(total.textContent, 10) || n) - n);
          }
          if (location.pathname.indexOf("/app/message/") === 0) {
            setTimeout(function () { location.href = "/app/quarantine"; }, 400);
          }
        } else {
          row.classList.add("row-graded");
          row.querySelectorAll(".js-grade").forEach(function (b) { b.disabled = false; });
        }
      })
      .catch(function (err) {
        var aborted = err && err.name === "AbortError";
        toast(aborted ? "Grade timed out — refresh and retry" : "Grade failed", "danger");
        row.querySelectorAll(".js-grade").forEach(function (b) { b.disabled = false; });
      })
      .finally(function () {
        if (timer) clearTimeout(timer);
      });
  }

  function openCascadeModal(row, verdict) {
    var modal = document.getElementById("cascade-modal");
    var list = document.getElementById("cascade-list");
    var senderEl = document.getElementById("cascade-sender");
    if (!modal || !list) {
      return postGrade(row, verdict, []);
    }
    var mid = row.getAttribute("data-mid");
    appFetch("/app/quarantine/siblings?mid=" + encodeURIComponent(mid), { headers: { Accept: "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        var sibs = (j && j.siblings) || [];
        if (!sibs.length) {
          return postGrade(row, verdict, []);
        }
        senderEl.textContent = (verdict === "block" ? "Block" : "Mark safe")
          + " — " + (j.sender || row.getAttribute("data-sender") || "same sender");
        list.innerHTML = sibs.map(function (s) {
          return '<label class="cascade-item"><input type="checkbox" checked data-id="'
            + s.id + '"> <span>#' + s.id + " · " + (s.ts_local || "")
            + " · " + (s.subject || "(no subject)").replace(/</g, "&lt;")
            + "</span></label>";
        }).join("");
        modal.classList.remove("hidden");
        modal._pending = { row: row, verdict: verdict };
      })
      .catch(function () { postGrade(row, verdict, []); });
  }

  function initCascadeModal() {
    var modal = document.getElementById("cascade-modal");
    if (!modal) return;
    function close() {
      modal.classList.add("hidden");
      modal._pending = null;
    }
    var cancel = document.getElementById("cascade-cancel");
    if (cancel) cancel.addEventListener("click", close);
    var allBtn = document.getElementById("cascade-all");
    if (allBtn) allBtn.addEventListener("click", function () {
      modal.querySelectorAll("#cascade-list input[type=checkbox]").forEach(function (c) { c.checked = true; });
    });
    var noneBtn = document.getElementById("cascade-none");
    if (noneBtn) noneBtn.addEventListener("click", function () {
      modal.querySelectorAll("#cascade-list input[type=checkbox]").forEach(function (c) { c.checked = false; });
    });
    var oneBtn = document.getElementById("cascade-one");
    if (oneBtn) oneBtn.addEventListener("click", function () {
      var p = modal._pending;
      if (!p) return;
      close();
      postGrade(p.row, p.verdict, []);
    });
    var applyBtn = document.getElementById("cascade-apply");
    if (applyBtn) applyBtn.addEventListener("click", function () {
      var p = modal._pending;
      if (!p) return;
      var ids = [];
      modal.querySelectorAll("#cascade-list input[type=checkbox]:checked").forEach(function (c) {
        ids.push(c.getAttribute("data-id"));
      });
      applyBtn.disabled = true;
      var one = document.getElementById("cascade-one");
      if (one) one.disabled = true;
      close();
      Promise.resolve(postGrade(p.row, p.verdict, ids)).finally(function () {
        applyBtn.disabled = false;
        if (one) one.disabled = false;
      });
    });
  }

  function initUserReport() {
    var overlay = document.getElementById("npr-overlay");
    if (!overlay) return;
    var currentStep = 1;
    var selectedYN = null;
    var selectedReasons = {};
    var ctx = { mid: "", sender: "", channel: "email" };

    function channelPhrase(ch) {
      if (ch === "sms" || ch === "smishing") return "text";
      if (ch === "call" || ch === "vishing") return "call";
      return "email";
    }

    function showStep(n) {
      currentStep = n;
      overlay.querySelectorAll(".npr-panel").forEach(function (p) {
        p.classList.remove("npr-active");
      });
      var foot = document.getElementById("npr-footer");
      var title = document.getElementById("npr-title");
      var label = document.getElementById("npr-step-label");
      var next = document.getElementById("npr-next");
      var back = document.getElementById("npr-back");

      if (n === "success") {
        document.getElementById("npr-step-success").classList.add("npr-active");
        if (title) title.textContent = "Thanks for reporting";
        if (label) label.textContent = "Done";
        if (foot) foot.style.display = "none";
        ["npr-dot-1", "npr-dot-2", "npr-dot-3"].forEach(function (id) {
          var d = document.getElementById(id);
          if (d) d.className = "npr-dot npr-complete";
        });
        return;
      }

      var panel = document.getElementById("npr-step-" + n);
      if (panel) panel.classList.add("npr-active");
      if (foot) foot.style.display = "flex";

      for (var i = 1; i <= 3; i++) {
        var dot = document.getElementById("npr-dot-" + i);
        if (!dot) continue;
        if (i < n) dot.className = "npr-dot npr-complete";
        else if (i === n) dot.className = "npr-dot npr-active";
        else dot.className = "npr-dot";
      }

      var titles = {
        1: "Did you expect this?",
        2: "What made you suspicious?",
        3: "Anything else? (optional)",
      };
      var labels = { 1: "Step 1 of 3", 2: "Step 2 of 3", 3: "Step 3 of 3" };
      if (title) title.textContent = titles[n] || "";
      if (label) label.textContent = labels[n] || "";
      if (back) back.style.visibility = n > 1 ? "visible" : "hidden";
      if (next) {
        next.textContent = n === 3 ? "Submit report" : "Continue";
        updateNextState();
      }
      if (n === 1) {
        var q = document.getElementById("npr-q1");
        if (q) q.textContent = "Were you expecting this " + channelPhrase(ctx.channel) + "?";
      }
    }

    function updateNextState() {
      var next = document.getElementById("npr-next");
      if (!next) return;
      if (currentStep === 1) next.disabled = selectedYN === null;
      else if (currentStep === 2) next.disabled = Object.keys(selectedReasons).length === 0;
      else next.disabled = false;
    }

    function resetModal() {
      selectedYN = null;
      selectedReasons = {};
      overlay.querySelectorAll(".npr-yn-btn").forEach(function (b) {
        b.classList.remove("npr-selected");
      });
      overlay.querySelectorAll(".npr-chip").forEach(function (c) {
        c.classList.remove("npr-selected");
      });
      var ta = document.getElementById("npr-detail");
      if (ta) ta.value = "";
      var cc = document.getElementById("npr-char-count");
      if (cc) cc.textContent = "0";
      showStep(1);
    }

    function openReport(btn) {
      ctx.mid = btn.getAttribute("data-mid") || "";
      ctx.sender = btn.getAttribute("data-sender") || "";
      ctx.channel = btn.getAttribute("data-channel") || "email";
      resetModal();
      overlay.classList.add("npr-open");
      document.body.style.overflow = "hidden";
    }

    function closeReport() {
      overlay.classList.remove("npr-open");
      document.body.style.overflow = "";
    }

    function submitReport() {
      var body = new URLSearchParams();
      body.set("mid", ctx.mid);
      body.set("sender", ctx.sender);
      body.set("channel", ctx.channel);
      body.set("expected", selectedYN === "yes" ? "yes" : "no");
      body.set("reasons", Object.keys(selectedReasons).join(","));
      var ta = document.getElementById("npr-detail");
      body.set("detail", ta ? ta.value.trim() : "");
      var next = document.getElementById("npr-next");
      if (next) next.disabled = true;
      appFetch("/app/report", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
        body: body.toString(),
      })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (!res.ok || !res.j.ok) {
            toast((res.j && res.j.error) || "Report failed", "danger");
            if (next) next.disabled = false;
            return;
          }
          showStep("success");
          var fleet = (res.j.fleet && res.j.fleet.status) || "";
          if (fleet === "auto_promoted") toast("Report in — sender promoted to fleet list", "safe");
          else if (fleet === "analyst_review") toast("Report in — flagged for analyst review", "warn");
          else toast("Report submitted", "safe");
          setTimeout(closeReport, 2800);
        })
        .catch(function () {
          toast("Report failed", "danger");
          if (next) next.disabled = false;
        });
    }

    document.addEventListener("click", function (e) {
      var btn = e.target.closest(".js-report");
      if (btn) {
        e.preventDefault();
        openReport(btn);
      }
    });

    var closeBtn = document.getElementById("npr-close");
    if (closeBtn) closeBtn.addEventListener("click", closeReport);
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay) closeReport();
    });

    overlay.querySelectorAll(".npr-yn-btn").forEach(function (b) {
      b.addEventListener("click", function () {
        selectedYN = b.getAttribute("data-yn");
        overlay.querySelectorAll(".npr-yn-btn").forEach(function (x) {
          x.classList.toggle("npr-selected", x === b);
        });
        updateNextState();
      });
    });

    overlay.querySelectorAll(".npr-chip").forEach(function (b) {
      b.addEventListener("click", function () {
        var id = b.getAttribute("data-reason");
        if (selectedReasons[id]) {
          delete selectedReasons[id];
          b.classList.remove("npr-selected");
        } else {
          selectedReasons[id] = true;
          b.classList.add("npr-selected");
        }
        updateNextState();
      });
    });

    var ta = document.getElementById("npr-detail");
    if (ta) {
      ta.addEventListener("input", function () {
        var cc = document.getElementById("npr-char-count");
        if (cc) cc.textContent = String(ta.value.length);
      });
    }

    var back = document.getElementById("npr-back");
    if (back) {
      back.addEventListener("click", function () {
        if (typeof currentStep === "number" && currentStep > 1) showStep(currentStep - 1);
      });
    }
    var next = document.getElementById("npr-next");
    if (next) {
      next.addEventListener("click", function () {
        if (currentStep === 3) submitReport();
        else if (typeof currentStep === "number") showStep(currentStep + 1);
      });
    }
  }

  function initGrading() {
    initCascadeModal();
    initUserReport();
    document.addEventListener("click", function (e) {
      var btn = e.target.closest(".js-grade");
      if (btn) {
        var row = btn.closest(".inbox-row");
        if (!row) return;
        var kind = btn.getAttribute("data-kind") || "message";
        var verdict = btn.getAttribute("data-verdict") || "unsure";
        if (kind === "call") {
          var body = new URLSearchParams();
          body.set("eid", row.getAttribute("data-eid") || "");
          body.set("verdict", verdict);
          row.querySelectorAll(".js-grade").forEach(function (b) { b.disabled = true; });
          appFetch("/app/calls/grade", {
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
              toast(verdict === "block" ? "Call blocked" : verdict === "safe" ? "Call marked safe" : "Held",
                verdict === "block" ? "danger" : "safe");
              if (verdict === "block" || verdict === "safe") {
                row.classList.add("row-bubble-out");
                setTimeout(function () { row.remove(); }, 320);
              }
            })
            .catch(function () {
              toast("Grade failed", "danger");
              row.querySelectorAll(".js-grade").forEach(function (b) { b.disabled = false; });
            });
          return;
        }
        if (verdict === "unsure") {
          postGrade(row, verdict, []);
          return;
        }
        openCascadeModal(row, verdict);
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

  function deviceFingerprint() {
    try {
      var raw = [
        navigator.userAgent || "",
        navigator.language || "",
        screen.width + "x" + screen.height,
        Intl.DateTimeFormat().resolvedOptions().timeZone || "",
      ].join("|");
      var h = 0;
      for (var i = 0; i < raw.length; i++) h = ((h << 5) - h + raw.charCodeAt(i)) | 0;
      return "npfp_" + (h >>> 0).toString(16);
    } catch (e) {
      return "npfp_unknown";
    }
  }

  function initCheckout() {
    var form = document.getElementById("checkout-form");
    if (!form) return;
    var fp = document.getElementById("fp-field");
    if (fp) fp.value = deviceFingerprint();
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
  initCheckout();
  if (document.getElementById("feed")) {
    refreshFeed();
    setInterval(refreshFeed, 8000);
  }
  var clock = document.getElementById("dash-clock");
  if (clock) {
    function tick() {
      try {
        clock.textContent = new Date().toLocaleTimeString(undefined, {
          timeZone: npTz || undefined,
          hour12: (function () {
            var hs = document.getElementById("hour-select");
            if (hs) return hs.value === "1";
            try { return (localStorage.getItem("np_hour12") || "") === "1"; } catch (e) { return false; }
          })(),
        });
      } catch (e) {
        clock.textContent = new Date().toISOString().slice(11, 19) + "Z";
      }
    }
    tick();
    setInterval(tick, 1000);
  }
})();
