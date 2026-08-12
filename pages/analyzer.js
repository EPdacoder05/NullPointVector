/* Public policy + lexicon layer (same ideas as production hot path).
   Champion SGD weights are not here. Prefer hold over miss. */
(function (global) {
  var URGENCY = ["urgent", "immediately", "expires", "suspend", "locked", "verify now",
    "act now", "final notice", "within 24", "last warning", "hacked", "unusual activity"];
  var FEAR = ["arrest", "lawsuit", "warrant", "fraud", "compromised", "unauthorized", "penalty"];
  var CRED = ["password", "username", "ssn", "social security", "cvv", "otp", "routing", "pin"];
  var MONEY = ["wire transfer", "gift card", "zelle", "venmo", "refund", "invoice", "bitcoin"];
  var ADVANCE = ["pay a small fee", "processing fee", "unlock your funds", "claim your inheritance",
    "pay to release", "western union fee"];
  var MALICE = ["wire transfer", "gift card", "verify your password", "account suspended",
    "click here to unlock", "urgent action required", "pay now or be locked", "seed phrase"];
  var PAY_ASK = ["pay now", "send payment", "send money", "gift card", "complete payment", "locked out"];
  var PAY_BRANDS = [
    { brand: "paypal", ok: ["paypal.com", "paypal.me"] },
    { brand: "venmo", ok: ["venmo.com"] },
    { brand: "zelle", ok: ["zellepay.com", "zelle.com"] },
    { brand: "cash app", ok: ["cash.app"] }
  ];
  var SHORT = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "rb.gy"];
  var BAD_TLD = ["ru", "tk", "xyz", "ml", "click", "work", "pw", "top", "gq", "ga", "cf"];
  var KNOWN = ["capitalone.com", "chase.com", "paypal.com", "google.com", "apple.com",
    "microsoft.com", "amazon.com"];
  var TFN = /\b(1[-.\s]?)?(8(00|33|44|55|66|77|88))[-.\s]?\d{3}[-.\s]?\d{4}\b/;

  function low(s) { return (s || "").toLowerCase(); }
  function senderHost(from) {
    var m = /@([a-z0-9.-]+\.[a-z]{2,24})/i.exec(from || "");
    return m ? m[1].toLowerCase() : "";
  }
  function hosts(text, from) {
    var h = {};
    var sh = senderHost(from);
    if (sh) h[sh] = true;
    var re = /https?:\/\/([^/\s"'<>]+)/gi, m;
    while ((m = re.exec(text || ""))) {
      var host = m[1].toLowerCase().split(":")[0].replace(/^www\./, "");
      if (host) h[host] = true;
    }
    return Object.keys(h);
  }
  function hasAny(text, list) {
    return list.filter(function (w) { return text.indexOf(w) >= 0; });
  }
  function paymentSpoof(text, from) {
    var hs = hosts(text, from);
    var ask = PAY_ASK.some(function (a) { return text.indexOf(a) >= 0; });
    for (var i = 0; i < PAY_BRANDS.length; i++) {
      var b = PAY_BRANDS[i];
      if (text.indexOf(b.brand) < 0) continue;
      if (!ask && text.indexOf("pay with " + b.brand) < 0 && text.indexOf(b.brand + " payment") < 0) continue;
      var ok = hs.some(function (h) {
        return b.ok.some(function (d) { return h === d || h.slice(-(d.length + 1)) === "." + d; });
      });
      if (!ok) return b.brand;
    }
    return null;
  }

  function analyze(input) {
    var from = (input.from || "").trim();
    var subject = (input.subject || "").trim();
    var body = (input.body || "").trim();
    var authPass = !!input.authPass;
    var text = low(subject + " " + body);
    var tags = [];
    var why = [];

    var spoof = paymentSpoof(text, from);
    if (spoof) {
      tags.push({ code: "PAYMENT_SPOOF", label: "Payment brand spoof", danger: true });
      why.push("Mentions " + spoof + " and asks for money, but From/links are not " + spoof + ".");
    }
    var mal = hasAny(text, MALICE);
    if (mal.length) {
      tags.push({ code: "HARD_MALICE", label: "Hard malice language", danger: true });
      why.push("Hit malice phrases: “" + mal.slice(0, 2).join("”, “") + "”.");
    }
    if (hasAny(text, URGENCY).length) {
      tags.push({ code: "URGENCY", label: "Urgency / fear", danger: true });
      why.push("Pressure language (urgent / locked / verify now).");
    }
    if (hasAny(text, FEAR).length) {
      tags.push({ code: "AUTHORITY", label: "Authority / legal threat", danger: true });
    }
    if (hasAny(text, CRED).length) {
      tags.push({ code: "SENSITIVE_ASK", label: "Credential / PII ask", danger: true });
      why.push("Asks for passwords, SSN, OTP, or card data.");
    }
    if (hasAny(text, ADVANCE).length) {
      tags.push({ code: "ADVANCE_FEE", label: "Advance fee", danger: true });
    }
    if (hasAny(text, MONEY).length && !spoof) {
      tags.push({ code: "MONEY_ASK", label: "Money / transfer ask", danger: false });
    }
    var hs = hosts(subject + " " + body, from);
    hs.forEach(function (h) {
      var tld = h.split(".").pop();
      if (BAD_TLD.indexOf(tld) >= 0) {
        tags.push({ code: "BAD_URL", label: "Abused TLD (" + tld + ")", danger: true });
        why.push("Link host “" + h + "” uses a frequently abused TLD.");
      }
      SHORT.forEach(function (s) {
        if (h === s || h.slice(-(s.length + 1)) === "." + s) {
          tags.push({ code: "SHORT_LINK", label: "Shortener hides destination", danger: true });
        }
      });
    });
    if (TFN.test(subject + " " + body)) {
      tags.push({ code: "TOLL_FREE", label: "Toll-free callback", danger: true });
      why.push("Pushes a toll-free number — common vish/smish callback.");
    }
    var sh = senderHost(from);
    var known = KNOWN.some(function (d) { return sh === d || sh.slice(-(d.length + 1)) === "." + d; });
    if (known && authPass && !spoof && !mal.length) {
      tags.push({ code: "AUTH_PASS", label: "Known-good + auth pass", danger: false });
      why.push("Sender domain is on the public known-good list and you marked auth pass. Domain alone would not clear it.");
    } else if (known && !authPass) {
      tags.push({ code: "KNOWN_NO_AUTH", label: "Known domain, no auth", danger: true });
      why.push("Looks like a brand From, but without SPF/DKIM/DMARC pass I still treat it as spoofable.");
    }

    var dangerN = tags.filter(function (t) { return t.danger; }).length;
    var verdict, tone, conf;
    if (spoof || mal.length || dangerN >= 2) {
      verdict = "Hold / likely threat";
      tone = "danger";
      conf = Math.min(0.97, 0.72 + dangerN * 0.08);
      why.unshift("I would rather quarantine this than miss it. Production ML can still raise or dampen after this layer.");
    } else if (known && authPass) {
      verdict = "Likely safe (auth-gated)";
      tone = "safe";
      conf = 0.12;
    } else if (dangerN === 1) {
      verdict = "Needs review";
      tone = "warn";
      conf = 0.62;
      why.unshift("One high-signal tag — hold for a human, don’t silently deliver.");
    } else {
      verdict = "No hard policy hit — ML would score this";
      tone = "muted";
      conf = 0.35;
      why.push("No malice / spoof / abused TLD. In production the SGD champion scores the text next. I don’t publish those weights.");
    }

    var seen = {};
    tags = tags.filter(function (t) {
      if (seen[t.code]) return false;
      seen[t.code] = true;
      return true;
    });
    return { verdict: verdict, tone: tone, confidence: conf, tags: tags, why: why, host: sh || "(none)" };
  }

  global.NullPointAnalyze = { analyze: analyze };
})(window);
