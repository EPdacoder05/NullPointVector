# What stays private vs public

This repo is **source-available**. Product IP is not.

| Public (git) | Private (local / not git) |
|---|---|
| Detectors, Signal Deck, policy, CI workflows | Champion `*.pkl` + anomaly IF + registry |
| Golden eval jsonl (held-out gate, synthetic-style) | `feedback.jsonl` (real labeled mail) |
| `data/vish_campaigns/example.json` | Real campaign packs (`tax_resolution.json`, …) |
| `.env.example` (names only) | `.env`, PilotSecrets values, Funnel host |
| Gate *metrics* you choose to publish | Unpublished process dumps |

## Local restore

Copy private artifacts next to the public tree (same paths as before). Detectors **cold-start** from the seed corpus if a pkl is missing — good enough for CI, not your production champion.

```bash
# models (gitignored)
PhishGuard/phish_mlm/models/phishing_sgd_model.pkl
SmishGuard/smish_mlm/models/smishing_sgd_model.pkl
VishGuard/vish_mlm/models/vishing_sgd_model.pkl

# campaigns
data/vish_campaigns/tax_resolution.json   # not committed
```

iOS: copy `ios/PilotSecrets.example.swift` → `ios/Sources/NullPointGuard/PilotSecrets.swift` and fill username/password/apiBase. Do not commit real values.

## History warning

Making files gitignored does **not** erase them from `main` history. If this GitHub repo is public, treat those blobs as burned: rotate pilot passwords, rotate Funnel/host names, keep real champions off git going forward. Making the GitHub repo **private** is the only way to stop anonymous clones of old commits.
