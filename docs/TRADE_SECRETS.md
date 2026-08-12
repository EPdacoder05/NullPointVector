# What I publish vs what I keep

I made NullPoint **source-available** so you can read how Signal Deck works. I did **not** open-source the product’s crown jewels.

| You can clone | Stays on my machine |
|---|---|
| Detectors, Signal Deck UI, policy, CI | Champion `*.pkl`, anomaly IF, registry |
| Golden eval jsonl (held-out gate) | Real `feedback.jsonl` (labeled mail) |
| `data/vish_campaigns/example.json` | Live campaign packs |
| `.env.example` (names only) | `.env`, PilotSecrets, Funnel host |
| Gate metrics I choose to show | Internal process dumps |

## If you clone this to run it

Drop your own models next to the tree (same paths). If a pkl is missing, the detector cold-starts from the seed corpus — fine for CI, not my production champion.

```bash
PhishGuard/phish_mlm/models/phishing_sgd_model.pkl
SmishGuard/smish_mlm/models/smishing_sgd_model.pkl
VishGuard/vish_mlm/models/vishing_sgd_model.pkl
data/vish_campaigns/tax_resolution.json   # yours, not in git
```

iOS: copy `ios/PilotSecrets.example.swift` → `ios/Sources/NullPointGuard/PilotSecrets.swift` and fill `username`, `password`, and `apiBaseURL`. Don’t commit real values.

## Old commits

Untracking a file does not erase history. Anything that hit `main` while the repo was public, I treat as burned: I rotate pilot passwords and hosts, and I keep new champions off git. Making the repo private is the only way to stop fresh clones of those old commits.

I am **not** rewriting git history. Filter-repo / BFG + force-push would not un-leak clones, and it would smash SHAs, PRs, and Actions. Local pkls stay if you only `git rm --cached`.

## Demo

Walk the console (fictional senders, no weights):

https://epdacoder05.github.io/NullPointVector/
