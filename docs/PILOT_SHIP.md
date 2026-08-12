# Friends-and-family ship (I still have to paste secrets)

WET refactors wait. This is the path to a public URL, signup, Gmail OAuth, privacy, IPQS, and internal TestFlight.

## 1. Public URL

I cannot log into your Fly/Railway from here. After merge:

**Railway (easiest full stack):** new project → deploy from GitHub → use `docker-compose.prod.yml`. Set every name in `.env.example`. Public port **8088**.

**Fly.io (app only):** `fly launch --no-deploy` then `fly postgres create`, `fly redis create`, `fly secrets set` JWT / DB / Redis / `SIGNUP_OPEN=true` / `PUBLIC_BASE_URL=https://<app>.fly.dev`, then `fly deploy`. `fly.toml` is in the repo.

Then: `curl -s https://YOUR_HOST/health` must be healthy. Set `PUBLIC_BASE_URL` to that origin (no trailing slash).

## 2. Signup (open the gate)

`.env`:

```
SIGNUP_OPEN=true
JWT_SECRET_KEY=<long random, not changeme>
API_ADMIN_USER=<you>
API_ADMIN_PASSWORD=<long>
```

Friends go to `/app/signup` (email + 10+ char password, bcrypt). Role = `customer`. Your admin/pilot env users still work. Close the gate later with `SIGNUP_OPEN=false`.

## 3. Google OAuth (Gmail actually connects)

[Google Cloud Console](https://console.cloud.google.com/) → OAuth client (Web) → authorized redirect:

`https://YOUR_HOST/app/connectors/callback/gmail`

`.env`:

```
GOOGLE_OAUTH_CLIENT_ID=...
GOOGLE_OAUTH_CLIENT_SECRET=...
PUBLIC_BASE_URL=https://YOUR_HOST
```

Friend signs in → Connectors → Connect OAuth. Refresh token is Fernet-encrypted under their `account_sub`. Ingest uses IMAP XOAUTH2 (and still accepts app passwords). Restart app after adding routes/env: `docker compose restart app`.

## 4. Privacy

Live console: `/app/privacy` (also `/app/terms`). Static demo: `/privacy.html` on Pages. First person, deletion via Account → Delete account.

## 5. IPQS

`.env`: `IPQS_API_KEY=...` (never commit it). Identity + phone reputation already fail open without it.

Nightly / cron:

```
python scripts/enrich_directory.py
```

High-risk numbers land in `number_reputation` and show up on `GET /api/v1/vish/directory` (customer+ JWT). Robokiller has no public API — IPQS + our fleet reports cover pilot scale.

## 6. Internal TestFlight (you + 2 friends)

1. Public HTTPS from step 1.
2. `ios/project.yml` → `API_BASE_URL: "https://YOUR_HOST"` (and Info.plist same). `cd ios && xcodegen generate`.
3. Archive → App Store Connect → **Internal** testers (not External).
4. Friend creates a Signal Deck account (`/app/signup`) → Guard **Sign in** (same email/password) → wait for “Synced N blocks”.
5. Settings → Phone → Call Blocking & Identification → Directory. Messages → Unknown & Spam → SMS Filter. Force-quit Phone + Messages.

Call Directory sync is **customer+** now (not analyst-only). I still cannot upload the binary without your Apple ID.

## Honest leftover

- WET (dual trainers, `utils/` vs `common/`) is not user-facing. Leave it.
- Champion pkls stay local. Cold-start from seed if missing.
- Rotate anything that ever hit git or chat (pilot password, Funnel host).
