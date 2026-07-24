# Compliance Draft — NullPoint Guard (pre-beta)

**Status:** draft for internal review. Not legal advice. Update before App Store submission.

## 1. Product scope

NullPoint Guard analyzes phishing (email), smishing (SMS), and vishing (voice) content using on-device and server-side ML. CallKit integration uses caller ID and optional voicemail transcripts only — not live call audio without user consent.

## 2. Data collected

| Data | Purpose | Retention |
|---|---|---|
| Message/call metadata (sender, timestamp) | Detection + reputation | Configurable; default 90 days |
| Message body / transcript (user-submitted or opt-in VM) | ML scoring + explainability | Hashed at rest where possible |
| Device ID (opaque per install) | Rate limiting, abuse prevention | Until app uninstall + 30 days |
| JWT subject | Authentication | Session lifetime only |

We do **not** sell personal data. Third-party reputation vendors receive only the minimum identifier needed for lookup (phone number, URL, or email).

## 3. Security controls (implemented)

1. JWT bearer auth + RBAC (viewer / analyst / admin)
2. Token-bucket rate limiting (IP or token keyed)
3. Request body size limits (nginx 1 MB; API field max_length)
4. Security response headers (CSP, X-Frame-Options, nosniff)
5. Idempotency keys on threat writes
6. DLQ for durable buffering during DB outages
7. Secrets via environment variables only (never in git)
8. Structured access logs without raw message bodies
9. Argon2 password hashing with pepper
10. Champion/challenger model promotion gates

## 4. App Store / CallKit disclosures (planned)

- **Call Directory:** block/label known fraud numbers synced from user account
- **Message Filter:** classify unknown SMS via backend (Message Filter extension)
- **Optional Speech:** voicemail transcription on device or via STT vendor when user enables
- Privacy nutrition labels: Contact Info, User Content, Identifiers
- In-app false-positive appeal and personal allow-list

## 5. Vendor subprocessors

| Vendor | Use | DPA required |
|---|---|---|
| IPQualityScore | Phone / URL fraud intel | Yes (when enabled) |
| AssemblyAI / Deepgram | Optional STT | Yes (when enabled) |
| Cloud host (TBD) | API hosting | Yes |

## 6. User rights (target)

- Export detection history (Enterprise tier)
- Delete account and associated threat reports
- Opt out of optional transcript analysis

## 7. Open items before public beta

- [ ] Final privacy policy URL
- [ ] Rotate all keys exposed in development chat
- [ ] Pen test / SAST on `api/` and `web/`
- [ ] SOC2-lite audit log export (Enterprise)
- [ ] GDPR/CCPA data-processing addendum for B2B

## 8. Incident response (outline)

1. Detect via Sentry / metrics anomaly
2. Contain (revoke JWTs, disable vendor keys)
3. Notify affected users within 72h if PII impacted
4. Post-mortem + registry rollback if model regression

---

Last updated: 2026-07-09
