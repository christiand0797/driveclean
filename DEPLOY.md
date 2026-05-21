# Deploy Guide

## Status

- **GitHub:** https://github.com/christiand0797/driveclean
- **Render:** https://driveclean.onrender.com
- **Google Cloud project:** ASSETTO MODS
- **Credentials page:** https://console.cloud.google.com/apis/credentials?project=assetto-mods

---

## Step 1 — Get the real client secret from Google Cloud

The `.env` currently has a placeholder secret. You need the real one:

1. Go to: https://console.cloud.google.com/apis/credentials?project=assetto-mods
2. Find the OAuth 2.0 Client ID: `264924479984-v3m9cklc4g18i17g9n1540lslo89acj2.apps.googleusercontent.com`
3. Click the **edit pencil** ✏️
4. Copy the **Client Secret** (starts with `GOCSPX-`)
5. Paste it into `.env` as `GOOGLE_CLIENT_SECRET=<the real value>`

Also confirm these are configured on that OAuth client:

**Authorized JavaScript origins:**
```
http://localhost:3000
https://driveclean.onrender.com
```

**Authorized redirect URIs:**
```
http://localhost:3000/api/auth/callback
https://driveclean.onrender.com/api/auth/callback
```

If either is missing, click **Add URI**, paste it, click **Save**.

---

## Step 2 — Set environment variables on Render

1. Go to: https://dashboard.render.com → select **driveclean** service → **Environment**
2. Add these env vars (Add Variable for each):

| Key | Value |
|-----|-------|
| `GOOGLE_CLIENT_ID` | `264924479984-v3m9cklc4g18i17g9n1540lslo89acj2.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | `<the real secret from Step 1>` |
| `REDIRECT_URI` | `https://driveclean.onrender.com/api/auth/callback` |
| `ENCRYPTION_KEY` | Run `node -e "require('crypto').randomBytes(32).toString('hex')"` and paste the output — OR let Render generate it via `render.yaml` |
| `SCAN_LIMIT` | `50000` |

3. Click **Save Changes** — Render will redeploy automatically.

---

## Step 3 — Add test user to OAuth consent screen (if not already done)

Go to: https://console.cloud.google.com/apis/credentials/consent?project=assetto-mods

Confirm `christiand0797@gmail.com` is listed under **Test users**. If not, click **Add users** and add it.

---

## Step 4 — Run locally

```bash
# Make sure .env has the real GOOGLE_CLIENT_SECRET filled in
npm ci
npm start
# Open http://localhost:3000
```

---

## Step 5 — Run with Docker (alternative)

```bash
# Copy and fill in .env
cp .env.example .env

# Build and run
docker compose up --build

# Or with plain Docker
docker build -t driveclean .
docker run -p 3000:3000 --env-file .env driveclean
```

---

## Enabled APIs required (ASSETTO MODS project)

Go to: https://console.cloud.google.com/apis/library?project=assetto-mods

Make sure these are enabled:
- **Google Drive API**
- **Gmail API**
- **Photos Library API**
- **Google People API** (for userinfo/profile)

---

## Render service configuration

`render.yaml` in the repo root declares the service config. Render reads it automatically on connect. The `generateValue: true` on `ENCRYPTION_KEY` means Render will create a stable random key on first deploy — don't override it after that or all existing sessions will break.

---

## GitHub Actions CI

Every push triggers:
1. **Test job** — runs on Node 20 and 22
2. **Docker build** — verifies the Docker image builds and boots
3. **Security scan** — runs `npm audit` for critical vulnerabilities

All must pass before a deploy is considered healthy.

---

## Troubleshooting

### "redirect_uri_mismatch" on login
The REDIRECT_URI in your Render env vars doesn't exactly match what's registered in Google Cloud. They must be byte-for-byte identical — no trailing slash.

### Login succeeds but app shows "Session missing"
The `ENCRYPTION_KEY` changed between deploys. In Render dashboard, check Environment → `ENCRYPTION_KEY` — if Render regenerated it, sessions from before that deploy are invalid (users just log in again).

### Scans show empty categories
Re-run a fresh Drive scan after deploying. Old cached scan snapshots from a different session don't carry over.

### App look stale after deploy
Hard refresh (Ctrl+Shift+R). If still stale, open browser devtools → Application → Service Workers → Unregister, then reload.

### Free tier sleep (Render free plan)
Render free services spin down after 15 minutes of inactivity and take ~30 seconds to cold-start. Upgrade to Starter ($7/mo) to keep it always on.

### Docker build fails
Ensure you're using Docker with BuildKit enabled. The Dockerfile uses multi-stage builds requiring `node:20-alpine`.

### Rate limiting errors (429)
The app has built-in rate limiting (120 req/min per IP). Wait a minute and retry. Google API rate limits are also handled with exponential backoff.
