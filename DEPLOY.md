# Deploy Guide

## Render setup

1. Push this repository to GitHub.
2. Create a new Render Web Service.
3. Use:
   - Build command: `npm install`
   - Start command: `node server.js`
4. Add these environment variables:

| Variable | Purpose |
| --- | --- |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `REDIRECT_URI` | Full callback URL, e.g. `https://your-app.onrender.com/api/auth/callback` |
| `ENCRYPTION_KEY` | Stable secret used to encrypt stored session tokens |
| `PORT` | Optional; Render sets this automatically |
| `SCAN_LIMIT` | Optional upper bound for active-file scan payload size |

## OAuth checklist

Make sure the Google OAuth client includes both your local and hosted callback URLs:

- `http://localhost:3000/api/auth/callback`
- `https://your-app.onrender.com/api/auth/callback`

And both origins:

- `http://localhost:3000`
- `https://your-app.onrender.com`

## Runtime behavior

- Sessions are stored in memory and persisted to `sessions.json`
- Latest scan snapshots are persisted to `scans.json` for active sessions
- OAuth state values are validated server-side before the callback completes
- Scan results stay in memory per active session for exports and UI refreshes
- The service worker uses a fresh app-shell cache version (`driveclean-v3`)

## Troubleshooting

### Login fails after Google auth

- Confirm `REDIRECT_URI` exactly matches the Google OAuth app
- Confirm the deployed site origin is listed in Google Cloud
- Check Render logs for OAuth or environment variable errors

### Scans complete but categories look empty

- Re-run a Drive scan after deploying the latest code
- Confirm the account granted Drive metadata permissions
- Increase `SCAN_LIMIT` if the account is extremely large and the scan is being capped

### The app looks stale after deploy

- Hard refresh once so the browser swaps to the new service worker cache
- If needed, unregister the old service worker in browser devtools and reload
