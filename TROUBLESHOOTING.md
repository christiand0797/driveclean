# Troubleshooting Guide

## Quick Checklist

- [ ] Node.js version >= 18
- [ ] `.env` file exists with all required variables
- [ ] Google APIs enabled (Drive, Gmail, Photos)
- [ ] OAuth redirect URIs match exactly
- [ ] Port 3000 (or your PORT) is not in use

---

## Authentication Issues

### "redirect_uri_mismatch"

The `REDIRECT_URI` in your `.env` or Render env vars doesn't match what's registered in Google Cloud Console.

**Fix:**
1. Go to [Google Cloud Console > Credentials](https://console.cloud.google.com/apis/credentials)
2. Find your OAuth 2.0 Client ID
3. Ensure **Authorized redirect URIs** includes exactly:
   - `http://localhost:3000/api/auth/callback` (local)
   - `https://driveclean.onrender.com/api/auth/callback` (production)
4. No trailing slashes allowed

### Login succeeds but app shows "Session missing"

The `ENCRYPTION_KEY` changed between restarts. Session tokens encrypted with the old key can't be decrypted.

**Fix:**
- Set a stable `ENCRYPTION_KEY` in your `.env` or Render env vars
- Generate one: `node -e "require('crypto').randomBytes(32).toString('hex')"`
- On Render: don't override the auto-generated key after first deploy
- Users just need to log in again

### "ENCRYPTION_KEY not set" warning

The app generates a temporary key, but sessions won't survive a restart.

**Fix:** Add `ENCRYPTION_KEY` to your `.env` file.

---

## Scan Issues

### Scans show empty categories

Old cached scan data from a different session doesn't carry over.

**Fix:** Re-run a fresh Drive scan.

### Scan stops at a certain percentage

Rate limiting from Google APIs. The app retries automatically with exponential backoff.

**Fix:** Wait for the retry. For large drives, scans can take several minutes.

### "Folder not found or access denied"

The folder ID or URL is invalid, or you don't have permission.

**Fix:**
- Verify the folder exists in your Drive
- Ensure you have at least viewer access
- Try pasting the full folder URL instead of just the ID

### Scan limit reached

The app stops at `SCAN_LIMIT` files (default 50,000) to prevent excessive API usage.

**Fix:** Increase `SCAN_LIMIT` in `.env` if needed, or use folder-scoped scans.

---

## Gmail Issues

### Gmail scan shows 0 messages

The scan looks for messages older than a threshold (default 1 year).

**Fix:** Adjust the "Older than" dropdown before scanning to a shorter period.

### "Insufficient permission" for Gmail

The Gmail API scope wasn't granted during OAuth.

**Fix:**
1. Log out
2. Log in again
3. Accept all permission scopes when prompted

---

## Photos Issues

### Photos scan fails with 403

The Photos Library API isn't enabled or the scope wasn't granted.

**Fix:**
1. Enable Photos Library API in Google Cloud Console
2. Log out and log in again to re-authorize

---

## File Operation Issues

### Delete/Restore fails for some files

Some files can't be modified due to permissions or sharing restrictions.

**Fix:** Check the response for `failed` entries. Shared files owned by others may not be deletable.

### "Too many requests" (429)

You've exceeded the rate limit of 120 requests per minute.

**Fix:** Wait a minute and try again. The rate limit resets per minute.

### Undo delete doesn't work

Undo only works for deletions within the last 5 minutes.

**Fix:** If the window has passed, find the file in Trash and restore it manually.

---

## Deployment Issues

### Render cold start takes 30+ seconds

Free tier services spin down after 15 minutes of inactivity.

**Fix:** Upgrade to Render Starter ($7/mo) for always-on, or use a keep-alive service.

### "Cannot find module" on Render

Dependencies weren't installed correctly.

**Fix:**
1. Check Render build logs
2. Ensure `npm ci` runs successfully
3. Verify `package.json` lists all dependencies

### Docker build fails

Multi-stage build requires Node 20+.

**Fix:** Ensure Docker is using a recent base image. The Dockerfile uses `node:20-alpine`.

---

## Frontend Issues

### App looks stale after deploy

Service Worker may be caching old assets.

**Fix:**
1. Hard refresh: `Ctrl+Shift+R` (Windows) or `Cmd+Shift+R` (Mac)
2. Or: DevTools > Application > Service Workers > Unregister > Reload

### WebSocket connection fails

WSS connection blocked by proxy or firewall.

**Fix:**
- Ensure your deployment supports WebSocket upgrades
- On Render, WebSockets are supported by default
- Check browser console for connection errors

### Toast notifications don't appear

Browser may be blocking notifications.

**Fix:** Check browser settings for the site. Toasts use DOM elements, not browser notifications, so this is rare.

---

## Performance Issues

### High memory usage

Scan data is stored in memory. Large drives (50k+ files) can use significant RAM.

**Fix:**
- Use folder-scoped scans to limit inventory size
- Increase server memory on Render (paid plans)
- The app persists scans to disk, so restarts recover data

### Slow scan progress

Google API rate limits or large file counts.

**Fix:**
- Use folder-scoped scans for targeted cleanup
- The app already implements exponential backoff for rate limits
- Consider running scans during off-peak hours

---

## Logs

Server logs show timestamped entries:
```
[2026-05-21T05:00:00.000Z] INFO: DriveClean running on http://localhost:3000
[2026-05-21T05:01:00.000Z] INFO: User logged in: user@gmail.com
[2026-05-21T05:02:00.000Z] INFO: Starting Drive scan for job abc-123
[2026-05-21T05:05:00.000Z] INFO: Drive Scan Complete for job abc-123: 12345 items
```

On Render, view logs in the dashboard under your service > Logs.

---

## Still Stuck?

1. Check [GitHub Issues](https://github.com/christiand0797/driveclean/issues) for similar problems
2. Open a new issue with:
   - Steps to reproduce
   - Error messages
   - Environment (local/Render, Node version)
   - Relevant log snippets
