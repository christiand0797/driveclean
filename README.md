# DriveClean

Open source Google Drive cleanup app built for fast, safe storage cleanup.

## What it does

- Scans Google Drive storage and shows total usage, file type mix, and largest folders
- Finds duplicate files using MD5 checksums when available, with name/size fallback for files without checksums
- Surfaces large files, old files, empty files, empty folders, temporary files, hidden files, orphaned files, public files, shared files, and files owned by others
- Lets you preview items, bulk move them to trash, restore trashed files, restore all trash in one action, and permanently empty trash
- Supports full-drive scans or folder-only scans by pasting a Google Drive folder URL/ID
- Scans Gmail promotions/social counts with full pagination and Google Photos totals for a fuller storage summary
- Works as a single deployable Node.js app for local use or Render
- Persists session-safe scan snapshots to disk so refreshes and restarts keep the latest results

## Stack

- Node.js + Express
- Google Drive, Gmail, Photos, and OAuth APIs
- Vanilla HTML/CSS/JS frontend
- WebSocket scan progress updates
- GitHub Actions CI smoke tests

## Local setup

```bash
npm ci
npm start
npm test
npm run check
```

Open [http://localhost:3000](http://localhost:3000).

## Required environment variables

Copy `.env.example` and fill in:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `REDIRECT_URI`
- `ENCRYPTION_KEY`
- `PORT` (optional)
- `SCAN_LIMIT` (optional, defaults to `50000`)

## Google OAuth setup

1. Create a Google Cloud OAuth 2.0 Web Application.
2. Add authorized origins:
   - `http://localhost:3000`
   - `https://your-app.onrender.com`
3. Add redirect URIs:
   - `http://localhost:3000/api/auth/callback`
   - `https://your-app.onrender.com/api/auth/callback`
4. Enable:
   - Google Drive API
   - Gmail API
   - Photos Library API

## Notes

- DriveClean moves files to trash by default before permanent deletion.
- Session tokens are encrypted before being written to disk.
- Drive scan snapshots are persisted to `scans.json`, and stale snapshots are pruned when sessions disappear.
- Scan payloads include the full file inventory for the current session so the UI can filter and paginate locally.

## License

MIT
