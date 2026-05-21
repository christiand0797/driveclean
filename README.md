# DriveClean

Open source Google Drive, Gmail, and Photos cleanup app built for fast, safe storage cleanup.

[![CI](https://github.com/christiand0797/driveclean/actions/workflows/ci.yml/badge.svg)](https://github.com/christiand0797/driveclean/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)

## What it does

- Scans Google Drive storage and shows total usage, file type mix, and largest folders
- Finds duplicate files using MD5 checksums when available, with name/size fallback for files without checksums
- Surfaces large files, old files, empty files, empty folders, temporary files, hidden files, orphaned files, public files, shared files, and files owned by others
- Lets you preview items, bulk move them to trash, restore trashed files, restore all trash in one action, and permanently empty trash
- **Rename files** directly from the interface
- **Move files** between folders
- **Fix permissions** - make public files private in bulk
- **Undo deletions** - restore recently deleted files within 5 minutes
- **Storage analytics** - visualize file type, age, and size distributions
- Supports full-drive scans or folder-only scans by pasting a Google Drive folder URL/ID
- Scans Gmail promotions/social counts with full pagination and Google Photos totals for a fuller storage summary
- Works as a single deployable Node.js app for local use, Docker, or Render
- Persists session-safe scan snapshots to disk so refreshes and restarts keep the latest results
- **Scan history** - track cleanup progress over time

## Stack

- Node.js + Express
- Google Drive, Gmail, Photos, and OAuth APIs
- Vanilla HTML/CSS/JS frontend
- WebSocket scan progress updates
- GitHub Actions CI smoke tests
- Docker support with multi-stage builds

## Quick Start

### Local Setup

```bash
npm ci
cp .env.example .env
# Fill in your Google OAuth credentials in .env
npm start
npm test
npm run check
```

Open [http://localhost:3000](http://localhost:3000).

### Docker

```bash
# Using docker-compose
cp .env.example .env
# Fill in your Google OAuth credentials
docker compose up --build

# Or with plain Docker
docker build -t driveclean .
docker run -p 3000:3000 --env-file .env driveclean
```

### Render

See [DEPLOY.md](DEPLOY.md) for step-by-step Render deployment instructions.

## Required environment variables

Copy `.env.example` and fill in:

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth Client Secret |
| `REDIRECT_URI` | OAuth callback URL (e.g., `http://localhost:3000/api/auth/callback`) |
| `ENCRYPTION_KEY` | AES encryption key for session tokens (generate with `node -e "require('crypto').randomBytes(32).toString('hex')"`) |
| `PORT` | Server port (optional, defaults to `3000`) |
| `SCAN_LIMIT` | Maximum files to scan (optional, defaults to `50000`) |

## Google OAuth setup

1. Create a Google Cloud OAuth 2.0 Web Application
2. Add authorized JavaScript origins:
   - `http://localhost:3000`
   - `https://your-app.onrender.com`
3. Add redirect URIs:
   - `http://localhost:3000/api/auth/callback`
   - `https://your-app.onrender.com/api/auth/callback`
4. Enable these APIs:
   - Google Drive API
   - Gmail API
   - Photos Library API

## API Endpoints

### Authentication
- `GET /api/auth/url` - Get OAuth authorization URL
- `GET /api/auth/callback` - OAuth callback handler
- `POST /api/auth/logout` - End session

### Session
- `GET /api/session` - Get current session info
- `GET /api/storage` - Get Google Drive storage quota

### Scanning
- `GET /api/scan/latest` - Get latest scan results
- `GET /api/scan/history` - Get scan history
- `GET /api/storage/analytics` - Get storage analytics (file types, age, size distributions)

### File Operations
- `POST /api/files/delete` - Move files to trash (body: `{ fileIds: string[] }`)
- `POST /api/files/restore` - Restore files from trash (body: `{ fileIds: string[] }`)
- `POST /api/files/rename` - Rename a file (body: `{ fileId: string, newName: string }`)
- `POST /api/files/move` - Move a file to another folder (body: `{ fileId: string, targetFolderId: string }`)
- `POST /api/files/permissions/fix` - Make files private (body: `{ fileIds: string[], makePrivate: boolean }`)
- `POST /api/files/undo-delete` - Undo recent deletions within 5 minutes (body: `{ fileIds: string[] }`)

### Trash
- `POST /api/trash/empty` - Permanently delete all trashed items

### Gmail
- `POST /api/gmail/clean` - Delete old Promotions/Social emails (body: `{ category: string, olderThanDays: number }`)

### Export
- `GET /api/export/csv?type=<category>` - Export files as CSV

### Health
- `GET /health` - Health check endpoint

All protected endpoints require an `x-session` header with a valid session ID.

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Space` / `S` | Start/stop scan |
| `Ctrl+A` | Select all in view |
| `Delete` | Delete selected files |
| `E` | Export as CSV |
| `1-9` | Switch tabs |
| `?` | Show keyboard shortcuts |
| `Esc` | Close modal / cancel scan |

## Features

### File Categories
- **All Files** - Complete file inventory
- **Large Files** - Files >= 100MB
- **Duplicates** - Files with matching MD5 checksums or name+size
- **Old Files** - Files not modified in over 1 year
- **Empty Files** - Zero-byte files
- **Empty Folders** - Folders with no children
- **Hidden Files** - Files starting with `.`
- **Temporary Files** - `.tmp`, `.temp`, `.crdownload`, etc.
- **Shared Files** - Files shared with others
- **Owned By Others** - Files you don't own
- **Orphaned Files** - Files with no parent folder
- **Public Files** - Files accessible to anyone
- **Folders** - Sorted by size
- **Trash** - Deleted files

### Security
- Session tokens encrypted with AES
- Rate limiting (120 requests/minute per IP)
- Security headers (CSP, X-Frame-Options, etc.)
- No sensitive data in client-side code

## Notes

- DriveClean moves files to trash by default before permanent deletion
- Session tokens are encrypted before being written to disk
- Drive scan snapshots are persisted to `scans.json`
- Scan history is persisted to `scan_history.json`
- Scan payloads include the full file inventory for the current session

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT
