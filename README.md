# DriveClean Pro

The ultimate Google Drive, Photos & Gmail cleanup tool with AI-powered analysis.

## Features

### Scanner Types
- **Drive Scan** - Full Drive analysis with parallel processing (5x faster)
- **Gmail Scan** - Find promotions & social emails for cleanup
- **Photos Scan** - Find large videos in Google Photos

### File Analysis
- **Large Files** - Files over 100MB
- **Duplicates** - Files with same name
- **True Duplicates** - Content-based MD5 hash detection
- **Old Files** - Not modified in 1+ year
- **Empty Files** - Zero-byte files
- **Shared Files** - Files shared with others
- **Public Files** - Shared with anyone (security risk)
- **Orphaned Files** - Files without owners
- **Trash** - Files in trash

### Analytics
- File extension breakdown
- MIME type breakdown
- Folder size analysis
- Oldest/newest file tracking
- Gmail promotions & social count
- Scan history (last 10 scans)

### Actions
- One-click delete
- Batch delete with progress modal
- Empty trash
- Gmail bulk cleanup
- Keep newest/oldest quick actions
- Export to CSV & JSON
- Size filters
- File preview modal

### UI/UX
- Cyberpunk dark theme
- Light mode toggle
- Real-time progress
- Storage overview with warnings
- Sound notifications
- Keyboard shortcuts
- PWA installable
- Mobile optimized
- Human-readable dates ("2 weeks ago")

## Quick Start

```bash
npm install
npm start
```

Open http://localhost:3000

## Keyboard Shortcuts

| Key | Action |
|-----|-------|
| Space / S | Start/Stop scan |
| Ctrl+A | Select all |
| Del | Delete selected |
| E | Export CSV |
| 1-6 | Switch tabs |
| Esc | Cancel |

## Deploy to Render (Free)

1. Push to GitHub
2. Go to render.com
3. New → Web Service
4. Connect GitHub repo
5. Set Environment Variables:
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `REDIRECT_URI`
   - `PORT=3000`
6. Deploy!

## Google OAuth Setup

1. Go to Google Cloud Console → APIs & Services → Credentials
2. Create OAuth 2.0 Client ID
3. Add authorized origins:
   - http://localhost:3000
   - https://your-app.onrender.com
4. Add redirect URIs:
   - http://localhost:3000/api/auth/callback
   - https://your-app.onrender.com/api/auth/callback
5. Enable APIs:
   - Google Drive API
   - Gmail API
   - Photos Library API

## Tech Stack

- Node.js + Express
- WebSocket for real-time updates
- Google APIs (Drive, Photos, Gmail)
- OAuth 2.0 with AES-256 encryption
- Parallel API requests (5x faster)
- PWA with service worker

## License

MIT