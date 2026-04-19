# DriveClean

Automatic cleanup for Google Drive, Photos & Gmail.

## Features

- **Scan ALL files** - Drive, Photos, Gmail (unlimited)
- **Live thumbnails** - See actual previews
- **Duplicates** - Find duplicates
- **Large files** - Files over 100MB
- **Old files** - Not accessed in 1+ year
- **Gmail cleanup** - Promotions, social, spam
- **Google Photos** - All photos
- **One-click delete** - Select and delete

## Local Development

```bash
npm install
npm start
```

Open http://localhost:3000

## Deploy to Render

1. Push to GitHub
2. Render dashboard → New → Web Service
3. Connect repo, set:
   - Build: `npm install`
   - Start: `node server.js`
4. Add Environment Variables:
   | Key | Value |
   |-----|-------|
   | GOOGLE_CLIENT_ID | (from Google Cloud Console) |
   | GOOGLE_CLIENT_SECRET | (from Google Cloud Console) |
   | REDIRECT_URI | https://your-app.onrender.com/api/auth/callback |
   | PORT | 3000 |
5. Deploy

## Google OAuth Setup

1. Go to https://console.cloud.google.com/apis/credentials
2. Create OAuth 2.0 Client ID
3. Add JavaScript origins:
   - http://localhost:3000 (dev)
   - https://your-app.onrender.com (prod)
4. Add redirect URIs:
   - http://localhost:3000/api/auth/callback
   - https://your-app.onrender.com/api/auth/callback

## Tech

- Node.js + Express
- Google APIs
- Sessions with encryption

## License

MIT