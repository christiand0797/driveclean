# DriveClean

Automatic cleanup for Google Drive, Photos & Gmail.

## Features

- **Scan ALL files** - Drive, Photos, Gmail (up to 5000 each)
- **Live thumbnails** - See actual previews of images, videos, documents
- **Duplicates** - Find files with same name
- **Large files** - Files over 100MB
- **Old files** - Not accessed in 1+ year
- **Empty files** - Zero byte files
- **Categories** - Images, videos, documents, audio, archives, folders
- **Gmail cleanup** - Promotions, social, spam emails
- **Google Photos** - All your photos
- **One-click delete** - Select multiple files and delete
- **Ad-supported** - Monetize with AdSense

## Quick Start

```bash
npm install
npm start
```

Open http://localhost:3000

## Deploy to Render (Free)

1. Push to GitHub
2. Go to https://render.com
3. New → Web Service
4. Connect your repo
5. Settings:
   - Build: `npm install`
   - Start: `node server.js`
6. Environment Variables:
   - `GOOGLE_CLIENT_ID`: Your Google OAuth Client ID
   - `GOOGLE_CLIENT_SECRET`: Your OAuth Client Secret
   - `REDIRECT_URI`: https://your-app.onrender.com/api/auth/callback
   - `PORT`: 3000
7. Deploy!

## Google Cloud Console Setup

1. Go to https://console.cloud.google.com/apis/credentials
2. Create OAuth 2.0 Client ID
3. Add JavaScript origins:
   - `http://localhost:3000` (dev)
   - `https://your-app.onrender.com` (prod)
4. Add redirect URIs:
   - `http://localhost:3000/api/auth/callback`
   - `https://your-app.onrender.com/api/auth/callback`

## AdSense Setup

Replace `YOUR_PUBLISHER_ID` in public/index.html with your AdSense ID.

## Tech

- Node.js + Express
- Google APIs (Drive, Photos, Gmail, OAuth)
- Sessions with encryption

## License

MIT