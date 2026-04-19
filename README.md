# DriveClean

The ultimate Google Drive, Photos & Gmail cleanup tool.

## Features ✅

- **Unlimited Scanning** - All Drive files, Gmail emails, Google Photos (no limits)
- **Live Thumbnails** - Real previews for images, videos, documents
- **Smart Categorization** - Images, videos, documents, audio, archives, folders
- **Duplicate Detection** - Find files with same name
- **Large File Finder** - Files over 100MB
- **Old File Detection** - Files not accessed in 1+ year
- **Empty File Cleaner** - Find zero-byte files
- **Gmail Cleanup** - Promotions, social, spam emails
- **One-Click Actions** - Select multiple files, delete or move to trash
- **Progress Tracking** - Real-time scan progress
- **Storage Overview** - See your total storage usage
- **Token-Based Auth** - Secure in-memory token storage (no sessions)

## Quick Start

```bash
npm install
npm start
```

Open http://localhost:3000

## Deploy to Render (Free)

```bash
# 1. Push to GitHub
git add .
git commit -m "v2.5"
git push origin master

# 2. Go to render.com
# 3. New → Web Service
# 4. Connect GitHub repo
# 5. Set Environment Variables:
#    GOOGLE_CLIENT_ID=your_id
#    GOOGLE_CLIENT_SECRET=your_secret
#    REDIRECT_URI=https://your-app.onrender.com/api/auth/callback
#    PORT=3000
# 6. Deploy!
```

## Troubleshooting

### Login loops back to homepage after Google auth
1. Check browser console for errors
2. Verify environment variables are set in Render dashboard
3. Check Render logs for error messages: `render.com → Your App → Logs`

## Tech Stack

- Node.js + Express
- Google APIs (Drive, Photos, Gmail)
- OAuth 2.0
- Token-based authentication with AES encryption

## License

MIT