# Deploy Guide

## Quick Deploy

```bash
# Install dependencies
npm install

# Start locally
npm start
```

## Render Deployment

1. Push code to GitHub
2. Go to https://render.com
3. New → Web Service
4. Connect GitHub repo
5. Configure:
   - Build: `npm install`
   - Start: `node server.js`
6. Add Environment Variables:
   | Key | Value |
   |-----|-------|
   | GOOGLE_CLIENT_ID | your_client_id.apps.googleusercontent.com |
   | GOOGLE_CLIENT_SECRET | your_client_secret |
   | REDIRECT_URI | https://your-app.onrender.com/api/auth/callback |
   | PORT | 3000 |
7. Deploy!

## Auto-Deploy

Enable "Auto-Deploy" in Render settings to deploy automatically on GitHub push.

## Google OAuth Setup

1. Go to Google Cloud Console → APIs & Services → Credentials
2. Create OAuth 2.0 Client ID
3. Add authorized origins:
   - http://localhost:3000
   - https://your-app.onrender.com
4. Add authorized redirect URIs:
   - http://localhost:3000/api/auth/callback
   - https://your-app.onrender.com/api/auth/callback

## Troubleshooting

### Login loops back to homepage after Google auth
- Check browser console for JavaScript errors
- Verify environment variables in Render dashboard
- Check Render logs: App → Logs
- Clear browser cookies and retry

### Session/Token issues
- Clear browser cookies
- Make sure REDIRECT_URI matches exactly

### 503 errors
- Check environment variables are set
- Redeploy

### Can't see all files
- First scan takes time (up to 5000 files)
- Refresh page to scan again