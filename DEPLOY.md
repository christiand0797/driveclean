# Deploy Guide

## Quick Deploy

```bash
npm install
npm start
```

Open http://localhost:3000

## Running on Render

### 1. GitHub Setup
```bash
git add .
git commit -m "DriveClean Pro v2.0"
git push origin main
```

### 2. Render Setup
1. Go to https://render.com
2. New → Web Service
3. Connect GitHub repo
4. Configure:
   - Build Command: `npm install`
   - Start Command: `node server.js`
5. Add Environment Variables:

| Variable | Value | Example |
|---------|-------|---------|
| GOOGLE_CLIENT_ID | Your OAuth Client ID | xxx.apps.googleusercontent.com |
| GOOGLE_CLIENT_SECRET | Your OAuth Secret | xxxx |
| REDIRECT_URI | Your Render URL | https://driveclean.onrender.com/api/auth/callback |
| PORT | 3000 | 3000 |
| ENCRYPTION_KEY | Random 32-char key | (auto-generated) |

### 3. Auto-Deploy
Enable "Auto-Deploy" in Render settings for automatic deployments on GitHub push.

## Google OAuth Setup

### Create Credentials
1. Go to https://console.cloud.google.com/apis/credentials
2. Create Credentials → OAuth client ID
3. Application type: Web application
4. Add authorized origins:
   - `http://localhost:3000`
   - `https://your-app.onrender.com`
5. Add authorized redirect URIs:
   - `http://localhost:3000/api/auth/callback`
   - `https://your-app.onrender.com/api/auth/callback`

### Enable APIs
Enable these APIs in Google Cloud Console:
- Google Drive API
- Gmail API
- Photos Library API

## Troubleshooting

### Login loops back after Google auth
- Check browser console for JavaScript errors
- Verify all environment variables set in Render
- Check Render logs: App → Logs
- Clear browser cookies and retry

### 503 Service Unavailable
- Verify environment variables are set correctly
- Redeploy the service

### Can't see all files
- First scan takes time (parallel processing)
- Refresh to scan again

### Session expired
- Clear browser cookies
- Log in again

## Security Notes

- Tokens encrypted with AES-256
- No persistent storage of credentials
- Sessions stored in memory + JSON file
- Security headers enabled (X-Frame-Options, CSP)