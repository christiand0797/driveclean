require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { google } = require('googleapis');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Generate encryption key if not set
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

// In-memory user store
const users = new Map();

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use(express.static(path.join(__dirname, 'public')));

// Encrypt tokens
function encrypt(text) {
  const CryptoJS = require('crypto-js');
  return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}

function decrypt(encrypted) {
  const CryptoJS = require('crypto-js');
  try {
    return CryptoJS.AES.decrypt(encrypted, ENCRYPTION_KEY).toString(CryptoJS.enc.Utf8);
  } catch (e) { return null; }
}

function createToken() {
  return crypto.randomBytes(32).toString('hex');
}

function createOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URI
  );
}

// AUTH URL - returns Google OAuth URL
app.get('/api/auth/url', (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID === 'YOUR_CLIENT_ID') {
    return res.status(500).json({ error: 'GOOGLE_CLIENT_ID not configured' });
  }
  
  const oauth2Client = createOAuth2Client();
  
  const scopes = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive.metadata.readonly',
    'https://www.googleapis.com/auth/drive.photos.readonly',
    'https://www.googleapis.com/auth/photoslibrary.readonly',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email'
  ];
  
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent'
  });
  
  res.json({ url });
});

// AUTH CALLBACK - exchange code for tokens, redirect to home with token
app.get('/api/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  
  if (error) {
    console.error('Auth error:', error);
    return res.redirect('/?error=' + encodeURIComponent(error));
  }
  
  if (!code) {
    return res.redirect('/?error=no_code');
  }
  
  try {
    const oauth2Client = createOAuth2Client();
    const { tokens } = await oauth2Client.getToken(code);
    
    if (!tokens) {
      return res.redirect('/?error=no_tokens');
    }
    
    // Get user info
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    
    let user;
    try {
      user = await oauth2.userinfo.get();
    } catch (err) {
      console.error('User info error:', err.message);
      return res.redirect('/?error=user_info_failed');
    }
    
    if (!user?.data) {
      return res.redirect('/?error=no_user');
    }
    
    // Create auth token
    const authToken = createToken();
    
    // Store user data with encrypted tokens
    users.set(authToken, {
      tokens: encrypt(JSON.stringify(tokens)),
      email: user.data.email,
      name: user.data.name,
      picture: user.data.picture
    });
    
    console.log('Logged in:', user.data.email);
    
    // Redirect to home with token - client will handle storing it
    res.redirect('/?login=success&token=' + authToken);
    
  } catch (err) {
    console.error('Auth error:', err.message);
    res.redirect('/?error=auth_failed');
  }
});

// GET CURRENT USER - check if logged in
app.get('/api/user', (req, res) => {
  const token = req.query.token || req.cookies.token;
  
  if (!token) {
    return res.json({ loggedIn: false });
  }
  
  const user = users.get(token);
  
  if (!user) {
    return res.json({ loggedIn: false });
  }
  
  res.json({
    loggedIn: true,
    user: {
      email: user.email,
      name: user.name,
      picture: user.picture
    }
  });
});

// LOGOUT
app.get('/api/logout', (req, res) => {
  const token = req.query.token || req.cookies.token;
  if (token) users.delete(token);
  res.json({ success: true });
});

// Require auth middleware
function requireAuth(req, res, next) {
  const token = req.query.token || req.cookies.token;
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const user = users.get(token);
  if (!user) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  req.user = user;
  next();
}

function getAuthUser(req) {
  const token = req.query.token || req.cookies.token;
  return token ? users.get(token) : null;
}

// GET STORAGE
app.get('/api/storage', requireAuth, async (req, res) => {
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(getAuthUser(req).tokens)));
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    const about = await drive.about.get({ fields: 'storageQuota' });
    res.json({
      usage: about.data.storageQuota?.limit || 0,
      usageInDrive: about.data.storageQuota?.usageInDrive || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SCAN - get all files
app.post('/api/scan', requireAuth, async (req, res) => {
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(getAuthUser(req).tokens)));
    
    const results = { 
      total: 0, files: [], duplicates: [], large: [], old: [], empty: [], 
      images: [], videos: [], documents: [], 
      emails: [], promotions: [], spam: [],
      photos: []
    };
    
    // DRIVE FILES - ALL files not in trash
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    let pageToken = null;
    let fileCount = 0;
    
    do {
      const response = await drive.files.list({
        pageSize: 1000,
        fields: 'nextPageToken,files(id,name,mimeType,size,createdTime,modifiedTime,thumbnailLink,iconLink,webViewLink,shared,starred)',
        q: "trashed=false",
        pageToken: pageToken
      });
      
      const files = response.data?.files || [];
      if (!files.length) break;
      
      results.files.push(...files);
      fileCount += files.length;
      pageToken = response.data?.nextPageToken;
      console.log('Loaded ' + fileCount + ' Drive files');
    } while (pageToken);
    
    results.total = results.files.length;
    console.log('Total Drive files: ' + results.total);
    
    // Categorize
    const nameCount = {};
    results.files.forEach(f => nameCount[f.name] = (nameCount[f.name] || 0) + 1);
    results.duplicates = results.files.filter(f => nameCount[f.name] > 1);
    results.large = results.files.filter(f => parseInt(f.size || 0) > 100 * 1024 * 1024);
    results.empty = results.files.filter(f => parseInt(f.size || 0) === 0 && !f.mimeType?.includes('folder'));
    results.images = results.files.filter(f => f.mimeType?.includes('image'));
    results.videos = results.files.filter(f => f.mimeType?.includes('video'));
    results.documents = results.files.filter(f => f.mimeType?.includes('document') || f.mimeType?.includes('sheet'));
    
    const oneYear = new Date(); oneYear.setFullYear(oneYear.getFullYear() - 1);
    results.old = results.files.filter(f => new Date(f.createdTime) < oneYear);
    
    // GMAIL
    try {
      const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
      
      let emailPage = null;
      do {
        const r = await gmail.users.messages.list({ userId: 'me', maxResults: 500, pageToken: emailPage, q: '-in:trash' });
        if (!r.data?.messages?.length) break;
        results.emails.push(...r.data.messages);
        emailPage = r.data.nextPageToken;
      } while (emailPage);
      
      console.log('Total emails: ' + results.emails.length);
      
      results.promotions = (await gmail.users.messages.list({ userId: 'me', maxResults: 500, q: 'category:promotions -in:trash' })).data?.messages || [];
      results.spam = (await gmail.users.messages.list({ userId: 'me', maxResults: 500, q: 'category:spam -in:trash' })).data?.messages || [];
    } catch (e) { console.log('Gmail error:', e.message); }
    
    // GOOGLE PHOTOS
    try {
      const photos = google.photoslibrary({ version: 'v1', auth: oauth2Client });
      let photoPage = null;
      do {
        const p = await photos.mediaItems.list({ pageSize: 100, pageToken: photoPage });
        if (!p.data?.mediaItems?.length) break;
        results.photos.push(...p.data.mediaItems);
        photoPage = p.data.nextPageToken;
      } while (photoPage);
      console.log('Total Photos: ' + results.photos.length);
    } catch (e) { console.log('Photos error:', e.message); }
    
    res.json(results);
  } catch (err) {
    console.error('Scan error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// DELETE files permanently
app.post('/api/delete', requireAuth, async (req, res) => {
  const { fileIds } = req.body;
  if (!fileIds?.length) return res.status(400).json({ error: 'No files' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(getAuthUser(req).tokens)));
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    
    let deleted = 0;
    for (const id of fileIds.slice(0, 100)) {
      try {
        await drive.files.delete({ fileId: id });
        deleted++;
      } catch (e) { console.log('Delete error:', e.message); }
    }
    res.json({ deleted });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// TRASH files
app.post('/api/trash', requireAuth, async (req, res) => {
  const { fileIds } = req.body;
  if (!fileIds?.length) return res.status(400).json({ error: 'No files' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(getAuthUser(req).tokens)));
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    
    for (const id of fileIds.slice(0, 100)) {
      try {
        await drive.files.update({ fileId: id, requestBody: { trashed: true } });
      } catch (e) {}
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// EMPTY TRASH
app.post('/api/empty-trash', requireAuth, async (req, res) => {
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(getAuthUser(req).tokens)));
    await google.drive({ version: 'v3', auth: oauth2Client }).files.emptyTrash();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Home
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('DriveClean running on http://localhost:' + PORT);
});

module.exports = app;