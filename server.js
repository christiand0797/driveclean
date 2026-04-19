require('dotenv').config();
const express = require('express');

// Suppress MemoryStore warning in production
const original warn = console.warn;
console.warn = (...args) => {
  if (args[0]?.includes?.('MemoryStore')) return;
  original.apply(console, args);
};
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { google } = require('googleapis');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const config = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    redirectUri: process.env.REDIRECT_URI || ''
  },
  sessionSecret: process.env.SESSION_SECRET || 'driveclean-secret',
  encryptionKey: process.env.ENCRYPTION_KEY || 'driveclean-key'
};

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Use memory store for sessions (fine for small apps)
const MemoryStore = require('express-session').MemoryStore;
const sessionStore = new MemoryStore();

app.use(session({
  store: sessionStore,
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true,
    secure: false,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

function encrypt(text) {
  const CryptoJS = require('crypto-js');
  return CryptoJS.AES.encrypt(text, config.encryptionKey).toString();
}

function decrypt(encrypted) {
  const CryptoJS = require('crypto-js');
  try {
    return CryptoJS.AES.decrypt(encrypted, config.encryptionKey).toString(CryptoJS.enc.Utf8);
  } catch (e) { return null; }
}

function createOAuth2Client() {
  return new google.auth.OAuth2(config.google.clientId, config.google.clientSecret, config.google.redirectUri);
}

// ==================== AUTH ====================

app.get('/api/auth/url', (req, res) => {
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

app.get('/api/auth/callback', async (req, res) => {
  const { code, error: errorDesc } = req.query;
  if (errorDesc) return res.redirect('/?error=' + encodeURIComponent(errorDesc));
  if (!code) return res.redirect('/?error=no_code');
  
  try {
    const oauth2Client = createOAuth2Client();
    const { tokens } = await oauth2Client.getToken(code);
    req.session.tokens = encrypt(JSON.stringify(tokens));
    
    // Force save session before redirect
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.redirect('/?error=session_failed');
      }
      console.log('Session saved, redirecting...');
      res.redirect('/');
    });
  } catch (err) {
    console.error('Auth error:', err.message);
    res.redirect('/?error=auth_failed');
  }
});

// ==================== USER ====================

app.get('/api/user', (req, res) => {
  console.log('Session ID:', req.sessionID);
  console.log('Has tokens:', !!req.session.tokens);
  
  if (!req.session.tokens) return res.json({ loggedIn: false, sessionId: req.sessionID });
  
  try {
    const oauth2Client = createOAuth2Client();
    const decrypted = decrypt(req.session.tokens);
    console.log('Decrypted tokens:', !!decrypted);
    
    if (!decrypted) return res.json({ loggedIn: false, sessionId: req.sessionID });
    
    const tokens = JSON.parse(decrypted);
    oauth2Client.setCredentials(tokens);
    
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    oauth2.userinfo.get((err, user) => {
      if (err) return res.json({ loggedIn: false, error: err.message, sessionId: req.sessionID });
      res.json({ loggedIn: true, user: { name: user.data.name, email: user.data.email, picture: user.data.picture }, sessionId: req.sessionID });
    });
  } catch (e) {
    res.json({ loggedIn: false, error: e.message, sessionId: req.sessionID });
  }
});

app.get('/api/debug', (req, res) => {
  res.json({
    sessionId: req.sessionID,
    hasTokens: !!req.session.tokens,
    cookie: req.headers.cookie,
    userAgent: req.headers['user-agent']
  });
});

// ==================== STORAGE ====================

app.get('/api/storage', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    const about = await drive.about.get({ fields: 'storageQuota,quotaBytesTotal,quotaBytesUsedAggregate' });
    const quota = about.data.storageQuota || {};
    res.json({
      usage: quota.limit || 0,
      usageInDrive: quota.usageInDrive || 0,
      usageInTrash: quota.usageInTrash || 0,
      totalUsed: about.data.quotaBytesUsedAggregate || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== SCAN ====================

app.post('/api/scan', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    res.write('Scanning...\n');
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    
    const results = { 
      total: 0,
      files: [], duplicates: [], large: [], old: [], empty: [], 
      images: [], videos: [], documents: [], audios: [], archives: [],
      emails: [], promotions: [], social: [], spam: [],
      photos: [], shared: [], starred: [], folders: []
    };
    
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    let pageToken = null;
    let fileCount = 0;
    
    res.write('Scanning Drive files...\n');
    do {
      const response = await drive.files.list({
        pageSize: 100,
        fields: 'nextPageToken,files(id,name,mimeType,size,createdTime,modifiedTime,thumbnailLink,iconLink,webViewLink,shared,starred)',
        q: "trashed=false",
        pageToken: pageToken
      });
      
      const files = response.data.files || [];
      if (!files.length) break;
      
      results.files.push(...files);
      fileCount += files.length;
      pageToken = response.data.nextPageToken;
      res.write(`Loaded ${fileCount} files...\n`);
    } while (pageToken);
    
    results.total = results.files.length;
    res.write(`Total: ${results.total} files\n`);
    
    // Categorize
    const nameCount = {};
    results.files.forEach(f => nameCount[f.name] = (nameCount[f.name] || 0) + 1);
    results.duplicates = results.files.filter(f => nameCount[f.name] > 1);
    results.large = results.files.filter(f => parseInt(f.size || 0) > 100 * 1024 * 1024);
    results.empty = results.files.filter(f => parseInt(f.size || 0) === 0 && !f.mimeType?.includes('folder'));
    results.images = results.files.filter(f => f.mimeType?.includes('image'));
    results.videos = results.files.filter(f => f.mimeType?.includes('video'));
    results.audios = results.files.filter(f => f.mimeType?.includes('audio'));
    results.documents = results.files.filter(f => f.mimeType?.includes('document') || f.mimeType?.includes('sheet') || f.mimeType?.includes('presentation'));
    results.archives = results.files.filter(f => f.mimeType?.includes('zip') || f.mimeType?.includes('rar') || f.mimeType?.includes('tar'));
    results.shared = results.files.filter(f => f.shared);
    results.starred = results.files.filter(f => f.starred);
    results.folders = results.files.filter(f => f.mimeType?.includes('folder'));
    
    const oneYear = new Date(); oneYear.setFullYear(oneYear.getFullYear() - 1);
    results.old = results.files.filter(f => new Date(f.createdTime) < oneYear);
    
    res.write('Scanning Gmail...\n');
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    
    // All emails
    let emailPage = null;
    do {
      try {
        const r = await gmail.users.messages.list({ userId: 'me', maxResults: 500, pageToken: emailPage });
        const msgs = r.data.messages || [];
        if (!msgs.length) break;
        results.emails.push(...msgs);
        emailPage = r.data.nextPageToken;
        if (results.emails.length % 1000 === 0) res.write(`${results.emails.length} emails...\n`);
      } catch (e) { break; }
    } while (emailPage);
    
    // Promotions
    try {
      let p = await gmail.users.messages.list({ userId: 'me', maxResults: 500, q: 'category:promotions' });
      results.promotions = p.data.messages || [];
    } catch (e) {}
    
    // Social
    try {
      let s = await gmail.users.messages.list({ userId: 'me', maxResults: 500, q: 'category:social' });
      results.social = s.data.messages || [];
    } catch (e) {}
    
    // Spam
    try {
      let sp = await gmail.users.messages.list({ userId: 'me', maxResults: 500, q: 'category:spam' });
      results.spam = sp.data.messages || [];
    } catch (e) {}
    
    res.write('Scanning Google Photos...\n');
    try {
      const photos = google.photoslibrary({ version: 'v1', auth: oauth2Client });
      let photoPage = null;
      do {
        const p = await photos.mediaItems.list({ pageSize: 100, pageToken: photoPage });
        const items = p.data.mediaItems || [];
        if (!items.length) break;
        results.photos.push(...items);
        photoPage = p.data.nextPageToken;
      } while (photoPage);
    } catch (e) { res.write('Photos error: ' + e.message + '\n'); }
    
    res.write('Done!\n');
    res.json(results);
  } catch (err) {
    console.error('Scan error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ==================== DELETE ====================

app.post('/api/delete', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  const { fileIds } = req.body;
  if (!fileIds?.length) return res.status(400).json({ error: 'No files' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    
    let deleted = 0;
    for (const id of fileIds.slice(0, 100)) {
      try {
        await drive.files.delete({ fileId: id });
        deleted++;
      } catch (e) { console.log('Delete error:', e.message); }
    }
    res.json({ deleted, count: deleted });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/trash', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  const { fileIds } = req.body;
  if (!fileIds?.length) return res.status(400).json({ error: 'No files' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
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

app.post('/api/empty-trash', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    await google.drive({ version: 'v3', auth: oauth2Client }).files.emptyTrash();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== RENAME ====================

app.post('/api/rename', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  const { fileId, newName } = req.body;
  if (!fileId || !newName) return res.status(400).json({ error: 'Missing fileId or newName' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    await google.drive({ version: 'v3', auth: oauth2Client }).files.update({
      fileId,
      requestBody: { name: newName }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== FILE INFO ====================

app.get('/api/file/:fileId', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    const file = await google.drive({ version: 'v3', auth: oauth2Client }).files.get({
      fileId: req.params.fileId,
      fields: 'id,name,mimeType,size,createdTime,modifiedTime,thumbnailLink,webViewLink,description,owners,shared'
    });
    res.json(file.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== COPY FILE ====================

app.post('/api/copy', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  const { fileId, newName } = req.body;
  if (!fileId) return res.status(400).json({ error: 'Missing fileId' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    const file = await google.drive({ version: 'v3', auth: oauth2Client }).files.copy({
      fileId,
      requestBody: { name: newName || undefined }
    });
    res.json(file.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== LOGOUT ====================

app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// ==================== HOME ====================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check for Render
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Status endpoint
app.get('/api/status', (req, res) => {
  res.json({ 
    status: 'running',
    sessionId: req.sessionID,
    hasSession: !!req.session.tokens,
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

app.listen(PORT, () => {
  console.log('DriveClean running on port ' + PORT);
});

module.exports = app;