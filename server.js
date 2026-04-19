require('dotenv').config();
const express = require('express');
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
  sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  encryptionKey: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex')
};

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: false,
    sameSite: 'lax'
  }
}));

function encrypt(text) {
  const CryptoJS = require('crypto-js');
  return CryptoJS.AES.encrypt(text, config.encryptionKey).toString();
}

function decrypt(encrypted) {
  const CryptoJS = require('crypto-js');
  return CryptoJS.AES.decrypt(encrypted, config.encryptionKey).toString(CryptoJS.enc.Utf8);
}

function createOAuth2Client() {
  return new google.auth.OAuth2(config.google.clientId, config.google.clientSecret, config.google.redirectUri);
}

// AUTH
app.get('/api/auth/url', (req, res) => {
  const oauth2Client = createOAuth2Client();
  const scopes = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive.metadata.readonly',
    'https://www.googleapis.com/auth/drive.readonly',
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
    req.session.userEmail = tokens.email;
    
    res.redirect('/');
  } catch (err) {
    console.error('Auth error:', err.message);
    res.redirect('/?error=auth_failed');
  }
});

app.get('/api/user', (req, res) => {
  if (!req.session.tokens) return res.json({ loggedIn: false });
  
  try {
    const oauth2Client = createOAuth2Client();
    const tokens = JSON.parse(decrypt(req.session.tokens));
    oauth2Client.setCredentials(tokens);
    
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    oauth2.userinfo.get((err, user) => {
      if (err) return res.json({ loggedIn: false, error: err.message });
      res.json({ loggedIn: true, user: { name: user.data.name, email: user.data.email, picture: user.data.picture } });
    });
  } catch (e) {
    res.json({ loggedIn: false, error: e.message });
  }
});

// STORAGE
app.get('/api/storage', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
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

// SCAN - ALL FILES
app.post('/api/scan', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    
    const results = { 
      files: [], duplicates: [], large: [], old: [], empty: [], 
      images: [], videos: [], documents: [], audios: [], archives: [],
      emails: [], promotions: [], social: [], spam: [],
      photos: [], shared: [], starred: [], folders: []
    };
    
    // === DRIVE - ALL FILES (no limit) ===
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    let fileCount = 0;
    let nextPageToken = null;
    
    do {
      const response = await drive.files.list({
        pageSize: 100,
        fields: 'nextPageToken,files(id,name,mimeType,size,createdTime,modifiedTime,thumbnailLink,iconLink,webViewLink,shared,starred,parents)',
        q: "trashed=false",
        orderBy: 'modifiedTime desc',
        pageToken: nextPageToken
      });
      
      const files = response.data.files || [];
      if (!files.length) break;
      
      results.files.push(...files);
      fileCount += files.length;
      nextPageToken = response.data.nextPageToken;
      
      console.log('Scanned', fileCount, 'files...');
    } while (nextPageToken);
    
    console.log('Total Drive files scanned:', results.files.length);
    
    results.total = results.files.length;
    
    // Analyze all files
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
    
    // === GMAIL - ALL EMAILS (unlimited) ===
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    let emailCount = 0;
    let emailPage = null;
    try {
      do {
        const r = await gmail.users.messages.list({ userId: 'me', maxResults: 500, pageToken: emailPage });
        const msgs = r.data.messages || [];
        if (!msgs.length) break;
        results.emails.push(...msgs);
        emailCount += msgs.length;
        emailPage = r.data.nextPageToken;
        console.log('Scanned', emailCount, 'emails...');
      } while (emailPage);
    } catch (e) { console.log('Gmail error:', e.message); }
    
    try {
      let promoPage = null;
      do {
        const p = await gmail.users.messages.list({ userId: 'me', maxResults: 500, pageToken: promoPage, q: 'category:promotions' });
        if (!p.data.messages?.length) break;
        results.promotions.push(...p.data.messages);
        promoPage = p.data.nextPageToken;
      } while (promoPage);
    } catch (e) {}
    
    try {
      let socialPage = null;
      do {
        const s = await gmail.users.messages.list({ userId: 'me', maxResults: 500, pageToken: socialPage, q: 'category:social' });
        if (!s.data.messages?.length) break;
        results.social.push(...s.data.messages);
        socialPage = s.data.nextPageToken;
      } while (socialPage);
    } catch (e) {}
    
    try {
      let spamPage = null;
      do {
        const sp = await gmail.users.messages.list({ userId: 'me', maxResults: 500, pageToken: spamPage, q: 'category:spam' });
        if (!sp.data.messages?.length) break;
        results.spam.push(...sp.data.messages);
        spamPage = sp.data.nextPageToken;
      } while (spamPage);
    } catch (e) {}
    
    // === GOOGLE PHOTOS (unlimited) ===
    try {
      const photos = google.photoslibrary({ version: 'v1', auth: oauth2Client });
      let photoPage = null;
      let photoCount = 0;
      do {
        const p = await photos.mediaItems.list({ pageSize: 100, pageToken: photoPage });
        const items = p.data.mediaItems || [];
        if (!items.length) break;
        results.photos.push(...items);
        photoCount += items.length;
        photoPage = p.data.nextPageToken;
        console.log('Scanned', photoCount, 'photos...');
      } while (photoPage);
    } catch (e) { console.log('Photos error:', e.message); }
    
    console.log('SCAN COMPLETE - Files:', results.files.length, 'Emails:', results.emails.length, 'Photos:', results.photos.length);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE
app.post('/api/delete', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  const { fileIds } = req.body;
  if (!fileIds?.length) return res.status(400).json({ error: 'No files' });
  
  try {
    const oauth2Client = createOAuth2Client();
    oauth2Client.setCredentials(JSON.parse(decrypt(req.session.tokens)));
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    for (const id of fileIds) await drive.files.delete({ fileId: id });
    res.json({ deleted: fileIds.length });
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
    for (const id of fileIds) await drive.files.update({ fileId: id, requestBody: { trashed: true } });
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

// LOGOUT
app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('DriveClean running on port ' + PORT);
});

module.exports = app;