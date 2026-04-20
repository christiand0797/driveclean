require('dotenv').config();

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { google } = require('googleapis');
const path = require('path');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');

const log = (msg, type = 'info') => {
  const timestamp = new Date().toISOString();
  const prefix = type === 'error' ? 'ERROR' : type === 'warn' ? 'WARN' : 'INFO';
  console.log(`[${timestamp}] ${prefix}: ${msg}`);
};

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  log("Missing Google OAuth credentials. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.", 'error');
}
if (!process.env.ENCRYPTION_KEY) {
  log("ENCRYPTION_KEY not set. Generating temporary key. Sessions will invalidate on restart.", 'warn');
  process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const validateSession = (req, res, next) => {
  const session = req.headers['x-session'] || req.query.session;
  if (!session || typeof session !== 'string' || session.length > 100) {
    return res.status(400).json({ error: "Invalid session ID format" });
  }
  next();
};

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.removeHeader('X-Powered-By');
  next();
});

const sessions = new Map();
const scanJobs = new Map();

function loadSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const data = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
      for (const [id, session] of Object.entries(data)) {
        sessions.set(id, session);
      }
      log(`Loaded ${sessions.size} sessions from disk.`);
    }
  } catch (e) {
    log(`Failed to load sessions: ${e.message}`, 'error');
  }
}

function saveSessions() {
  try {
    const obj = Object.fromEntries(sessions);
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(obj));
  } catch (e) {
    log(`Failed to save sessions: ${e.message}`, 'error');
  }
}

loadSessions();
setInterval(saveSessions, 300000);

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

function shutdown(signal) {
  log(`Received ${signal}. Saving sessions and shutting down...`);
  saveSessions();
  server.close(() => {
    log('HTTP server closed.');
    process.exit(0);
  });
  setTimeout(() => {
    log('Forcing shutdown...');
    process.exit(1);
  }, 5000);
}

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

function encrypt(text) {
  return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}
function decrypt(ciphertext) {
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (e) {
    return null;
  }
}

async function retryRequest(promiseFn, retries = 3, delay = 1000) {
  for (let i = 0; i < retries; i++) {
    try {
      return await promiseFn();
    } catch (e) {
      if (e.code === 403 && e.errors?.[0]?.reason === 'rateLimitExceeded' && i < retries - 1) {
        log(`Rate limit hit, retrying in ${delay}ms...`, 'warn');
        await new Promise(r => setTimeout(r, delay));
        delay *= 2;
      } else {
        throw e;
      }
    }
  }
}

function oauthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URI
  );
}

async function getAuthClient(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) throw new Error("Session missing");

  const oauth = oauthClient();
  const decrypted = decrypt(session.tokens);
  if (!decrypted) throw new Error("Token decryption failed");
  
  const tokens = JSON.parse(decrypted);
  oauth.setCredentials(tokens);

  oauth.on('tokens', (newTokens) => {
    const merged = { ...tokens, ...newTokens };
    session.tokens = encrypt(JSON.stringify(merged));
    sessions.set(sessionId, session);
    saveSessions();
  });

  return oauth;
}

app.get('/api/auth/url', (req, res) => {
  const oauth = oauthClient();
  const url = oauth.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/drive',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/photoslibrary.readonly',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ]
  });
  res.json({ url });
});

app.get('/api/auth/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const oauth = oauthClient();
    const { tokens } = await oauth.getToken(code);
    
    oauth.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth });
    const user = await oauth2.userinfo.get();

    const sessionId = uuidv4();
    sessions.set(sessionId, {
      email: user.data.email,
      name: user.data.name,
      tokens: encrypt(JSON.stringify(tokens))
    });
    saveSessions();
    log(`User logged in: ${user.data.email}`);

    res.redirect(`/?session=${sessionId}`);
  } catch (error) {
    log(`OAuth Error: ${error.message}`, 'error');
    res.status(500).send("Auth failed.");
  }
});

app.get('/api/storage', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const oauth = await getAuthClient(sessionId);
    
    const drive = google.drive({ version: 'v3', auth: oauth });
    const about = await retryRequest(() => drive.about.get({ fields: 'storageQuota' }));
    res.json(about.data.storageQuota);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/export/csv', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const { type } = req.query;
    if (!['large', 'old', 'empty'].includes(type)) return res.status(400).send("Invalid export type");

    const job = Array.from(scanJobs.values()).find(j => j.session === sessionId && j.data);
    if (!job || !job.data) return res.status(404).send("No scan data found");

    const files = job.data[type] || [];
    
    let csv = 'ID,Name,Size,Modified Time,MIME Type\n';
    files.forEach(f => {
      const name = f.name.replace(/"/g, '""');
      csv += `"${f.id}","${name}","${f.size}","${f.modifiedTime}","${f.mimeType}"\n`;
    });

    res.header('Content-Type', 'text/csv');
    res.attachment(`${type}_files_${Date.now()}.csv`);
    res.send(csv);
  } catch (e) {
    res.status(500).send(e.message);
  }
});

app.post('/api/files/delete', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const oauth = await getAuthClient(sessionId);
    const drive = google.drive({ version: 'v3', auth: oauth });
    
    const { fileIds } = req.body;
    if (!fileIds || !Array.isArray(fileIds) || fileIds.length > 1000) return res.status(400).json({ error: "Invalid file IDs" });

    log(`Deleting ${fileIds.length} files for session ${sessionId}`);
    
    const results = await Promise.all(
      fileIds.map(id => 
        retryRequest(() => drive.files.update({ fileId: id, requestBody: { trashed: true } }))
          .catch(e => ({ id, error: e.message }))
      )
    );
    
    const success = results.filter(r => !r.error).length;
    res.json({ message: `Moved ${success} files to trash.` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/trash/empty', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const oauth = await getAuthClient(sessionId);
    const drive = google.drive({ version: 'v3', auth: oauth });
    
    log(`Emptying trash for session ${sessionId}`);
    
    let deletedCount = 0;
    let pageToken = null;
    
    do {
      const r = await retryRequest(() => drive.files.list({
        pageSize: 100,
        fields: 'nextPageToken,files(id)',
        q: "trashed=true",
        pageToken
      }));
      
      const files = r.data.files || [];
      if (files.length === 0) break;
      
      await Promise.all(files.map(f => 
        retryRequest(() => drive.files.delete({ fileId: f.id }))
          .catch(() => {})
      ));
      
      deletedCount += files.length;
      pageToken = r.data.nextPageToken;
    } while (pageToken);
    
    res.json({ message: `Permanently deleted ${deletedCount} items.` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/gmail/clean', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const oauth = await getAuthClient(sessionId);
    const gmail = google.gmail({ version: 'v1', auth: oauth });
    
    const { category, olderThanDays } = req.body;
    if (!['promotions', 'social'].includes(category)) return res.status(400).json({ error: "Invalid category" });

    const date = new Date();
    date.setDate(date.getDate() - (olderThanDays || 365));
    const timestamp = Math.floor(date.getTime() / 1000);
    
    const query = `category:${category} before:${timestamp}`;
    const listRes = await retryRequest(() => gmail.users.messages.list({ userId: 'me', q: query, maxResults: 500 }));

    const messages = listRes.data.messages || [];
    if (messages.length === 0) return res.json({ message: "No emails found." });

    log(`Deleting ${messages.length} ${category} emails for session ${sessionId}`);
    await retryRequest(() => gmail.users.messages.batchDelete({ userId: 'me', requestBody: { ids: messages.map(m => m.id) } }));
    res.json({ message: `Deleted ${messages.length} emails.` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

wss.on('connection', (ws) => {
  ws.on('message', async (msg) => {
    try {
      const data = JSON.parse(msg);

      if (data.type === "startScan") {
        const jobId = uuidv4();
        scanJobs.set(jobId, { session: data.session, cancel: false });
        ws.send(JSON.stringify({ type: "jobStarted", jobId }));
        runDriveScan(jobId, ws);
      }
      
      if (data.type === "startGmailScan") {
        const jobId = uuidv4();
        scanJobs.set(jobId, { session: data.session, cancel: false });
        ws.send(JSON.stringify({ type: "jobStarted", jobId }));
        runGmailScan(jobId, ws);
      }

      if (data.type === "startPhotosScan") {
        const jobId = uuidv4();
        scanJobs.set(jobId, { session: data.session, cancel: false });
        ws.send(JSON.stringify({ type: "jobStarted", jobId }));
        runPhotosScan(jobId, ws);
      }

      if (data.type === "cancelScan") {
        const job = scanJobs.get(data.jobId);
        if (job) job.cancel = true;
      }
    } catch (e) {
      log(`WS Error: ${e.message}`, 'error');
    }
  });
});

async function runPhotosScan(jobId, ws) {
  const job = scanJobs.get(jobId);
  try {
    log(`Starting Photos Scan for job ${jobId}`);
    const oauth = await getAuthClient(job.session);
    const headers = { 'Authorization': `Bearer ${oauth.credentials.access_token}` };
    
    let totalItems = 0;
    let largeItems = [];
    let pageToken = null;

    job.stage = "Scanning Photos";
    pushUpdate(jobId, ws, job);

    do {
      if (job.cancel) return;
      
      const url = `https://photoslibrary.googleapis.com/v1/mediaItems?pageSize=100${pageToken ? '&pageToken='+pageToken : ''}`;
      const res = await fetch(url, { headers });
      const data = await res.json();

      if (data.mediaItems) {
        totalItems += data.mediaItems.length;
        data.mediaItems.forEach(item => {
          if (item.mimeType && item.mimeType.includes('video')) {
            largeItems.push({ name: item.filename, id: item.id, type: 'video' });
          }
        });
      }

      job.progress = Math.min(80, totalItems / 100);
      job.stage = `Found ${totalItems} items`;
      pushUpdate(jobId, ws, job);
      
      pageToken = data.nextPageToken;
    } while (pageToken);

    job.progress = 100;
    job.stage = "Complete";
    job.data = { photos: { total: totalItems, videos: largeItems.length } };
    pushUpdate(jobId, ws, job);
    log(`Photos Scan Complete for job ${jobId}`);

  } catch (e) {
    errorOut(jobId, ws, e.message);
  }
}

async function runGmailScan(jobId, ws) {
  const job = scanJobs.get(jobId);
  try {
    log(`Starting Gmail Scan for job ${jobId}`);
    const oauth = await getAuthClient(job.session);
    const gmail = google.gmail({ version: 'v1', auth: oauth });

    job.stage = "Scanning Promotions";
    pushUpdate(jobId, ws, job);

    const date = new Date();
    date.setFullYear(date.getFullYear() - 1);
    const timestamp = Math.floor(date.getTime() / 1000);
    
    const promos = await retryRequest(() => gmail.users.messages.list({ userId: 'me', q: `category:promotions before:${timestamp}`, maxResults: 5000 }));
    const promoCount = promos.data.messages?.length || 0;

    job.stage = "Scanning Social";
    job.progress = 50;
    pushUpdate(jobId, ws, job);

    const social = await retryRequest(() => gmail.users.messages.list({ userId: 'me', q: `category:social before:${timestamp}`, maxResults: 5000 }));
    const socialCount = social.data.messages?.length || 0;

    job.progress = 100;
    job.stage = "Complete";
    job.data = { gmail: { promotions: promoCount, social: socialCount } };
    pushUpdate(jobId, ws, job);
    log(`Gmail Scan Complete for job ${jobId}`);

  } catch (e) {
    errorOut(jobId, ws, e.message);
  }
}

async function runDriveScan(jobId, ws) {
  const job = scanJobs.get(jobId);
  try {
    log(`Starting Drive Scan for job ${jobId}`);
    const oauth = await getAuthClient(job.session);
    const drive = google.drive({ version: 'v3', auth: oauth });

    let totalFiles = 0;
    let totalSize = 0;
    let pageToken = null;
    
    const nameMap = new Map();
    const extMap = new Map();
    const largeFiles = [];
    const oldFiles = [];
    const emptyFiles = [];
    const trashFiles = [];
    const sharedFiles = [];
    const orphanFiles = [];
    const mimeMap = new Map();
    
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);

    const folderSizeMap = new Map();

    job.stage = "Scanning Drive";
    pushUpdate(jobId, ws, job);

    const pageSize = 100;
    let nextPageTokens = [null];

    do {
      if (job.cancel) return;

      const futures = nextPageTokens.slice(0, 5).map(token => 
        retryRequest(() => drive.files.list({
          pageSize: pageSize,
          fields: 'nextPageToken,files(id,name,mimeType,size,modifiedTime,owners,permissions,parents)',
          q: "trashed=false",
          pageToken: token
        }))
      );

      const results = await Promise.all(futures);
      
      for (const r of results) {
        if (r?.data?.files) {
          r.data.files.forEach(f => {
            const size = Number(f.size || 0);
            totalFiles++;
            totalSize += size;

            const count = nameMap.get(f.name) || 0;
            nameMap.set(f.name, count + 1);

            if (size > 100 * 1024 * 1024) largeFiles.push(f);
            if (size === 0) emptyFiles.push(f); 

            if (f.modifiedTime) {
              if (new Date(f.modifiedTime) < oneYearAgo) oldFiles.push(f);
            }

            if (f.permissions && f.permissions.length > 1) {
              sharedFiles.push({ id: f.id, name: f.name, size: f.size, mimeType: f.mimeType, modifiedTime: f.modifiedTime, shared: true });
            }

            if (f.owners && f.owners.length === 0) {
              orphanFiles.push({ id: f.id, name: f.name, size: f.size, mimeType: f.mimeType, modifiedTime: f.modifiedTime });
            }

            const ext = f.name.split('.').pop()?.toLowerCase() || 'none';
            extMap.set(ext, (extMap.get(ext) || 0) + 1);
            
            const mimeCat = f.mimeType?.split('/')[0] || 'other';
            mimeMap.set(mimeCat, (mimeMap.get(mimeCat) || 0) + 1);

            if (f.parents && f.parents.length > 0) {
              const parentId = f.parents[0];
              folderSizeMap.set(parentId, (folderSizeMap.get(parentId) || 0) + size);
            }
          });
        }
      }

      nextPageTokens = results
        .filter(r => r.data.nextPageToken)
        .map(r => r.data.nextPageToken);

      if (nextPageTokens.length === 0) break;

      job.progress = Math.min(60, (totalFiles / 20000) * 60); 
      job.stage = `Scanned ${totalFiles.toLocaleString()} files`;
      pushUpdate(jobId, ws, job);
    } while (nextPageTokens.length > 0);

    job.stage = "Analyzing Folders";
    job.progress = 80;
    pushUpdate(jobId, ws, job);

    const folderSizes = Array.from(folderSizeMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    job.stage = "Scanning Trash";
    job.progress = 85;
    pushUpdate(jobId, ws, job);

    let trashPageToken = null;
    do {
      if (job.cancel) return;
      
      const r = await retryRequest(() => drive.files.list({
        pageSize: 1000,
        fields: 'nextPageToken,files(id,name,mimeType,size,modifiedTime)',
        q: "trashed=true",
        pageToken: trashPageToken
      }));
      
      const files = r.data.files || [];
      files.forEach(f => {
        const size = Number(f.size || 0);
        trashFiles.push({ ...f, trashed: true });
      });
      
      job.progress = Math.min(95, 85 + (trashFiles.length / 5000) * 10);
      job.stage = `Found ${trashFiles.length} trashed items`;
      pushUpdate(jobId, ws, job);
      
      trashPageToken = r.data.nextPageToken;
    } while (trashPageToken);

    job.stage = "Processing";
    job.progress = 80;
    pushUpdate(jobId, ws, job);

    const duplicateNames = [];
    for (const [name, count] of nameMap.entries()) {
      if (count > 1) duplicateNames.push({ name, count });
    }

    job.stage = "Computing content hashes";
    job.progress = 90;
    pushUpdate(jobId, ws, job);

    const contentHashes = new Map();
    const potentialDupes = largeFiles.filter(f => f.size > 1024 * 1024).slice(0, 100);
    
    for (const file of potentialDupes) {
      if (job.cancel) return;
      try {
        const metadata = await retryRequest(() => drive.files.get({ fileId: file.id, fields: 'md5Checksum,size,name,mimeType,modifiedTime' }));
        const hash = metadata.data.md5Checksum;
        if (hash) {
          const existing = contentHashes.get(hash) || [];
          existing.push({ id: file.id, name: file.name, size: Number(file.size), mimeType: file.mimeType, modifiedTime: file.modifiedTime, md5: hash });
          contentHashes.set(hash, existing);
        }
      } catch (e) {}
    }

    const contentDupes = [];
    for (const [hash, files] of contentHashes.entries()) {
      if (files.length > 1) {
        files.forEach(f => contentDupes.push(f));
      }
    }

    job.progress = 100;
    job.stage = "Complete";
    
    largeFiles.sort((a, b) => (Number(b.size) - Number(a.size)));
    oldFiles.sort((a, b) => (new Date(a.modifiedTime) - new Date(b.modifiedTime)));

    job.data = {
      total: totalFiles,
      totalSize: totalSize,
      duplicates: duplicateNames.slice(0, 100),
      large: largeFiles.slice(0, 500),
      old: oldFiles.slice(0, 500),
      empty: emptyFiles.slice(0, 500),
      trash: trashFiles.slice(0, 500),
      shared: sharedFiles.slice(0, 500),
      orphan: orphanFiles.slice(0, 500),
      contentDupes: contentDupes.slice(0, 500),
      extensions: Array.from(extMap.entries()).sort((a, b) => b[1] - a[1]).slice(0, 20),
      mimeTypes: Array.from(mimeMap.entries()).sort((a, b) => b[1] - a[1]),
      folderSizes: folderSizes
    };

    pushUpdate(jobId, ws, job);
    log(`Drive Scan Complete for job ${jobId}: ${totalFiles} files`);

  } catch (e) {
    errorOut(jobId, ws, e.message);
  }
}

function errorOut(jobId, ws, msg) {
  const job = scanJobs.get(jobId);
  if (job) {
    job.stage = "Error";
    job.error = msg;
    pushUpdate(jobId, ws, job);
    log(`Job ${jobId} failed: ${msg}`, 'error');
  }
}

function pushUpdate(jobId, ws, job) {
  try {
    ws.send(JSON.stringify({ type: "update", jobId, ...job }));
  } catch (e) {}
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  log(`DriveClean running on http://localhost:${PORT}`);
});