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

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = Number(process.env.PORT || 3000);
const SCAN_LIMIT = Number(process.env.SCAN_LIMIT || 50000);
const DRIVE_PAGE_SIZE = 1000;
const FOLDER_MIME = 'application/vnd.google-apps.folder';
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

const sessions = new Map();
const scanJobs = new Map();
const latestScans = new Map();
const authStates = new Map();
const SCANS_FILE = path.join(__dirname, 'scans.json');
const DRIVE_SCAN_KEYS = [
  'capturedAt',
  'scope',
  'total',
  'totalSize',
  'files',
  'duplicates',
  'duplicateGroups',
  'large',
  'old',
  'empty',
  'emptyFolders',
  'hidden',
  'orphan',
  'shared',
  'ownedByOthers',
  'public',
  'temporary',
  'trash',
  'extensions',
  'mimeTypes',
  'folderSizes'
];

const log = (msg, type = 'info') => {
  const timestamp = new Date().toISOString();
  const prefix = type === 'error' ? 'ERROR' : type === 'warn' ? 'WARN' : 'INFO';
  console.log(`[${timestamp}] ${prefix}: ${msg}`);
};

if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.REDIRECT_URI) {
  log('Missing Google OAuth credentials. Please set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and REDIRECT_URI.', 'error');
}

if (!process.env.ENCRYPTION_KEY) {
  log('ENCRYPTION_KEY not set. Generating temporary key. Sessions will invalidate on restart.', 'warn');
  process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
}

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self' https://www.googleapis.com https://photoslibrary.googleapis.com ws: wss:; frame-ancestors 'none';"
  );
  res.removeHeader('X-Powered-By');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

const validateSession = (req, res, next) => {
  const session = req.headers['x-session'] || req.query.session;
  if (!session || typeof session !== 'string' || session.length > 100) {
    return res.status(400).json({ error: 'Invalid session ID format' });
  }
  if (!sessions.has(session)) {
    return res.status(401).json({ error: 'Session missing' });
  }
  next();
};

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    sessions: sessions.size,
    scans: latestScans.size
  });
});

function loadSessions() {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) {
      return;
    }

    const data = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
    for (const [id, session] of Object.entries(data)) {
      sessions.set(id, session);
    }
    log(`Loaded ${sessions.size} sessions from disk.`);
  } catch (error) {
    log(`Failed to load sessions: ${error.message}`, 'error');
  }
}

function saveSessions() {
  try {
    const serialized = Object.fromEntries(sessions);
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(serialized, null, 2));
  } catch (error) {
    log(`Failed to save sessions: ${error.message}`, 'error');
  }
}

function loadScans() {
  try {
    if (!fs.existsSync(SCANS_FILE)) {
      return;
    }
    const data = JSON.parse(fs.readFileSync(SCANS_FILE, 'utf8'));
    for (const [sessionId, scan] of Object.entries(data)) {
      if (sessions.has(sessionId) && hasPersistableScanData(scan)) {
        latestScans.set(sessionId, scan);
      }
    }
    log(`Loaded ${latestScans.size} scans from disk.`);
  } catch (error) {
    log(`Failed to load scans: ${error.message}`, 'error');
  }
}

function saveScans() {
  try {
    const serialized = Object.fromEntries(latestScans);
    const filtered = {};
    for (const [sessionId, scan] of Object.entries(serialized)) {
      if (sessions.has(sessionId) && hasPersistableScanData(scan)) {
        filtered[sessionId] = scan;
      }
    }
    fs.writeFileSync(SCANS_FILE, JSON.stringify(filtered, null, 2));
  } catch (error) {
    log(`Failed to save scans: ${error.message}`, 'error');
  }
}

function encrypt(text) {
  return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}

function decrypt(ciphertext) {
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch {
    return null;
  }
}

function oauthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URI
  );
}

async function retryRequest(promiseFn, retries = 3, delay = 1000) {
  for (let attempt = 0; attempt < retries; attempt += 1) {
    try {
      return await promiseFn();
    } catch (error) {
      const reason = error?.errors?.[0]?.reason;
      const shouldRetry = error?.code === 403 && ['rateLimitExceeded', 'userRateLimitExceeded'].includes(reason);
      if (!shouldRetry || attempt === retries - 1) {
        throw error;
      }
      log(`Rate limit hit, retrying in ${delay}ms...`, 'warn');
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay *= 2;
    }
  }
}

function getSessionRecord(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) {
    const error = new Error('Session missing');
    error.statusCode = 401;
    throw error;
  }
  return session;
}

async function getAuthClient(sessionId) {
  const session = getSessionRecord(sessionId);
  const oauth = oauthClient();
  const decrypted = decrypt(session.tokens);

  if (!decrypted) {
    const error = new Error('Token decryption failed');
    error.statusCode = 401;
    throw error;
  }

  const tokens = JSON.parse(decrypted);
  oauth.setCredentials(tokens);

  oauth.on('tokens', (newTokens) => {
    const merged = { ...oauth.credentials, ...newTokens };
    session.tokens = encrypt(JSON.stringify(merged));
    session.updatedAt = new Date().toISOString();
    sessions.set(sessionId, session);
    saveSessions();
  });

  return oauth;
}

function cleanupAuthStates() {
  const now = Date.now();
  for (const [state, createdAt] of authStates.entries()) {
    if (now - createdAt > 10 * 60 * 1000) {
      authStates.delete(state);
    }
  }
}

function getDriveListBaseOptions(pageToken = null) {
  return {
    pageSize: DRIVE_PAGE_SIZE,
    pageToken,
    spaces: 'drive',
    supportsAllDrives: true,
    includeItemsFromAllDrives: true
  };
}

function buildWebLink(fileId, mimeType, existingLink) {
  if (existingLink) {
    return existingLink;
  }
  if (mimeType === FOLDER_MIME) {
    return `https://drive.google.com/drive/folders/${fileId}`;
  }
  return `https://drive.google.com/file/d/${fileId}/view`;
}

function normalizeDriveFile(file) {
  const size = Number(file.quotaBytesUsed || file.size || 0);
  const permissions = Array.isArray(file.permissions)
    ? file.permissions.map((permission) => ({
        type: permission.type,
        role: permission.role,
        emailAddress: permission.emailAddress || null,
        domain: permission.domain || null
      }))
    : [];

  return {
    id: file.id,
    name: file.name || 'Untitled',
    mimeType: file.mimeType || 'application/octet-stream',
    size,
    modifiedTime: file.modifiedTime || null,
    md5Checksum: file.md5Checksum || null,
    parents: Array.isArray(file.parents) ? file.parents : [],
    ownedByMe: file.ownedByMe !== false,
    shared: Boolean(file.shared) || permissions.length > 1,
    public: permissions.some((permission) => permission.type === 'anyone' || permission.type === 'domain'),
    permissions,
    webViewLink: buildWebLink(file.id, file.mimeType, file.webViewLink)
  };
}

function isFolder(file) {
  return file.mimeType === FOLDER_MIME;
}

function isGoogleWorkspaceFile(file) {
  return file.mimeType?.startsWith('application/vnd.google-apps.') && !isFolder(file);
}

function isTemporaryFile(file) {
  const name = (file.name || '').toLowerCase();
  const temporaryExtensions = ['.tmp', '.temp', '.part', '.crdownload', '.download', '.dwl', '.dwl2'];
  const temporaryNames = ['thumbs.db', 'desktop.ini', '.ds_store', 'tmp'];

  if (temporaryNames.includes(name)) {
    return true;
  }

  if (name.startsWith('~$') || name.startsWith('.~lock')) {
    return true;
  }

  return temporaryExtensions.some((extension) => name.endsWith(extension));
}

function buildDuplicateKey(file) {
  if (isFolder(file) || file.size <= 0) {
    return null;
  }

  if (file.md5Checksum) {
    return `md5:${file.md5Checksum}`;
  }

  if (isGoogleWorkspaceFile(file)) {
    return `${file.mimeType}:${file.name.toLowerCase()}:${file.size}`;
  }

  return `${file.name.toLowerCase()}:${file.size}:${file.mimeType}`;
}

function buildExtension(name) {
  if (!name || !name.includes('.')) {
    return 'none';
  }
  return name.split('.').pop().toLowerCase();
}

function hasPersistableScanData(scan) {
  if (!scan || typeof scan !== 'object') {
    return false;
  }

  return Boolean(scan.capturedAt || scan.gmailCapturedAt || scan.photosCapturedAt);
}

function parseDriveFolderId(input) {
  if (!input) {
    return null;
  }

  const trimmed = String(input).trim();
  if (!trimmed) {
    return null;
  }

  const folderMatch = trimmed.match(/\/folders\/([a-zA-Z0-9_-]+)/);
  if (folderMatch) {
    return folderMatch[1];
  }

  try {
    const parsed = new URL(trimmed);
    const queryId = parsed.searchParams.get('id');
    if (queryId) {
      return queryId;
    }

    const pathMatch = parsed.pathname.match(/\/folders\/([a-zA-Z0-9_-]+)/);
    if (pathMatch) {
      return pathMatch[1];
    }
  } catch {
    // Not a URL, treat the raw input as a folder ID.
  }

  return trimmed.replace(/^.*folders\//, '').split(/[?&#/]/)[0];
}

async function resolveDriveScanScope(drive, scopeInput) {
  const folderId = parseDriveFolderId(scopeInput);
  if (!folderId) {
    return { mode: 'drive' };
  }

  let response;
  try {
    response = await retryRequest(() =>
      drive.files.get({
        fileId: folderId,
        supportsAllDrives: true,
        fields:
          'id,name,mimeType,modifiedTime,parents,permissions(type,role,emailAddress,domain),webViewLink,ownedByMe,shared'
      })
    );
  } catch (error) {
    const wrapped = new Error('Folder not found or access denied.');
    wrapped.statusCode = error.code || error.statusCode || 404;
    throw wrapped;
  }

  const folder = normalizeDriveFile(response.data);
  if (!isFolder(folder)) {
    const error = new Error('Scan scope must be a Google Drive folder.');
    error.statusCode = 400;
    throw error;
  }

  return { mode: 'folder', folder };
}

function mergeLatestScan(sessionId, patch) {
  const merged = { ...(latestScans.get(sessionId) || {}), ...patch };
  latestScans.set(sessionId, merged);
  saveScans();
  return merged;
}

function invalidateDriveInventory(sessionId) {
  const existing = latestScans.get(sessionId);
  if (!existing) {
    return null;
  }

  const next = { ...existing };
  for (const key of DRIVE_SCAN_KEYS) {
    delete next[key];
  }

  if (hasPersistableScanData(next)) {
    latestScans.set(sessionId, next);
  } else {
    latestScans.delete(sessionId);
  }
  saveScans();
  return next;
}

async function countGmailMessages(gmail, query, onProgress) {
  let total = 0;
  let pageToken = null;

  do {
    const response = await retryRequest(() =>
      gmail.users.messages.list({
        userId: 'me',
        q: query,
        maxResults: 500,
        pageToken: pageToken || undefined
      })
    );

    const messages = response.data.messages || [];
    total += messages.length;
    pageToken = response.data.nextPageToken || null;

    if (typeof onProgress === 'function') {
      await onProgress(total);
    }
  } while (pageToken);

  return total;
}

async function deleteGmailMessages(gmail, query, onProgress) {
  let deletedCount = 0;

  while (true) {
    const response = await retryRequest(() =>
      gmail.users.messages.list({
        userId: 'me',
        q: query,
        maxResults: 500
      })
    );

    const messages = response.data.messages || [];
    if (messages.length === 0) {
      break;
    }

    await retryRequest(() =>
      gmail.users.messages.batchDelete({
        userId: 'me',
        requestBody: { ids: messages.map((message) => message.id) }
      })
    );

    deletedCount += messages.length;
    if (typeof onProgress === 'function') {
      await onProgress(deletedCount);
    }

    if (!response.data.nextPageToken && messages.length < 500) {
      break;
    }
  }

  return deletedCount;
}

function updateJob(jobId, ws, patch) {
  const job = scanJobs.get(jobId);
  if (!job) {
    return null;
  }
  Object.assign(job, patch);
  pushUpdate(jobId, ws, job);
  return job;
}

function pushUpdate(jobId, ws, job) {
  try {
    ws.send(JSON.stringify({ type: 'update', jobId, ...job }));
  } catch {
    // noop: socket might already be closed
  }
}

function finishJob(jobId) {
  scanJobs.delete(jobId);
}

function failJob(jobId, ws, message, statusCode = 500) {
  const job = scanJobs.get(jobId);
  if (!job) {
    return;
  }

  job.stage = 'Error';
  job.error = message;
  job.statusCode = statusCode;
  pushUpdate(jobId, ws, job);
  finishJob(jobId);
  log(`Job ${jobId} failed: ${message}`, 'error');
}

function respondWithError(res, error) {
  const statusCode = error.statusCode || 500;
  res.status(statusCode).json({ error: error.message || 'Unexpected error' });
}

function getLatestScan(sessionId) {
  const scan = latestScans.get(sessionId);
  if (!scan) {
    const error = new Error('No scan data found');
    error.statusCode = 404;
    throw error;
  }
  return scan;
}

function collectCategories(scan, category) {
  const lookup = {
    all: scan.files || [],
    large: scan.large || [],
    duplicates: scan.duplicates || [],
    old: scan.old || [],
    empty: scan.empty || [],
    emptyFolders: scan.emptyFolders || [],
    hidden: scan.hidden || [],
    orphan: scan.orphan || [],
    shared: scan.shared || [],
    ownedByOthers: scan.ownedByOthers || [],
    public: scan.public || [],
    temporary: scan.temporary || [],
    folders: scan.folderSizes || [],
    trash: scan.trash || []
  };
  return lookup[category] || [];
}

app.get('/api/auth/url', (req, res) => {
  cleanupAuthStates();
  const oauth = oauthClient();
  const state = uuidv4();
  authStates.set(state, Date.now());

  const url = oauth.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: true,
    state,
    scope: [
      'https://www.googleapis.com/auth/drive',
      'https://www.googleapis.com/auth/drive.file',
      'https://www.googleapis.com/auth/drive.metadata',
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
    cleanupAuthStates();
    const { code, state } = req.query;

    if (!state || !authStates.has(state)) {
      return res.status(400).send('Invalid or expired OAuth state.');
    }
    authStates.delete(state);

    const oauth = oauthClient();
    const { tokens } = await oauth.getToken(code);
    oauth.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: 'v2', auth: oauth });
    const user = await oauth2.userinfo.get();

    const sessionId = uuidv4();
    sessions.set(sessionId, {
      email: user.data.email,
      name: user.data.name || user.data.email,
      tokens: encrypt(JSON.stringify(tokens)),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
    saveSessions();
    log(`User logged in: ${user.data.email}`);

    res.redirect(`/?session=${sessionId}`);
  } catch (error) {
    log(`OAuth Error: ${error.message}`, 'error');
    res.status(500).send('Auth failed.');
  }
});

app.post('/api/auth/logout', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const session = getSessionRecord(sessionId);
    sessions.delete(sessionId);
    latestScans.delete(sessionId);
    saveSessions();
    saveScans();
    log(`User logged out: ${session.email}`);
    res.json({ ok: true });
  } catch (error) {
    respondWithError(res, error);
  }
});

app.get('/api/session', validateSession, (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const session = getSessionRecord(sessionId);
    res.json({
      email: session.email,
      name: session.name,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt
    });
  } catch (error) {
    respondWithError(res, error);
  }
});

app.get('/api/storage', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const oauth = await getAuthClient(sessionId);
    const drive = google.drive({ version: 'v3', auth: oauth });
    const about = await retryRequest(() => drive.about.get({ fields: 'storageQuota' }));
    res.json(about.data.storageQuota);
  } catch (error) {
    respondWithError(res, error);
  }
});

app.get('/api/scan/latest', validateSession, (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const scan = getLatestScan(sessionId);
    res.json(scan);
  } catch (error) {
    respondWithError(res, error);
  }
});

app.get('/api/export/csv', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const category = String(req.query.type || 'all');
    const scan = getLatestScan(sessionId);
    const files = collectCategories(scan, category);

    let csv = 'ID,Name,Size,Modified Time,MIME Type,Web Link\n';
    for (const file of files) {
      const cells = [
        file.id,
        file.name,
        file.size,
        file.modifiedTime,
        file.mimeType,
        file.webViewLink || ''
      ].map((value) => `"${String(value ?? '').replace(/"/g, '""')}"`);
      csv += `${cells.join(',')}\n`;
    }

    res.header('Content-Type', 'text/csv');
    res.attachment(`${category}_files_${Date.now()}.csv`);
    res.send(csv);
  } catch (error) {
    respondWithError(res, error);
  }
});

async function mutateFiles(sessionId, fileIds, updateRequestBody) {
  const oauth = await getAuthClient(sessionId);
  const drive = google.drive({ version: 'v3', auth: oauth });

  const results = await Promise.all(
    fileIds.map(async (fileId) => {
      try {
        await retryRequest(() =>
          drive.files.update({
            fileId,
            supportsAllDrives: true,
            requestBody: updateRequestBody
          })
        );
        return { id: fileId, ok: true };
      } catch (error) {
        return { id: fileId, ok: false, error: error.message };
      }
    })
  );

  const successIds = results.filter((result) => result.ok).map((result) => result.id);
  const failed = results.filter((result) => !result.ok);

  return {
    results,
    successIds,
    failed,
    successCount: successIds.length,
    failureCount: failed.length
  };
}

app.post('/api/files/delete', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const { fileIds } = req.body;
    if (!Array.isArray(fileIds) || fileIds.length === 0 || fileIds.length > 1000) {
      return res.status(400).json({ error: 'Invalid file IDs' });
    }

    log(`Deleting ${fileIds.length} files for session ${sessionId}`);
    const result = await mutateFiles(sessionId, fileIds, { trashed: true });
    if (result.successCount > 0) {
      invalidateDriveInventory(sessionId);
    }
    res.json({
      message: `Moved ${result.successCount} files to trash.`,
      inventoryInvalidated: result.successCount > 0,
      ...result
    });
  } catch (error) {
    respondWithError(res, error);
  }
});

app.post('/api/files/restore', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const { fileIds } = req.body;
    if (!Array.isArray(fileIds) || fileIds.length === 0 || fileIds.length > 1000) {
      return res.status(400).json({ error: 'Invalid file IDs' });
    }

    const result = await mutateFiles(sessionId, fileIds, { trashed: false });
    if (result.successCount > 0) {
      invalidateDriveInventory(sessionId);
    }
    res.json({
      message: `Restored ${result.successCount} files.`,
      inventoryInvalidated: result.successCount > 0,
      ...result
    });
  } catch (error) {
    respondWithError(res, error);
  }
});

app.post('/api/trash/empty', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const oauth = await getAuthClient(sessionId);
    const drive = google.drive({ version: 'v3', auth: oauth });

    let deletedCount = 0;
    let pageToken = null;

    do {
      const response = await retryRequest(() =>
        drive.files.list({
          ...getDriveListBaseOptions(pageToken),
          q: 'trashed=true',
          fields: 'nextPageToken,files(id)'
        })
      );

      const files = response.data.files || [];
      if (files.length === 0) {
        break;
      }

      const batchResults = await Promise.all(
        files.map(async (file) => {
          try {
            await retryRequest(() =>
              drive.files.delete({
                fileId: file.id,
                supportsAllDrives: true
              })
            );
            return true;
          } catch {
            return false;
          }
        })
      );

      deletedCount += batchResults.filter(Boolean).length;
      pageToken = response.data.nextPageToken;
    } while (pageToken);

    if (latestScans.has(sessionId)) {
      invalidateDriveInventory(sessionId);
    }

    res.json({ message: `Permanently deleted ${deletedCount} items.`, deletedCount });
  } catch (error) {
    respondWithError(res, error);
  }
});

function gmailBeforeDate(daysAgo) {
  const date = new Date();
  date.setDate(date.getDate() - daysAgo);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}/${month}/${day}`;
}

app.post('/api/gmail/clean', validateSession, async (req, res) => {
  try {
    const sessionId = req.headers['x-session'];
    const oauth = await getAuthClient(sessionId);
    const gmail = google.gmail({ version: 'v1', auth: oauth });
    const { category, olderThanDays } = req.body;

    if (!['promotions', 'social'].includes(category)) {
      return res.status(400).json({ error: 'Invalid category' });
    }

    const before = gmailBeforeDate(Number(olderThanDays) || 365);
    const query = `category:${category} before:${before}`;
    const deletedCount = await deleteGmailMessages(gmail, query);
    if (deletedCount === 0) {
      return res.json({ message: 'No emails found.', deletedCount: 0 });
    }

    const gmailState = latestScans.get(sessionId)?.gmail || {};
    mergeLatestScan(sessionId, {
      gmail: {
        ...gmailState,
        [category]: Math.max(0, Number(gmailState[category] || 0) - deletedCount)
      },
      gmailCapturedAt: new Date().toISOString(),
      gmailOlderThanDays: Number(olderThanDays) || 365
    });

    res.json({ message: `Deleted ${deletedCount} emails.`, deletedCount });
  } catch (error) {
    respondWithError(res, error);
  }
});

wss.on('connection', (ws) => {
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);

      if (data.type === 'startScan') {
        const jobId = uuidv4();
        scanJobs.set(jobId, {
          session: data.session,
          scope: data.scope || null,
          cancel: false,
          progress: 0,
          stage: 'Queued'
        });
        ws.send(JSON.stringify({ type: 'jobStarted', jobId }));
        await runDriveScan(jobId, ws);
      }

      if (data.type === 'startGmailScan') {
        const jobId = uuidv4();
        scanJobs.set(jobId, {
          session: data.session,
          olderThanDays: Number(data.olderThanDays) || 365,
          cancel: false,
          progress: 0,
          stage: 'Queued'
        });
        ws.send(JSON.stringify({ type: 'jobStarted', jobId }));
        await runGmailScan(jobId, ws);
      }

      if (data.type === 'startPhotosScan') {
        const jobId = uuidv4();
        scanJobs.set(jobId, { session: data.session, cancel: false, progress: 0, stage: 'Queued' });
        ws.send(JSON.stringify({ type: 'jobStarted', jobId }));
        await runPhotosScan(jobId, ws);
      }

      if (data.type === 'cancelScan') {
        const job = scanJobs.get(data.jobId);
        if (job) {
          job.cancel = true;
          pushUpdate(data.jobId, ws, {
            ...job,
            stage: 'Canceled',
            progress: job.progress || 0
          });
          finishJob(data.jobId);
        }
      }
    } catch (error) {
      log(`WS Error: ${error.message}`, 'error');
    }
  });
});

async function runPhotosScan(jobId, ws) {
  const job = scanJobs.get(jobId);
  if (!job) {
    return;
  }

  try {
    const oauth = await getAuthClient(job.session);
    const accessToken = (await oauth.getAccessToken())?.token || oauth.credentials.access_token;
    const headers = { Authorization: `Bearer ${accessToken}` };
    let totalItems = 0;
    let videoCount = 0;
    let pageToken = null;

    updateJob(jobId, ws, { stage: 'Scanning Photos', progress: 5 });

    do {
      const currentJob = scanJobs.get(jobId);
      if (!currentJob || currentJob.cancel) {
        return;
      }

      const url = `https://photoslibrary.googleapis.com/v1/mediaItems?pageSize=100${pageToken ? `&pageToken=${pageToken}` : ''}`;
      const response = await fetch(url, { headers });
      const data = await response.json();
      if (!response.ok) {
        const error = new Error(data?.error?.message || 'Photos scan failed.');
        error.statusCode = response.status;
        throw error;
      }

      const items = data.mediaItems || [];
      totalItems += items.length;
      videoCount += items.filter((item) => item.mimeType?.includes('video')).length;

      updateJob(jobId, ws, {
        stage: `Scanned ${totalItems.toLocaleString()} photos and videos`,
        progress: Math.min(90, 10 + totalItems / 20)
      });

      pageToken = data.nextPageToken;
    } while (pageToken);

    updateJob(jobId, ws, {
      stage: 'Complete',
      progress: 100,
      data: mergeLatestScan(job.session, {
        photos: { total: totalItems, videos: videoCount },
        photosCapturedAt: new Date().toISOString()
      })
    });
    finishJob(jobId);
    log(`Photos Scan Complete for job ${jobId}`);
  } catch (error) {
    failJob(jobId, ws, error.message, error.statusCode);
  }
}

async function runGmailScan(jobId, ws) {
  const job = scanJobs.get(jobId);
  if (!job) {
    return;
  }

  try {
    const oauth = await getAuthClient(job.session);
    const gmail = google.gmail({ version: 'v1', auth: oauth });
    const olderThanDays = Number(job.olderThanDays) || 365;
    const before = gmailBeforeDate(olderThanDays);

    updateJob(jobId, ws, { stage: 'Scanning Promotions', progress: 10 });
    const promotionsCount = await countGmailMessages(
      gmail,
      `category:promotions before:${before}`,
      async (count) => {
        updateJob(jobId, ws, {
          stage: `Scanning Promotions (${count.toLocaleString()})`,
          progress: Math.min(45, 10 + count / 200)
        });
      }
    );

    updateJob(jobId, ws, { stage: 'Scanning Social', progress: 60 });
    const socialCount = await countGmailMessages(
      gmail,
      `category:social before:${before}`,
      async (count) => {
        updateJob(jobId, ws, {
          stage: `Scanning Social (${count.toLocaleString()})`,
          progress: Math.min(92, 60 + count / 200)
        });
      }
    );

    const scanData = mergeLatestScan(job.session, {
      gmail: {
        promotions: promotionsCount,
        social: socialCount
      },
      gmailCapturedAt: new Date().toISOString(),
      gmailOlderThanDays: olderThanDays
    });

    updateJob(jobId, ws, {
      stage: 'Complete',
      progress: 100,
      data: scanData
    });
    finishJob(jobId);
    log(`Gmail Scan Complete for job ${jobId}`);
  } catch (error) {
    failJob(jobId, ws, error.message, error.statusCode);
  }
}

async function runDriveScan(jobId, ws) {
  const job = scanJobs.get(jobId);
  if (!job) {
    return;
  }

  try {
    log(`Starting Drive Scan for job ${jobId}`);
    const oauth = await getAuthClient(job.session);
    const drive = google.drive({ version: 'v3', auth: oauth });
    const scope = await resolveDriveScanScope(drive, job.scope);
    const driveFields =
      'nextPageToken,files(id,name,mimeType,size,quotaBytesUsed,modifiedTime,md5Checksum,parents,permissions(type,role,emailAddress,domain),webViewLink,ownedByMe,shared)';
    const trashFields =
      'nextPageToken,files(id,name,mimeType,size,quotaBytesUsed,modifiedTime,parents,permissions(type,role,emailAddress,domain),webViewLink,ownedByMe,shared)';

    const activeFiles = [];
    const trashFiles = [];
    const duplicateBuckets = new Map();
    const folders = new Map();
    const childCountMap = new Map();
    const extMap = new Map();
    const mimeMap = new Map();
    const categorySets = {
      large: [],
      old: [],
      empty: [],
      emptyFolders: [],
      hidden: [],
      orphan: [],
      shared: [],
      ownedByOthers: [],
      public: [],
      temporary: []
    };

    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);

    let totalFiles = 0;
    let totalSize = 0;

    const processFile = (file) => {
      activeFiles.push(file);
      totalFiles += 1;
      totalSize += file.size;

      const extension = buildExtension(file.name);
      const mimeCategory = (file.mimeType || 'other').split('/')[0];
      extMap.set(extension, (extMap.get(extension) || 0) + 1);
      mimeMap.set(mimeCategory, (mimeMap.get(mimeCategory) || 0) + 1);

      const hasParents = file.parents.length > 0;
      if (!hasParents) {
        categorySets.orphan.push(file);
      } else {
        for (const parentId of file.parents) {
          childCountMap.set(parentId, (childCountMap.get(parentId) || 0) + 1);
        }
      }

      if (file.name.startsWith('.')) {
        categorySets.hidden.push(file);
      }

      if (file.size >= 100 * 1024 * 1024) {
        categorySets.large.push(file);
      }

      if (!isFolder(file) && file.size === 0) {
        categorySets.empty.push(file);
      }

      if (file.modifiedTime && new Date(file.modifiedTime) < oneYearAgo) {
        categorySets.old.push(file);
      }

      if (file.shared) {
        categorySets.shared.push(file);
      }

      if (!file.ownedByMe) {
        categorySets.ownedByOthers.push(file);
      }

      if (file.public) {
        categorySets.public.push(file);
      }

      if (isTemporaryFile(file)) {
        categorySets.temporary.push(file);
      }

      if (isFolder(file)) {
        folders.set(file.id, { ...file, totalSize: 0, childCount: 0 });
      } else {
        const duplicateKey = buildDuplicateKey(file);
        if (duplicateKey) {
          const bucket = duplicateBuckets.get(duplicateKey) || [];
          bucket.push(file);
          duplicateBuckets.set(duplicateKey, bucket);
        }
      }
    };

    const updateActiveProgress = () =>
      updateJob(jobId, ws, {
        stage:
          scope.mode === 'folder'
            ? `Scanned ${totalFiles.toLocaleString()} items in ${scope.folder.name}`
            : `Scanned ${totalFiles.toLocaleString()} files`,
        progress: Math.min(70, 5 + (activeFiles.length / SCAN_LIMIT) * 65)
      });

    if (scope.mode === 'folder') {
      folders.set(scope.folder.id, { ...scope.folder, totalSize: 0, childCount: 0 });
      updateJob(jobId, ws, { stage: `Scanning folder ${scope.folder.name}`, progress: 2 });

      const folderQueue = [scope.folder.id];
      const visitedFolderIds = new Set();

      while (folderQueue.length > 0 && activeFiles.length < SCAN_LIMIT) {
        const currentJob = scanJobs.get(jobId);
        if (!currentJob || currentJob.cancel) {
          return;
        }

        const currentFolderId = folderQueue.shift();
        if (!currentFolderId || visitedFolderIds.has(currentFolderId)) {
          continue;
        }
        visitedFolderIds.add(currentFolderId);

        let pageToken = null;
        do {
          const runningJob = scanJobs.get(jobId);
          if (!runningJob || runningJob.cancel) {
            return;
          }

          const response = await retryRequest(() =>
            drive.files.list({
              ...getDriveListBaseOptions(pageToken),
              q: `'${currentFolderId}' in parents and trashed=false`,
              fields: driveFields
            })
          );

          const files = response.data.files || [];
          for (const rawFile of files) {
            if (activeFiles.length >= SCAN_LIMIT) {
              break;
            }

            const file = normalizeDriveFile(rawFile);
            processFile(file);

            if (isFolder(file) && !visitedFolderIds.has(file.id)) {
              folderQueue.push(file.id);
            }
          }

          pageToken = response.data.nextPageToken;
          updateActiveProgress();
        } while (pageToken && activeFiles.length < SCAN_LIMIT);
      }
    } else {
      let pageToken = null;
      updateJob(jobId, ws, { stage: 'Scanning Drive', progress: 2 });

      do {
        const currentJob = scanJobs.get(jobId);
        if (!currentJob || currentJob.cancel) {
          return;
        }

        const response = await retryRequest(() =>
          drive.files.list({
            ...getDriveListBaseOptions(pageToken),
            q: 'trashed=false',
            fields: driveFields
          })
        );

        const files = response.data.files || [];
        if (files.length === 0) {
          break;
        }

        for (const rawFile of files) {
          if (activeFiles.length >= SCAN_LIMIT) {
            break;
          }

          processFile(normalizeDriveFile(rawFile));
        }

        pageToken = response.data.nextPageToken;
        updateActiveProgress();
      } while (pageToken && activeFiles.length < SCAN_LIMIT);
    }

    updateJob(jobId, ws, { stage: 'Computing folder sizes', progress: 72 });

    const addSizeToAncestors = (parentIds, size) => {
      const stack = [...parentIds];
      const visited = new Set();

      while (stack.length > 0) {
        const folderId = stack.pop();
        if (!folderId || visited.has(folderId)) {
          continue;
        }
        visited.add(folderId);

        const folder = folders.get(folderId);
        if (!folder) {
          continue;
        }

        folder.totalSize += size;
        for (const parentId of folder.parents || []) {
          stack.push(parentId);
        }
      }
    };

    for (const file of activeFiles) {
      if (!isFolder(file) && file.size > 0 && file.parents.length > 0) {
        addSizeToAncestors(file.parents, file.size);
      }
    }

    for (const folder of folders.values()) {
      folder.childCount = childCountMap.get(folder.id) || 0;
      folder.size = folder.totalSize;
      if (folder.childCount === 0) {
        categorySets.emptyFolders.push(folder);
      }
    }

    updateJob(jobId, ws, { stage: 'Finding duplicates', progress: 82 });

    const duplicateFiles = [];
    const duplicateGroups = [];

    for (const [groupKey, files] of duplicateBuckets.entries()) {
      if (files.length < 2) {
        continue;
      }

      const sorted = [...files].sort((a, b) => {
        const sizeDelta = Number(b.size || 0) - Number(a.size || 0);
        if (sizeDelta !== 0) {
          return sizeDelta;
        }
        return new Date(b.modifiedTime || 0) - new Date(a.modifiedTime || 0);
      });

      const totalGroupSize = sorted.reduce((sum, file) => sum + Number(file.size || 0), 0);
      const wastedBytes = totalGroupSize - Number(sorted[0].size || 0);
      const detection = groupKey.startsWith('md5:') ? 'content' : 'name-size';

      duplicateGroups.push({
        id: groupKey,
        name: sorted[0].name,
        fileCount: sorted.length,
        wastedBytes,
        totalSize: totalGroupSize,
        detection
      });

      sorted.forEach((file, index) => {
        duplicateFiles.push({
          ...file,
          duplicateGroupId: groupKey,
          duplicateCount: sorted.length,
          duplicateRank: index,
          duplicateDetection: detection,
          wastedBytes
        });
      });
    }

    duplicateGroups.sort((a, b) => b.wastedBytes - a.wastedBytes);
    duplicateFiles.sort((a, b) => b.wastedBytes - a.wastedBytes || Number(b.size || 0) - Number(a.size || 0));

    updateJob(jobId, ws, {
      stage: scope.mode === 'folder' ? 'Scanning account trash' : 'Scanning Trash',
      progress: 90
    });

    let trashPageToken = null;
    do {
      const currentJob = scanJobs.get(jobId);
      if (!currentJob || currentJob.cancel) {
        return;
      }

      const response = await retryRequest(() =>
        drive.files.list({
          ...getDriveListBaseOptions(trashPageToken),
          q: 'trashed=true',
          fields: trashFields
        })
      );

      const files = response.data.files || [];
      for (const rawFile of files) {
        trashFiles.push({
          ...normalizeDriveFile(rawFile),
          trashed: true
        });
      }

      trashPageToken = response.data.nextPageToken;
      updateJob(jobId, ws, {
        stage: `Indexed ${trashFiles.length.toLocaleString()} trashed files`,
        progress: Math.min(98, 92 + trashFiles.length / 250)
      });
    } while (trashPageToken);

    const folderSizes = [...folders.values()]
      .filter((folder) => folder.totalSize > 0 || folder.childCount > 0)
      .sort((a, b) => b.totalSize - a.totalSize);

    categorySets.large.sort((a, b) => Number(b.size || 0) - Number(a.size || 0));
    categorySets.old.sort((a, b) => new Date(a.modifiedTime || 0) - new Date(b.modifiedTime || 0));
    categorySets.emptyFolders.sort((a, b) => a.name.localeCompare(b.name));
    categorySets.shared.sort((a, b) => Number(b.size || 0) - Number(a.size || 0));
    categorySets.ownedByOthers.sort((a, b) => Number(b.size || 0) - Number(a.size || 0));
    categorySets.public.sort((a, b) => Number(b.size || 0) - Number(a.size || 0));
    categorySets.temporary.sort((a, b) => Number(b.size || 0) - Number(a.size || 0));

    const scanData = {
      capturedAt: new Date().toISOString(),
      scope:
        scope.mode === 'folder'
          ? {
              mode: 'folder',
              folderId: scope.folder.id,
              folderName: scope.folder.name,
              webViewLink: scope.folder.webViewLink,
              trashScope: 'global'
            }
          : { mode: 'drive' },
      total: totalFiles,
      totalSize,
      files: activeFiles,
      duplicates: duplicateFiles,
      duplicateGroups,
      large: categorySets.large,
      old: categorySets.old,
      empty: categorySets.empty,
      emptyFolders: categorySets.emptyFolders,
      hidden: categorySets.hidden,
      orphan: categorySets.orphan,
      shared: categorySets.shared,
      ownedByOthers: categorySets.ownedByOthers,
      public: categorySets.public,
      temporary: categorySets.temporary,
      trash: trashFiles,
      extensions: [...extMap.entries()].sort((a, b) => b[1] - a[1]),
      mimeTypes: [...mimeMap.entries()].sort((a, b) => b[1] - a[1]),
      folderSizes
    };

    const persistedScan = mergeLatestScan(job.session, scanData);

    const summary = {
      capturedAt: persistedScan.capturedAt,
      scope: persistedScan.scope,
      total: persistedScan.total,
      totalSize: persistedScan.totalSize,
      large: persistedScan.large?.length || 0,
      old: persistedScan.old?.length || 0,
      empty: persistedScan.empty?.length || 0,
      duplicates: persistedScan.duplicates?.length || 0,
      hidden: persistedScan.hidden?.length || 0,
      trash: persistedScan.trash?.length || 0,
      extensions: persistedScan.extensions,
      mimeTypes: persistedScan.mimeTypes,
      folderSizes: persistedScan.folderSizes,
      __triggerFetch: true
    };
    updateJob(jobId, ws, {
      stage: 'Complete',
      progress: 100,
      data: summary
    });
    finishJob(jobId);
    log(
      `Drive Scan Complete for job ${jobId}: ${totalFiles} items${
        scope.mode === 'folder' ? ` in folder ${scope.folder.id}` : ''
      }`
    );
  } catch (error) {
    failJob(jobId, ws, error.message, error.statusCode);
  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

loadSessions();
loadScans();
saveScans();
setInterval(saveSessions, 5 * 60 * 1000);
setInterval(saveScans, 5 * 60 * 1000);
setInterval(cleanupAuthStates, 5 * 60 * 1000);

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

function shutdown(signal) {
  log(`Received ${signal}. Saving sessions and shutting down...`);
  saveSessions();
  saveScans();
  server.close(() => {
    log('HTTP server closed.');
    process.exit(0);
  });

  setTimeout(() => {
    log('Forcing shutdown...');
    process.exit(1);
  }, 5000);
}

server.listen(PORT, () => {
  log(`DriveClean running on http://localhost:${PORT}`);
});
