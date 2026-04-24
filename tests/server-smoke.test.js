const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const net = require('node:net');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
    server.on('error', reject);
  });
}

async function waitForServer(url, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return response;
      }
      lastError = new Error(`Unexpected status ${response.status}`);
    } catch (error) {
      lastError = error;
    }

    await delay(250);
  }

  throw lastError || new Error(`Timed out waiting for ${url}`);
}

async function startServer(t) {
  const cwd = path.resolve(__dirname, '..');
  const port = await getFreePort();
  const child = spawn(process.execPath, ['server.js'], {
    cwd,
    env: {
      ...process.env,
      PORT: String(port),
      GOOGLE_CLIENT_ID: 'test-client-id',
      GOOGLE_CLIENT_SECRET: 'test-client-secret',
      REDIRECT_URI: `http://127.0.0.1:${port}/api/auth/callback`,
      ENCRYPTION_KEY: 'test-encryption-key'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let logs = '';
  child.stdout.on('data', (chunk) => {
    logs += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    logs += chunk.toString();
  });

  t.after(async () => {
    if (!child.killed) {
      child.kill();
    }
    await once(child, 'exit').catch(() => {});
  });

  await waitForServer(`http://127.0.0.1:${port}/health`);
  return { port, logsRef: () => logs };
}

test('server boots and serves core assets', async (t) => {
  const { port, logsRef } = await startServer(t);

  const healthResponse = await fetch(`http://127.0.0.1:${port}/health`);
  const health = await healthResponse.json();
  assert.equal(health.status, 'ok');
  assert.equal(typeof health.uptime, 'number');

  const homeResponse = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(homeResponse.status, 200);
  const homeHtml = await homeResponse.text();
  assert.match(homeHtml, /DriveClean/);

  const manifestResponse = await fetch(`http://127.0.0.1:${port}/manifest.json`);
  assert.equal(manifestResponse.status, 200);
  const manifest = await manifestResponse.json();
  assert.equal(manifest.name, 'DriveClean');

  const serviceWorkerResponse = await fetch(`http://127.0.0.1:${port}/sw.js`);
  assert.equal(serviceWorkerResponse.status, 200);
  const serviceWorker = await serviceWorkerResponse.text();
  assert.match(serviceWorker, /driveclean-v4/);

  assert.doesNotMatch(logsRef(), /EADDRINUSE/);
});

test('protected endpoints reject unknown sessions', async (t) => {
  const { port } = await startServer(t);

  const response = await fetch(`http://127.0.0.1:${port}/api/session`, {
    headers: { 'x-session': 'missing-session' }
  });

  assert.equal(response.status, 401);
  const body = await response.json();
  assert.match(body.error, /Session missing/i);
});

test('auth url endpoint returns configured callback host', async (t) => {
  const { port } = await startServer(t);

  const response = await fetch(`http://127.0.0.1:${port}/api/auth/url`);
  assert.equal(response.status, 200);

  const body = await response.json();
  assert.equal(typeof body.url, 'string');
  const url = new URL(body.url);
  assert.match(url.toString(), /oauth/i);
  assert.equal(url.searchParams.get('redirect_uri'), `http://127.0.0.1:${port}/api/auth/callback`);
});
