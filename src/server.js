/**
 * enview ui — local management server.
 *
 * This is the ONE place in enview that handles secret values, and it is deliberately the only
 * one. The CLI, the library API and any dashboard consuming them see key names and status only.
 * Here you are on your own machine, looking at your own files, so revealing a value on request
 * is appropriate — but nothing is persisted, cached, or logged, and the value only crosses the
 * wire when you explicitly ask for that one key.
 *
 * SECURITY MODEL — one user, one machine:
 *   - binds 127.0.0.1 only
 *   - validates Host and Origin on every request, which is what defeats DNS rebinding (a remote
 *     page resolving its own domain to 127.0.0.1 to read your secrets through your browser)
 *   - requires a token, printed once in the terminal, so another local process cannot simply
 *     poll the port
 *   - no CORS headers, restrictive CSP, no external requests, no telemetry
 *   - every write makes a timestamped backup first
 *
 * Do not expose this through a tunnel, port-forward or reverse proxy. It has no multi-user
 * concept and is not built to be one.
 */

import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanDirectories, addGitignoreEntry, detectSensitiveKeys } from './scanner.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SECURITY_HEADERS = {
  // connect-src 'self' is required, not optional: default-src 'none' otherwise blocks the page's
  // own fetch() calls and the UI renders empty. Everything else stays denied — in particular
  // there is no way for this page to send a value anywhere but back to this server.
  'Content-Security-Policy':
    "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  // Secrets must never be written to a disk cache by the browser.
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
};

const json = (res, status, body) => {
  const payload = JSON.stringify(body);
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
  res.end(payload);
};

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

// ---------------------------------------------------------------- .env parsing that round-trips
//
// Editing a .env must not reformat the parts you did not touch. Comments, blank lines, ordering
// and quoting all carry meaning to the humans who maintain these files, so the file is kept as a
// line list and only the target line is rewritten.

export function parseEnvLines(content) {
  return content.split(/\r?\n/).map((raw, index) => {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) return { index, raw, type: trimmed ? 'comment' : 'blank' };
    const eq = trimmed.indexOf('=');
    if (eq === -1) return { index, raw, type: 'other' };
    const key = trimmed.slice(0, eq).trim();
    const rawValue = trimmed.slice(eq + 1).trim();
    const quote = /^".*"$/.test(rawValue) ? '"' : /^'.*'$/.test(rawValue) ? "'" : '';
    const value = quote ? rawValue.slice(1, -1) : rawValue;
    return { index, raw, type: 'pair', key, value, quote };
  });
}

function serializeValue(value, quote) {
  if (quote) return `${quote}${value}${quote}`;
  // Quote when the value would otherwise not survive a round trip.
  if (value === '' || /[\s#"']/.test(value)) return JSON.stringify(value);
  return value;
}

function backupFile(filePath) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backup = `${filePath}.bak.${stamp}`;
  fs.copyFileSync(filePath, backup);
  return backup;
}

/** Mask a value for display. Length is hinted, never the content. */
function mask(value) {
  if (!value) return '';
  return '•'.repeat(Math.min(24, Math.max(8, value.length)));
}

// ---------------------------------------------------------------- file operations

function readEnvFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = parseEnvLines(content);
  const pairs = lines.filter((l) => l.type === 'pair');
  const sensitive = new Set(detectSensitiveKeys(pairs.map((p) => p.key)));
  return {
    filePath,
    fileName: path.basename(filePath),
    keys: pairs.map((p) => ({
      key: p.key,
      masked: mask(p.value),
      length: p.value.length,
      empty: p.value.length === 0,
      sensitive: sensitive.has(p.key),
      encrypted: /^(encrypted:|ENC\[)/.test(p.value),
    })),
  };
}

function writeKey(filePath, key, value) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = parseEnvLines(content);
  const eol = content.includes('\r\n') ? '\r\n' : '\n';
  const backup = backupFile(filePath);

  const target = lines.find((l) => l.type === 'pair' && l.key === key);
  const out = content.split(/\r?\n/);
  if (target) {
    out[target.index] = `${key}=${serializeValue(value, target.quote)}`;
  } else {
    // Append, keeping a single trailing newline.
    while (out.length && out[out.length - 1].trim() === '') out.pop();
    out.push(`${key}=${serializeValue(value, '')}`);
    out.push('');
  }
  fs.writeFileSync(filePath, out.join(eol));
  return { backup, created: !target };
}

function deleteKey(filePath, key) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = parseEnvLines(content);
  const target = lines.find((l) => l.type === 'pair' && l.key === key);
  if (!target) return null;
  const backup = backupFile(filePath);
  const eol = content.includes('\r\n') ? '\r\n' : '\n';
  const out = content.split(/\r?\n/);
  out.splice(target.index, 1);
  fs.writeFileSync(filePath, out.join(eol));
  return { backup };
}

function readValue(filePath, key) {
  const lines = parseEnvLines(fs.readFileSync(filePath, 'utf-8'));
  const target = lines.find((l) => l.type === 'pair' && l.key === key);
  return target ? target.value : null;
}

/** Generate a .env.example next to a .env: same keys, same comments, no values. */
function generateExample(filePath) {
  const target = path.join(path.dirname(filePath), `${path.basename(filePath)}.example`);
  const content = fs.readFileSync(filePath, 'utf-8');
  const eol = content.includes('\r\n') ? '\r\n' : '\n';
  const lines = parseEnvLines(content);
  const out = lines.map((l) => (l.type === 'pair' ? `${l.key}=` : l.raw));
  const existed = fs.existsSync(target);
  const backup = existed ? backupFile(target) : null;
  fs.writeFileSync(target, out.join(eol));
  return { target, backup, created: !existed };
}

// ---------------------------------------------------------------- request handling

function collectBody(request, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) { reject(new Error('body too large')); request.destroy(); return; }
      chunks.push(chunk);
    });
    request.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf-8')) : {}); }
      catch { reject(new Error('invalid JSON body')); }
    });
    request.on('error', reject);
  });
}

export function createEnviewServer({ roots, port = 4174, token, maxDepth = 4 }) {
  const authToken = token || randomBytes(24).toString('hex');
  // Only files discovered by a scan may be touched. A path arriving in a request is checked
  // against this set rather than sanitised — an allowlist cannot be escaped by clever encoding.
  let allowed = new Set();

  const refresh = () => {
    const projects = scanDirectories(roots, { maxDepth });
    allowed = new Set(projects.flatMap((p) => p.files.map((f) => path.resolve(f.filePath))));
    return projects;
  };
  refresh();

  const resolveAllowed = (filePath) => {
    if (!filePath) return null;
    const resolved = path.resolve(String(filePath));
    return allowed.has(resolved) ? resolved : null;
  };

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://127.0.0.1:${port}`);

    // --- origin checks, before anything else happens ---
    const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
    if (!allowedHosts.has(request.headers.host || '')) {
      json(response, 403, { error: 'bad host' });
      return;
    }
    const origin = request.headers.origin;
    if (origin && !new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]).has(origin)) {
      json(response, 403, { error: 'bad origin' });
      return;
    }

    // The page itself carries the token in its query string; API calls send it as a header.
    const supplied = request.headers['x-enview-token'] || url.searchParams.get('token') || '';
    const authorized = safeEqual(supplied, authToken);

    if (url.pathname === '/' && request.method === 'GET') {
      if (!authorized) {
        response.writeHead(401, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
        response.end('enview ui — open the URL printed in your terminal (it carries the access token).');
        return;
      }
      const html = fs.readFileSync(path.join(__dirname, 'ui', 'index.html'), 'utf-8')
        .replace('__ENVIEW_TOKEN__', authToken);
      response.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
      response.end(html);
      return;
    }

    if (!authorized) { json(response, 401, { error: 'unauthorized' }); return; }

    try {
      if (url.pathname === '/api/projects' && request.method === 'GET') {
        const projects = refresh();
        json(response, 200, {
          roots,
          projects: projects.map((p) => ({
            name: p.name,
            path: p.path,
            files: p.files.map((f) => ({
              ...readEnvFile(f.filePath),
              environment: f.environment,
              encryption: f.encryption.type,
              gitIgnored: f.gitIgnored,
              gitTracked: f.gitTracked,
              gitInHistory: f.gitInHistory,
              inGitRepo: f.inGitRepo,
              modifiedAt: f.modifiedAt,
              hasExample: fs.existsSync(path.join(path.dirname(f.filePath), `${f.fileName}.example`)),
            })),
          })),
        });
        return;
      }

      // The only endpoint that returns a value, and only ever one at a time.
      if (url.pathname === '/api/value' && request.method === 'GET') {
        const filePath = resolveAllowed(url.searchParams.get('file'));
        const key = url.searchParams.get('key');
        if (!filePath) { json(response, 404, { error: 'unknown file' }); return; }
        const value = readValue(filePath, key);
        if (value === null) { json(response, 404, { error: 'unknown key' }); return; }
        json(response, 200, { key, value });
        return;
      }

      if (url.pathname === '/api/key' && (request.method === 'PUT' || request.method === 'DELETE')) {
        const body = await collectBody(request);
        const filePath = resolveAllowed(body.file);
        if (!filePath) { json(response, 404, { error: 'unknown file' }); return; }
        if (!body.key || !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(body.key)) {
          json(response, 400, { error: 'invalid key name' });
          return;
        }
        if (request.method === 'DELETE') {
          const result = deleteKey(filePath, body.key);
          if (!result) { json(response, 404, { error: 'unknown key' }); return; }
          json(response, 200, { ok: true, ...result });
          return;
        }
        const result = writeKey(filePath, body.key, String(body.value ?? ''));
        json(response, 200, { ok: true, ...result });
        return;
      }

      if (url.pathname === '/api/action' && request.method === 'POST') {
        const body = await collectBody(request);
        const filePath = resolveAllowed(body.file);
        if (!filePath) { json(response, 404, { error: 'unknown file' }); return; }

        if (body.action === 'generate-example') {
          json(response, 200, { ok: true, ...generateExample(filePath) });
          return;
        }
        if (body.action === 'gitignore') {
          const added = addGitignoreEntry(path.dirname(filePath), path.basename(filePath));
          json(response, 200, { ok: true, added });
          return;
        }
        json(response, 400, { error: `unknown action ${body.action}` });
        return;
      }

      json(response, 404, { error: 'not found' });
    } catch (error) {
      json(response, 500, { error: error.message });
    }
  });

  return { server, token: authToken, port };
}

export function startEnviewUi(options) {
  const { server, token, port } = createEnviewServer(options);
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({ server, token, port, url: `http://127.0.0.1:${port}/?token=${token}` }));
  });
}
