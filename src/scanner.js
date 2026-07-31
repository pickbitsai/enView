import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

const ENV_PATTERNS = [
  '.env', '.env.*',
];

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'vendor', '__pycache__', '.venv',
  'venv', 'dist', 'build', '.next', '.nuxt', '.output',
  'target', 'coverage', '.terraform', '.cache',
]);

// Extra dirs to skip when scanning home or system-wide
const IGNORE_DIRS_BROAD = new Set([
  ...IGNORE_DIRS,
  // Windows
  'AppData', 'Application Data', 'Program Files', 'Program Files (x86)',
  'ProgramData', 'Windows', 'Recovery', '$Recycle.Bin', 'System Volume Information',
  'Intel', 'PerfLogs', 'MSOCache',
  // macOS
  'Library', 'Applications', 'System',
  // Linux
  'snap', 'proc', 'sys', 'run', 'boot', 'dev', 'mnt', 'media',
  // Common non-code dirs
  'Music', 'Videos', 'Pictures', 'Movies', 'Photos',
  'Games', 'Steam', 'Epic Games',
  'OneDrive', 'Google Drive', 'Dropbox',
  '.local', '.config', '.cache', '.npm', '.nvm', '.yarn',
  '.rustup', '.cargo', '.gradle', '.m2', '.nuget',
  '.docker', '.kube', '.minikube', '.vagrant',
  // Recent items (Windows)
  'Recent',
]);

const IGNORE_EXTENSIONS = new Set([
  '.example', '.sample', '.template', '.bak', '.swp',
]);

/**
 * Recursively find .env files under given root directories
 */
export function scanDirectories(roots, opts = {}) {
  const maxDepth = opts.maxDepth ?? 6;
  const broad = opts.broad ?? false;
  const results = [];

  for (const root of roots) {
    const absRoot = path.resolve(root);
    if (!fs.existsSync(absRoot)) continue;
    walkDir(absRoot, absRoot, 0, maxDepth, broad, results);
  }

  return groupByProject(results);
}

/**
 * Get the user's home directory as the default scan root
 */
export function getAutoRoots() {
  return [os.homedir()];
}

/**
 * Get system drive roots for deep system-wide scanning
 */
export function getSystemRoots() {
  if (process.platform === 'win32') {
    // Check common drive letters
    return ['C', 'D', 'E', 'F'].map(d => `${d}:\\`).filter(d => fs.existsSync(d));
  }
  return ['/home', '/Users', '/root'].filter(d => fs.existsSync(d));
}

function walkDir(dir, root, depth, maxDepth, broad, results) {
  if (depth > maxDepth) return;

  const ignoreDirs = broad ? IGNORE_DIRS_BROAD : IGNORE_DIRS;

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // permission denied, etc.
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (ignoreDirs.has(entry.name)) continue;
      if (!broad && entry.name.startsWith('.')) continue;
      walkDir(fullPath, root, depth + 1, maxDepth, broad, results);
      continue;
    }

    if (!entry.isFile()) continue;
    if (!isEnvFile(entry.name)) continue;

    const info = analyzeEnvFile(fullPath, root);
    if (info) results.push(info);
  }
}

function isEnvFile(filename) {
  if (filename === '.env') return true;
  if (!filename.startsWith('.env.')) return false;

  const suffix = filename.slice(5); // after ".env."
  // Skip example/template files
  if (IGNORE_EXTENSIONS.has('.' + suffix)) return false;
  // Skip .env.keys (dotenvx private key file — never scan)
  if (suffix === 'keys') return false;
  // Skip Windows shortcut files
  if (filename.endsWith('.lnk')) return false;
  return true;
}

function analyzeEnvFile(filePath, scanRoot) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }

  const stat = fs.statSync(filePath);
  const dir = path.dirname(filePath);
  const projectDir = detectProjectRoot(dir, scanRoot);

  const keys = [];
  const encryptedKeys = [];
  const plaintextKeys = [];
  const lines = content.split('\n');

  let hasDotenvxPublicKey = false;
  let hasSopsMetadata = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) {
      if (trimmed.includes('DOTENV_PUBLIC_KEY')) hasDotenvxPublicKey = true;
      continue;
    }

    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;

    const key = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim();

    // Skip dotenvx internal keys
    if (key === 'DOTENV_PUBLIC_KEY' || key.startsWith('DOTENV_PUBLIC_KEY_')) continue;

    keys.push(key);

    if (isEncryptedValue(value)) {
      encryptedKeys.push(key);
    } else if (value && !isBoringValue(value)) {
      plaintextKeys.push(key);
    }
  }

  // Check for SOPS metadata
  if (content.includes('sops_version') || content.includes('sops:')) {
    hasSopsMetadata = true;
  }

  const encryption = detectEncryption(hasDotenvxPublicKey, hasSopsMetadata, encryptedKeys, keys);
  const gitInfo = getGitInfo(filePath, dir);

  return {
    filePath,
    fileName: path.basename(filePath),
    projectDir,
    projectName: path.basename(projectDir),
    environment: detectEnvironment(path.basename(filePath)),
    keys,
    encryptedKeys,
    plaintextKeys,
    encryption,
    modifiedAt: stat.mtime,
    size: stat.size,
    gitTracked: gitInfo.tracked,
    gitInHistory: gitInfo.inHistory,
    gitIgnored: gitInfo.ignored,
    lastCommit: gitInfo.lastCommit,
    inGitRepo: gitInfo.inGitRepo,
    sensitiveKeys: detectSensitiveKeys(plaintextKeys),
  };
}

function isEncryptedValue(value) {
  // dotenvx: "encrypted:..."
  if (value.startsWith('"encrypted:') || value.startsWith('encrypted:')) return true;
  // SOPS-style encrypted values
  if (value.startsWith('ENC[') && value.endsWith(']')) return true;
  // age-encrypted
  if (value.includes('age-encryption.org')) return true;
  return false;
}

function isBoringValue(value) {
  const unquoted = value.replace(/^["']|["']$/g, '');
  // Empty, localhost, true/false, numbers
  if (!unquoted) return true;
  if (/^(true|false|yes|no|on|off)$/i.test(unquoted)) return true;
  if (/^\d+$/.test(unquoted)) return true;
  if (unquoted === 'localhost' || unquoted === '127.0.0.1') return true;
  return false;
}

function detectEncryption(hasDotenvxKey, hasSops, encryptedKeys, allKeys) {
  if (hasDotenvxKey && encryptedKeys.length > 0) {
    return {
      type: 'dotenvx',
      partial: encryptedKeys.length < allKeys.length,
      encryptedCount: encryptedKeys.length,
      totalCount: allKeys.length,
    };
  }
  if (hasSops) {
    return { type: 'sops', partial: false, encryptedCount: allKeys.length, totalCount: allKeys.length };
  }
  if (encryptedKeys.length > 0) {
    return {
      type: 'unknown',
      partial: encryptedKeys.length < allKeys.length,
      encryptedCount: encryptedKeys.length,
      totalCount: allKeys.length,
    };
  }
  return { type: 'none', partial: false, encryptedCount: 0, totalCount: allKeys.length };
}

function detectEnvironment(fileName) {
  if (fileName === '.env') return 'development';
  const suffix = fileName.slice(5); // after ".env."
  const normalized = suffix.toLowerCase();
  const map = {
    'dev': 'development', 'development': 'development',
    'prod': 'production', 'production': 'production',
    'stg': 'staging', 'staging': 'staging',
    'local': 'local', 'test': 'test', 'ci': 'ci',
  };
  return map[normalized] || normalized;
}

const SENSITIVE_PATTERNS = [
  /api.?key/i, /secret/i, /password/i, /passwd/i, /token/i,
  /private.?key/i, /auth/i, /credential/i, /connection.?string/i,
  /database.?url/i, /db.?pass/i, /smtp/i, /stripe/i,
  /aws.?access/i, /aws.?secret/i, /openai/i, /anthropic/i,
  /github.?token/i, /webhook/i, /signing/i, /encryption/i,
];

// Exported so history scanning classifies a key the same way whether it is on disk or in a
// historical blob — two different verdicts for the same key name would be worse than none.
export function detectSensitiveKeys(plaintextKeys) {
  return plaintextKeys.filter(key =>
    SENSITIVE_PATTERNS.some(pattern => pattern.test(key))
  );
}

function detectProjectRoot(dir, scanRoot) {
  let current = dir;
  while (current !== scanRoot && current !== path.dirname(current)) {
    const markers = ['package.json', 'Cargo.toml', 'go.mod', 'pyproject.toml',
      'Gemfile', 'pom.xml', 'build.gradle', 'Makefile', '.git',
      'composer.json', 'mix.exs', 'deno.json'];
    for (const marker of markers) {
      if (fs.existsSync(path.join(current, marker))) return current;
    }
    current = path.dirname(current);
  }
  return dir;
}

function getGitInfo(filePath, dir) {
  const result = { tracked: false, inHistory: false, ignored: false, lastCommit: null, inGitRepo: false };

  try {
    execFileSync('git', ['rev-parse', '--git-dir'], { cwd: dir, stdio: 'pipe' });
    result.inGitRepo = true;
  } catch {
    return result;
  }

  // execFileSync, not execSync: a shell command string needs `2>/dev/null` to stay quiet, and
  // cmd.exe cannot resolve that path — so on Windows the command failed every time, the catch
  // ran, and EVERY file was reported as not-gitignored. That turned the audit's most important
  // signal into a permanent false alarm. Passing argv directly needs no shell and no redirect
  // (stdio 'pipe' already captures stderr), and it sidesteps quoting differences between
  // platforms. git exits 1 for "not ignored", which is a throw, not an error.
  try {
    const status = execFileSync('git', ['check-ignore', filePath], {
      cwd: dir, stdio: 'pipe', encoding: 'utf-8',
    });
    result.ignored = status.trim().length > 0;
  } catch {
    result.ignored = false;
  }

  // "Tracked" means git has this file in the index RIGHT NOW — ask git that question directly.
  // Inferring it from `git log` conflated two different states: a file currently under version
  // control, and a file that was committed once and later removed. Both leak, but they need
  // different remedies, and calling the second one "tracked" overstates the first.
  try {
    execFileSync('git', ['ls-files', '--error-unmatch', filePath], { cwd: dir, stdio: 'pipe' });
    result.tracked = true;
  } catch {
    result.tracked = false;
  }

  // Separately: does this path appear anywhere in history? A file removed from the index still
  // has its secrets in every clone, so this stays a finding even when tracked is false.
  try {
    const log = execFileSync(
      'git',
      ['log', '-1', '--format=%H|%aI|%s', '--', path.basename(filePath)],
      { cwd: dir, stdio: 'pipe', encoding: 'utf-8' }
    ).trim();
    if (log) {
      const [hash, date, message] = log.split('|');
      result.inHistory = true;
      result.lastCommit = { hash: hash.slice(0, 8), date: new Date(date), message };
    }
  } catch {
    // never committed
  }

  return result;
}

export function addGitignoreEntry(projectPath, fileName) {
  const gitignorePath = path.join(projectPath, '.gitignore');
  let content = '';
  if (fs.existsSync(gitignorePath)) {
    content = fs.readFileSync(gitignorePath, 'utf-8');
    const lines = content.split('\n').map(l => l.trim());
    if (lines.includes(fileName)) return false; // already present
  }
  const newline = content && !content.endsWith('\n') ? '\n' : '';
  fs.appendFileSync(gitignorePath, `${newline}${fileName}\n`);
  return true;
}

// Removes a file from git's index without touching the working copy, then makes sure it can't
// be re-added by accident. Does NOT touch history — the remedy text callers show must say so.
export function untrackFile(projectPath, filePath) {
  execFileSync('git', ['rm', '--cached', '--ignore-unmatch', filePath], { cwd: projectPath, stdio: 'pipe' });
  const gitignoreAdded = addGitignoreEntry(projectPath, path.basename(filePath));
  return { gitignoreAdded };
}

function groupByProject(files) {
  const projects = new Map();
  for (const file of files) {
    const key = file.projectDir;
    if (!projects.has(key)) {
      projects.set(key, {
        name: file.projectName,
        path: file.projectDir,
        files: [],
      });
    }
    projects.get(key).files.push(file);
  }
  return [...projects.values()].sort((a, b) => a.name.localeCompare(b.name));
}
