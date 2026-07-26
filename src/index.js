/**
 * enview — library API.
 *
 * The CLI is the primary interface, but the scan is useful to embed: a dashboard, a CI job, or a
 * pre-commit hook all want the same answer without shelling out and parsing a table.
 *
 * The contract this file exposes is deliberately narrower than the internals, and it is the only
 * part covered by semver. Import from "enview", not from "enview/src/...".
 *
 * PRIVACY: nothing here ever returns a secret VALUE. Values are read only to classify them
 * (encrypted? placeholder? sensitive-looking?) and are discarded. What you get back is key names,
 * counts, encryption status, gitignore status and timestamps. That is what makes the result safe
 * to render in a dashboard or paste into a CI log — and it is a guarantee, not a default.
 */

import { scanDirectories, getAutoRoots, getSystemRoots, addGitignoreEntry, detectSensitiveKeys } from './scanner.js';
import { buildAuditReport } from './reporter.js';
import { scanHistories, historyFindings } from './history.js';

/**
 * Scan one or more roots for .env files.
 *
 * @param {string[]} [roots] Directories to scan. Defaults to the user's home directory.
 * @param {object} [opts]
 * @param {number} [opts.maxDepth=6] How deep to walk below each root.
 * @param {boolean} [opts.broad=false] Include directories normally skipped as noise.
 * @returns {Array<{name: string, path: string, files: EnvFile[]}>} Projects, sorted by name.
 *
 * @typedef {object} EnvFile
 * @property {string} filePath
 * @property {string} fileName
 * @property {string} projectDir
 * @property {string} projectName
 * @property {string} environment    development | production | staging | test | ...
 * @property {string[]} keys            every key name in the file
 * @property {string[]} encryptedKeys   keys whose value is encrypted at rest
 * @property {string[]} plaintextKeys   keys with a real, unencrypted value
 * @property {string[]} sensitiveKeys   plaintext keys whose NAME looks like a credential
 * @property {{type: string}} encryption
 * @property {boolean} inGitRepo
 * @property {boolean} gitIgnored
 * @property {Date} modifiedAt
 */
export function scanProjects(roots, opts = {}) {
  return scanDirectories(roots?.length ? roots : getAutoRoots(), opts);
}

/**
 * Turn a scan into structured findings — the same set `enview audit --json` reports.
 *
 * @param {ReturnType<typeof scanProjects>} projects
 * @returns {{findings: Finding[], summary: {total: number, critical: number}}}
 *
 * @typedef {object} Finding
 * @property {'critical'|'warning'} level
 * @property {string} project
 * @property {string} file
 * @property {'plaintext_secrets'|'not_gitignored'} type
 * @property {string[]} [keys] Key NAMES only, for plaintext_secrets.
 */
export function auditProjects(projects) {
  return buildAuditReport(projects);
}

/** Scan and audit in one call, for the common case. */
export function scanAndAudit(roots, opts = {}) {
  const projects = scanProjects(roots, opts);
  return { projects, ...auditProjects(projects) };
}

/**
 * Scan git history for secrets that are no longer on disk.
 *
 * A working-tree scan cannot see a .env deleted last year, or a signing key committed once and
 * removed — both are still in every clone. This walks `--all`, so abandoned branches count too.
 *
 * @param {string[]} dirs Any directories inside the repositories to scan.
 * @returns {Array<{root: string, repoName: string, findings: object[]}>}
 */
export function scanHistory(dirs, opts = {}) {
  return scanHistories(dirs, { detectSensitive: detectSensitiveKeys, ...opts });
}

/**
 * Everything, in the shape a scheduled guard wants: working-tree findings plus history findings.
 * `critical` counts both, so a non-zero exit is a single check.
 */
export function protect(roots, opts = {}) {
  const projects = scanProjects(roots, opts);
  const tree = auditProjects(projects);
  // History is scanned per project directory found by the scan, not per root — that keeps the
  // work proportional to where secrets actually live.
  const dirs = opts.historyDirs || [...new Set(projects.map((p) => p.path))];
  const historyOn = opts.history !== false;
  const histories = historyOn ? scanHistory(dirs, opts) : [];
  const history = historyFindings(histories);

  // The working-tree audit infers "this was committed" from git metadata about the file on disk.
  // The history scan answers the same question directly, and also covers files that are no
  // longer on disk at all. When both ran, keep the history answer and drop the inference —
  // otherwise every committed secret is reported twice, once vaguely.
  const historyPaths = new Set(
    histories.flatMap((repo) => repo.findings.map((f) => `${repo.root}::${f.filePath}`.toLowerCase()))
  );
  const supersededByHistory = (f) => {
    if (!historyOn || f.type !== 'committed_secrets') return false;
    const normalized = String(f.file).replace(/\\/g, '/').toLowerCase();
    for (const key of historyPaths) {
      const [root, rel] = key.split('::');
      if (normalized === `${root.replace(/\\/g, '/')}/${rel}`) return true;
    }
    return false;
  };

  const workingTree = tree.findings.filter((f) => !supersededByHistory(f));
  const findings = [...workingTree, ...history];
  return {
    projects,
    histories,
    findings,
    summary: {
      total: findings.length,
      critical: findings.filter((f) => f.level === 'critical').length,
      // Counted AFTER dedupe, so the breakdown always adds up to the total. A summary that
      // does not reconcile with the table under it makes the reader distrust both.
      workingTree: workingTree.length,
      history: history.length,
    },
  };
}

export { getAutoRoots, getSystemRoots, addGitignoreEntry, detectSensitiveKeys, historyFindings };
