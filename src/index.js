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

import { scanDirectories, getAutoRoots, getSystemRoots, addGitignoreEntry } from './scanner.js';
import { buildAuditReport } from './reporter.js';

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

export { getAutoRoots, getSystemRoots, addGitignoreEntry };
