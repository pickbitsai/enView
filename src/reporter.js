import chalk from 'chalk';
import Table from 'cli-table3';
import path from 'node:path';

const ICONS = {
  locked: '🔒',
  unlocked: '🔓',
  warning: '⚠️',
  check: '✅',
  cross: '❌',
  partial: '🟡',
  project: '📁',
  key: '🔑',
  shield: '🛡️',
  eye: '👁️',
  clock: '🕐',
};

// ─── scan command ────────────────────────────────────────

export function printScanResults(projects, opts = {}) {
  if (opts.json) {
    console.log(JSON.stringify(projects, null, 2));
    return;
  }

  if (projects.length === 0) {
    console.log(chalk.yellow('\n  No .env files found.\n'));
    return;
  }

  const totalFiles = projects.reduce((n, p) => n + p.files.length, 0);
  console.log(chalk.bold(`\n${ICONS.shield}  enview scan — ${projects.length} projects, ${totalFiles} env files\n`));

  const table = new Table({
    head: [
      chalk.cyan('Project'),
      chalk.cyan('File'),
      chalk.cyan('Env'),
      chalk.cyan('Keys'),
      chalk.cyan('Encrypted'),
      chalk.cyan('.gitignore'),
      chalk.cyan('Modified'),
    ],
    style: { head: [], border: ['dim'] },
    colWidths: [22, 20, 14, 7, 14, 12, 14],
    wordWrap: true,
  });

  for (const project of projects) {
    for (let i = 0; i < project.files.length; i++) {
      const f = project.files[i];
      const enc = formatEncryption(f.encryption);
      const gitignore = f.inGitRepo
        ? (f.gitIgnored ? chalk.green(`${ICONS.check} yes`) : chalk.red(`${ICONS.cross} NO`))
        : chalk.dim('n/a');
      const modified = formatDate(f.modifiedAt);

      table.push([
        i === 0 ? chalk.bold(truncate(project.name, 20)) : '',
        chalk.white(f.fileName),
        chalk.dim(f.environment),
        String(f.keys.length),
        enc,
        gitignore,
        modified,
      ]);
    }
  }

  console.log(table.toString());
  console.log();
}

// ─── audit command ───────────────────────────────────────

export function printAuditResults(projects, opts = {}) {
  if (opts.json) {
    console.log(JSON.stringify(buildAuditReport(projects), null, 2));
    return;
  }

  const findings = [];
  let criticalCount = 0;
  let warnCount = 0;

  for (const project of projects) {
    for (const f of project.files) {
      // CRITICAL: Plaintext secrets not gitignored
      if (f.encryption.type === 'none' && f.inGitRepo && !f.gitIgnored) {
        findings.push({
          level: 'CRITICAL',
          project: project.name,
          file: f.fileName,
          message: 'Plaintext .env file is NOT gitignored — secrets may be committed',
        });
        criticalCount++;
      }

      // CRITICAL: Sensitive keys in plaintext
      if (f.sensitiveKeys.length > 0) {
        findings.push({
          level: 'CRITICAL',
          project: project.name,
          file: f.fileName,
          message: `${f.sensitiveKeys.length} sensitive key(s) in plaintext: ${f.sensitiveKeys.slice(0, 3).join(', ')}${f.sensitiveKeys.length > 3 ? '…' : ''}`,
        });
        criticalCount++;
      }

      // WARN: Partial encryption
      if (f.encryption.partial) {
        findings.push({
          level: 'WARN',
          project: project.name,
          file: f.fileName,
          message: `Partial encryption — ${f.encryption.encryptedCount}/${f.encryption.totalCount} keys encrypted`,
        });
        warnCount++;
      }

      // WARN: .env.keys file might be committed
      if (f.inGitRepo && !f.gitIgnored && f.fileName === '.env.keys') {
        findings.push({
          level: 'CRITICAL',
          project: project.name,
          file: f.fileName,
          message: 'Private key file is NOT gitignored — decryption keys at risk',
        });
        criticalCount++;
      }

      // INFO: No encryption at all
      if (f.encryption.type === 'none' && f.keys.length > 0) {
        findings.push({
          level: 'INFO',
          project: project.name,
          file: f.fileName,
          message: `No encryption — ${f.keys.length} plaintext keys (exposed to AI agents, scripts, processes)`,
        });
      }
    }
  }

  // Drift check across environments per project
  for (const project of projects) {
    if (project.files.length < 2) continue;
    const envSets = project.files.map(f => ({
      name: f.fileName,
      keys: new Set(f.keys),
    }));

    for (let i = 0; i < envSets.length; i++) {
      for (let j = i + 1; j < envSets.length; j++) {
        const missing = [...envSets[i].keys].filter(k => !envSets[j].keys.has(k));
        if (missing.length > 0) {
          findings.push({
            level: 'WARN',
            project: project.name,
            file: `${envSets[i].name} → ${envSets[j].name}`,
            message: `${missing.length} key(s) in ${envSets[i].name} missing from ${envSets[j].name}: ${missing.slice(0, 3).join(', ')}${missing.length > 3 ? '…' : ''}`,
          });
          warnCount++;
        }
      }
    }
  }

  console.log(chalk.bold(`\n${ICONS.shield}  enview audit — ${findings.length} findings\n`));

  if (findings.length === 0) {
    console.log(chalk.green('  All clear! No issues found.\n'));
    return;
  }

  const table = new Table({
    head: [
      chalk.cyan('Level'),
      chalk.cyan('Project'),
      chalk.cyan('File'),
      chalk.cyan('Finding'),
    ],
    style: { head: [], border: ['dim'] },
    colWidths: [12, 18, 22, 50],
    wordWrap: true,
  });

  // Sort: CRITICAL first, then WARN, then INFO
  const order = { CRITICAL: 0, WARN: 1, INFO: 2 };
  findings.sort((a, b) => order[a.level] - order[b.level]);

  for (const f of findings) {
    const levelStr = f.level === 'CRITICAL'
      ? chalk.bgRed.white.bold(` ${f.level} `)
      : f.level === 'WARN'
        ? chalk.yellow.bold(f.level)
        : chalk.dim(f.level);
    table.push([levelStr, f.project, f.file, f.message]);
  }

  console.log(table.toString());

  if (criticalCount > 0) {
    console.log(chalk.red.bold(`\n  ${ICONS.warning}  ${criticalCount} critical issue(s) require immediate attention\n`));
  }

  const unencryptedProjects = projects.filter(p =>
    p.files.some(f => f.encryption.type === 'none' && f.keys.length > 0)
  );
  if (unencryptedProjects.length > 0) {
    const encCount = projects.length - unencryptedProjects.length;
    if (encCount > 0) {
      console.log(chalk.green(`  ${ICONS.locked} ${encCount}/${projects.length} projects fully encrypted\n`));
    }
    console.log(chalk.cyan(`  ${ICONS.locked} Encrypt your .env files with dotenvx: ${chalk.underline('https://dotenvx.com')}`));
    for (const p of unencryptedProjects) {
      console.log(chalk.dim(`    $ cd ${p.path} && npx @dotenvx/dotenvx encrypt`));
    }
    console.log();
    console.log(chalk.dim(`  Or run ${chalk.white('enview fix')} to add missing .gitignore entries and see per-project commands.`));
    console.log();
  } else if (projects.length > 0) {
    console.log(chalk.green(`\n  ${ICONS.locked} ${projects.length}/${projects.length} projects fully encrypted\n`));
  }
}

// ─── keys command ────────────────────────────────────────

export function printKeysResults(projects, opts = {}) {
  if (opts.json) {
    const result = {};
    for (const project of projects) {
      result[project.name] = {};
      for (const f of project.files) {
        result[project.name][f.fileName] = f.keys.map(k => ({
          name: k,
          encrypted: f.encryptedKeys.includes(k),
          sensitive: f.sensitiveKeys.includes(k),
        }));
      }
    }
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(chalk.bold(`\n${ICONS.key}  enview keys — key inventory (values never shown)\n`));

  for (const project of projects) {
    console.log(chalk.bold(`  ${ICONS.project} ${project.name}`));
    console.log(chalk.dim(`     ${project.path}\n`));

    for (const f of project.files) {
      console.log(`     ${chalk.underline(f.fileName)} ${chalk.dim(`(${f.environment})`)}`);
      for (const key of f.keys) {
        const isEnc = f.encryptedKeys.includes(key);
        const isSensitive = f.sensitiveKeys.includes(key);
        const icon = isEnc ? ICONS.locked : (isSensitive ? ICONS.warning : ICONS.unlocked);
        const label = isEnc
          ? chalk.green(key)
          : (isSensitive ? chalk.red(key) : chalk.white(key));
        const tag = isSensitive && !isEnc ? chalk.red(' ← plaintext secret!') : '';
        console.log(`       ${icon} ${label}${tag}`);
      }
      console.log();
    }
  }
}

// ─── drift command ───────────────────────────────────────

export function printDriftResults(projects, opts = {}) {
  console.log(chalk.bold(`\n${ICONS.eye}  enview drift — environment key comparison\n`));

  let hasDrift = false;

  for (const project of projects) {
    if (project.files.length < 2) continue;

    const allKeys = new Set();
    for (const f of project.files) f.keys.forEach(k => allKeys.add(k));

    const matrix = {};
    for (const key of allKeys) {
      matrix[key] = {};
      for (const f of project.files) {
        matrix[key][f.fileName] = f.keys.includes(key);
      }
    }

    // Check if there's any actual drift
    const driftKeys = Object.entries(matrix).filter(([, envs]) => {
      const vals = Object.values(envs);
      return vals.includes(true) && vals.includes(false);
    });

    if (driftKeys.length === 0) continue;
    hasDrift = true;

    console.log(chalk.bold(`  ${ICONS.project} ${project.name}`));

    const fileNames = project.files.map(f => f.fileName);
    const table = new Table({
      head: [chalk.cyan('Key'), ...fileNames.map(n => chalk.cyan(n))],
      style: { head: [], border: ['dim'] },
    });

    for (const [key, envs] of driftKeys) {
      table.push([
        chalk.white(key),
        ...fileNames.map(n => envs[n] ? chalk.green('✓') : chalk.red('✗ missing')),
      ]);
    }

    console.log(table.toString());
    console.log();
  }

  if (!hasDrift) {
    console.log(chalk.green('  No drift detected — all environments have consistent keys.\n'));
  }
}

// ─── fix command ────────────────────────────────────────

export function printFixResults(projects, fixActions) {
  console.log(chalk.bold(`\n🔧  enview fix — remediation\n`));

  if (fixActions.gitignoreAdded.length > 0) {
    console.log(chalk.green.bold('  .gitignore entries added:\n'));
    for (const entry of fixActions.gitignoreAdded) {
      console.log(chalk.green(`    ${ICONS.check} ${entry.project} — added ${entry.fileName} to .gitignore`));
    }
    console.log();
  }

  if (fixActions.alreadyIgnored.length > 0) {
    console.log(chalk.dim(`  Already gitignored: ${fixActions.alreadyIgnored.map(e => e.project + '/' + e.fileName).join(', ')}\n`));
  }

  const unencryptedProjects = projects.filter(p =>
    p.files.some(f => f.encryption.type === 'none' && f.keys.length > 0)
  );

  if (unencryptedProjects.length > 0) {
    console.log(chalk.cyan.bold('  Encrypt your .env files:\n'));
    console.log(chalk.dim('    Install dotenvx once:'));
    console.log(chalk.white('    $ npm install -g @dotenvx/dotenvx\n'));
    console.log(chalk.dim('    Then encrypt each project:'));
    for (const p of unencryptedProjects) {
      console.log(chalk.white(`    $ cd ${p.path} && dotenvx encrypt`));
    }
    console.log();
    console.log(chalk.dim(`    Learn more: ${chalk.underline('https://dotenvx.com')}`));
    console.log();
  }

  if (fixActions.gitignoreAdded.length === 0 && unencryptedProjects.length === 0) {
    console.log(chalk.green('  Nothing to fix — all projects are protected.\n'));
  }
}

// ─── helpers ─────────────────────────────────────────────

function formatEncryption(enc) {
  if (enc.type === 'none') return chalk.red(`${ICONS.unlocked} none`);
  if (enc.partial) return chalk.yellow(`${ICONS.partial} ${enc.type} (${enc.encryptedCount}/${enc.totalCount})`);
  return chalk.green(`${ICONS.locked} ${enc.type}`);
}

function formatDate(date) {
  const now = new Date();
  const diff = now - date;
  const days = Math.floor(diff / 86400000);
  if (days === 0) return chalk.green('today');
  if (days === 1) return chalk.green('yesterday');
  if (days < 7) return chalk.white(`${days}d ago`);
  if (days < 30) return chalk.white(`${Math.floor(days / 7)}w ago`);
  if (days < 365) return chalk.yellow(`${Math.floor(days / 30)}mo ago`);
  return chalk.red(`${Math.floor(days / 365)}y ago`);
}

function truncate(str, len) {
  return str.length > len ? str.slice(0, len - 1) + '…' : str;
}

// Exported so the library API (src/index.js) can offer audit findings without a consumer having
// to re-derive them from a raw scan. The CLI still uses it the same way.
export function buildAuditReport(projects) {
  // Structured JSON audit for CI integration
  const findings = [];
  for (const project of projects) {
    for (const f of project.files) {
      if (f.sensitiveKeys.length > 0) {
        findings.push({
          level: 'critical',
          project: project.name,
          file: f.filePath,
          type: 'plaintext_secrets',
          keys: f.sensitiveKeys,
        });
      }
      // A file git is merely not ignoring is a risk — one `git add -A` from disclosure.
      // A file git is TRACKING is already in history, on every clone and every remote, and
      // .gitignore cannot help. Rotation is the only remedy, so it gets its own finding rather
      // than being folded into not_gitignored where it reads as the same problem.
      if ((f.gitTracked || f.gitInHistory) && f.encryption.type === 'none' && f.plaintextKeys.length > 0) {
        findings.push({
          level: 'critical',
          project: project.name,
          file: f.filePath,
          type: 'committed_secrets',
          keys: f.sensitiveKeys,
          tracked: f.gitTracked,
          remedy: f.gitTracked
            ? 'git is tracking this file: `git rm --cached`, add it to .gitignore, then rotate the credentials'
            : 'no longer tracked, but still in history on every clone — rotate the credentials',
        });
      } else if (f.inGitRepo && !f.gitIgnored && f.encryption.type === 'none') {
        findings.push({
          level: 'critical',
          project: project.name,
          file: f.filePath,
          type: 'not_gitignored',
        });
      }
    }
  }
  return { findings, summary: { total: findings.length, critical: findings.filter(f => f.level === 'critical').length } };
}
