#!/usr/bin/env node

import { Command } from 'commander';
import os from 'node:os';
import chalk from 'chalk';
import { scanDirectories, addGitignoreEntry, getAutoRoots, getSystemRoots } from '../src/scanner.js';
import {
  printScanResults,
  printAuditResults,
  printKeysResults,
  printDriftResults,
  printFixResults,
  printHistoryResults,
  printProtectResults,
} from '../src/reporter.js';

function resolveRoots(dirs, opts) {
  if (opts.system) {
    const roots = getSystemRoots();
    console.log(chalk.dim(`\n  Scanning system drives: ${roots.join(', ')}\n`));
    return { roots, scanOpts: { maxDepth: opts.depth ?? 8, broad: true } };
  }
  if (!dirs.length) {
    const roots = getAutoRoots();
    console.log(chalk.dim(`\n  Scanning home directory: ${roots[0]}\n`));
    return { roots, scanOpts: { maxDepth: opts.depth ?? 5, broad: true } };
  }
  return { roots: dirs, scanOpts: { maxDepth: opts.depth ?? 6 } };
}

const program = new Command();

program
  .name('enview')
  .description('Cross-project .env scanner, auditor, and drift detector.\nKnow what secrets live where — without exposing them.')
  .version('0.2.0');

program
  .command('scan')
  .description('Find and inventory all .env files across project directories')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
    printScanResults(projects, opts);
  });

program
  .command('audit')
  .description('Security audit — find plaintext secrets, missing .gitignore, exposed keys')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON (for CI integration)')
  .option('--strict', 'Exit with code 1 on any critical finding')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
    printAuditResults(projects, opts);

    if (opts.strict) {
      const hasCritical = projects.some(p =>
        p.files.some(f => f.sensitiveKeys.length > 0 || (!f.gitIgnored && f.encryption.type === 'none' && f.inGitRepo))
      );
      if (hasCritical) process.exit(1);
    }
  });

program
  .command('keys')
  .description('List all key names across projects (values are NEVER shown)')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
    printKeysResults(projects, opts);
  });

program
  .command('drift')
  .description('Compare keys across environments — find missing variables')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
    printDriftResults(projects, opts);
  });

program
  .command('fix')
  .description('Add missing .gitignore entries and show encryption commands')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--dry-run', 'Show what would be fixed without making changes')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
    const fixActions = { gitignoreAdded: [], alreadyIgnored: [] };

    for (const project of projects) {
      for (const f of project.files) {
        if (!f.inGitRepo) continue;
        if (f.gitIgnored) {
          fixActions.alreadyIgnored.push({ project: project.name, fileName: f.fileName });
          continue;
        }
        if (opts.dryRun) {
          fixActions.gitignoreAdded.push({ project: project.name, fileName: f.fileName, dryRun: true });
        } else {
          const added = addGitignoreEntry(project.path, f.fileName);
          if (added) {
            fixActions.gitignoreAdded.push({ project: project.name, fileName: f.fileName });
          } else {
            fixActions.alreadyIgnored.push({ project: project.name, fileName: f.fileName });
          }
        }
      }
    }

    printFixResults(projects, fixActions);
  });

program
  .command('history')
  .description('Scan git history for secrets that are no longer on disk')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON')
  .action(async (dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const { scanHistory } = await import('../src/index.js');
    const projects = scanDirectories(roots, scanOpts);
    // Scan the repos where env files actually live, plus the roots themselves.
    const targets = [...new Set([...projects.map((p) => p.path), ...roots])];
    const histories = scanHistory(targets);
    printHistoryResults(histories, opts);
  });

program
  .command('protect')
  .description('Working-tree audit + git history scan. Exits 1 on critical findings — for cron/CI.')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON')
  .option('--no-history', 'Skip the git history scan (much faster)')
  .option('--quiet', 'Print nothing when there is nothing to report')
  .action(async (dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const { protect } = await import('../src/index.js');
    const report = protect(roots, { ...scanOpts, history: opts.history !== false });

    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
    } else if (!(opts.quiet && report.summary.critical === 0)) {
      printProtectResults(report);
    }
    // A guard that always exits 0 is decoration. Non-zero is what makes a cron job or a CI step
    // actually stop something.
    if (report.summary.critical > 0) process.exitCode = 1;
  });

program
  .command('ui')
  .description('Open the local management UI — masked values, reveal, copy, edit, remediate')
  .argument('[dirs...]', 'Directories to manage (default: home directory)')
  .option('-p, --port <n>', 'Port to listen on', (v) => parseInt(v, 10), 4174)
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--no-open', 'Do not launch a browser')
  .action(async (dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const { startEnviewUi } = await import('../src/server.js');
    const { url } = await startEnviewUi({ roots, port: opts.port, maxDepth: scanOpts.maxDepth });

    console.log(chalk.bold(`\n  🦅 enview ui — ${chalk.underline(url)}\n`));
    console.log(chalk.dim('  This is the only part of enview that handles secret values. It binds 127.0.0.1,'));
    console.log(chalk.dim('  validates Host and Origin, and requires the token in that URL. Do not tunnel or'));
    console.log(chalk.dim('  port-forward it. Every write makes a timestamped .bak first.\n'));
    console.log(chalk.dim('  Ctrl-C to stop.\n'));

    if (opts.open !== false) {
      const openers = { win32: ['cmd', ['/c', 'start', '', url]], darwin: ['open', [url]] };
      const [cmd, args] = openers[process.platform] || ['xdg-open', [url]];
      try {
        const { spawn } = await import('node:child_process');
        spawn(cmd, args, { stdio: 'ignore', detached: true }).unref();
      } catch { /* the URL is printed above; opening a browser is a convenience, not a requirement */ }
    }
  });

program.parse();
