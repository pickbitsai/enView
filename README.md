<p align="center">
  <h1 align="center">🦅 enview</h1>
  <p align="center">
    <strong>Cross-project .env scanner, auditor, and drift detector.</strong><br/>
    Know what secrets live where — without exposing them.
  </p>
  <p align="center">
    <a href="#install">Install</a> •
    <a href="#commands">Commands</a> •
    <a href="#ci-integration">CI Integration</a> •
    <a href="#why">Why?</a>
  </p>
</p>

---

> **Your `.env` files are scattered across dozens of projects.** Some are encrypted, some aren't. Some are gitignored, some aren't. Some have keys that don't exist in production. You don't know which ones AI agents can read.
>
> **enview gives you a single terminal command to see all of it.**

## The Problem

If you're a developer shipping multiple projects, you probably have:

- 🔓 **Plaintext API keys** sitting in `.env` files that any LLM, build script, or npm postinstall can read
- 🕳️ **Missing keys** between dev and production that cause deploy failures
- 🤷 **No idea** which projects use encryption (dotenvx, sops, etc.) and which don't
- 📂 **No inventory** of what secrets exist across your entire workspace

enview is a zero-config CLI that scans your project directories and tells you the truth.

## Install

```bash
npx @pickbitsai/enview scan ~/code        # try it instantly

npm install -g @pickbitsai/enview          # or install globally
```

The package is scoped, but the command it installs is plain `enview` — every
example below works as written once it's on your PATH.

## Commands

### `enview scan` — Find everything

Recursively discover all `.env` files across your projects. See encryption status, gitignore coverage, and modification dates at a glance.

```bash
enview scan ~/code ~/projects ~/freelance
```

```
🛡️  enview scan — 4 projects, 6 env files

┌──────────────┬─────────────────┬────────────┬──────┬────────────────┬────────────┬──────────┐
│ Project      │ File            │ Env        │ Keys │ Encrypted      │ .gitignore │ Modified │
├──────────────┼─────────────────┼────────────┼──────┼────────────────┼────────────┼──────────┤
│ echoforge    │ .env            │ development│ 4    │ 🟡 dotenvx 2/4 │ ✅ yes     │ 3d ago   │
│              │ .env.production │ production │ 4    │ 🔒 dotenvx     │ ✅ yes     │ 1w ago   │
├──────────────┼─────────────────┼────────────┼──────┼────────────────┼────────────┼──────────┤
│ my-saas      │ .env            │ development│ 12   │ 🔓 none        │ ❌ NO      │ 2mo ago  │
├──────────────┼─────────────────┼────────────┼──────┼────────────────┼────────────┼──────────┤
│ side-project │ .env            │ development│ 3    │ 🔓 none        │ ✅ yes     │ today    │
└──────────────┴─────────────────┴────────────┴──────┴────────────────┴────────────┴──────────┘
```

### `enview audit` — Security check

Find plaintext secrets, missing `.gitignore` entries, partial encryption, and environment drift — all in one pass.

```bash
enview audit ~/code
enview audit --strict ~/code   # exit code 1 on critical findings (for CI)
```

```
🛡️  enview audit — 6 findings

┌──────────┬────────────┬──────────────────┬──────────────────────────────────────────────┐
│ Level    │ Project    │ File             │ Finding                                      │
├──────────┼────────────┼──────────────────┼──────────────────────────────────────────────┤
│ CRITICAL │ my-saas    │ .env             │ Plaintext .env file is NOT gitignored        │
├──────────┼────────────┼──────────────────┼──────────────────────────────────────────────┤
│ CRITICAL │ my-saas    │ .env             │ 3 sensitive keys in plaintext:               │
│          │            │                  │ STRIPE_SECRET_KEY, DATABASE_PASSWORD…        │
├──────────┼────────────┼──────────────────┼──────────────────────────────────────────────┤
│ WARN     │ echoforge  │ .env             │ Partial encryption — 2/4 keys encrypted      │
├──────────┼────────────┼──────────────────┼──────────────────────────────────────────────┤
│ WARN     │ echoforge  │ .env → .env.prod │ 1 key in .env missing from .env.production   │
└──────────┴────────────┴──────────────────┴──────────────────────────────────────────────┘

  ⚠️  2 critical issue(s) require immediate attention
```

### `enview keys` — Key inventory

List every key name across every project. **Values are never shown.** Encrypted keys get 🔒, plaintext secrets get ⚠️.

```bash
enview keys ~/code
```

```
🔑  enview keys — key inventory (values never shown)

  📁 echoforge
     .env (development)
       🔒 ANTHROPIC_API_KEY
       🔒 DATABASE_URL
       🔓 OLLAMA_HOST
       🔓 APP_NAME

     .env.production (production)
       🔒 ANTHROPIC_API_KEY
       🔒 DATABASE_URL
       🔒 REDIS_URL
       🔓 APP_NAME
```

### `enview drift` — Compare environments

Find keys that exist in one environment but not another. Catches the "works on my machine" deploy failures.

```bash
enview drift ~/code
```

```
👁️  enview drift — environment key comparison

  📁 echoforge
┌─────────────┬──────┬─────────────────┐
│ Key         │ .env │ .env.production │
├─────────────┼──────┼─────────────────┤
│ OLLAMA_HOST │ ✓    │ ✗ missing       │
├─────────────┼──────┼─────────────────┤
│ REDIS_URL   │ ✗    │ ✓               │
└─────────────┴──────┴─────────────────┘
```

### `enview history` — What you already committed

A working-tree scan answers "what is exposed right now". It cannot answer the expensive question: *what did I commit last year and forget?* Deleting a `.env` and gitignoring it changes nothing about the copy in every clone, fork and CI cache — the credential is published until it is rotated.

```bash
enview history ~/code
```

```
🕰️  enview history — 4 risky paths across 3 repos

┌───────────────┬──────────────────────────────────┬─────────────────────────┬─────────────┬───────────────┐
│ Repo          │ Path in history                  │ Kind                    │ Keys        │ Still tracked │
├───────────────┼──────────────────────────────────┼─────────────────────────┼─────────────┼───────────────┤
│ CoachMark     │ .env                             │ environment file        │ 4 sensitive │ no            │
│ PantryPlanner │ android/app/release-keystore.jks │ private key or keystore │ —           │ no            │
└───────────────┴──────────────────────────────────┴─────────────────────────┴─────────────┴───────────────┘
```

Walks `--all`, so a secret on an abandoned branch still counts. Scoped to risky *paths* — env files, private keys, keystores, `.npmrc`, service-account JSON — rather than grepping every blob, because a scan slow enough to be switched off protects nothing. Key names are recovered from historical blobs; values are never returned.

### `enview ui` — Manage them

The one place enview handles values. Everything else — CLI, library, any dashboard reading them — sees names and status only.

```bash
enview ui ~/code
```

Masked values with reveal and copy, add/edit/delete/rename, and one-click remediation for what the scan found: generate a `.env.example` with values stripped, add a file to `.gitignore`. Every write makes a timestamped `.bak` first.

A revealed value re-masks itself after 30 seconds, with the countdown on the button — screen shares and recordings are a likelier way to lose a credential than an attacker is. The mask is a fixed width and no length is ever returned, so a short value and a long one look the same.

**Security model — one user, one machine.** Binds `127.0.0.1`; validates `Host` *and* `Origin` on every request, which is what defeats DNS rebinding; requires a token printed once in your terminal; no CORS, restrictive CSP, no telemetry, no external requests. Only files found by the scan can be touched — an allowlist, not path sanitising. Do not put it behind a tunnel, port-forward or reverse proxy; it has no multi-user concept.

Values cross the wire one key at a time, only when you ask, and are never cached or logged.

### `enview protect` — Keep it that way

Working-tree audit plus history scan, exiting non-zero on anything critical. Built for cron, Task Scheduler or CI — a guard that always exits 0 is decoration.

```bash
enview protect ~/code                 # exits 1 if anything critical
enview protect ~/code --quiet         # silent unless there is something to say
enview protect ~/code --no-history    # much faster; skips the history walk
enview protect ~/code --json          # for automation
```

```
🛡️  enview protect — 4 critical findings
   2 on disk · 2 in git history
```

Findings deduplicate across the two scans: when history has the real answer, the working-tree inference is dropped rather than reported twice.

<details>
<summary>Run it on a schedule</summary>

```bash
# cron — 9am daily
0 9 * * * npx @pickbitsai/enview protect ~/code --quiet

# Windows Task Scheduler
schtasks /create /tn "enview protect" /tr "npx @pickbitsai/enview protect C:\code --quiet" /sc daily /st 09:00
```
</details>

## CI Integration

Use `--json` for machine-readable output and `--strict` to fail builds:

```yaml
# GitHub Actions
- name: Audit secrets
  run: npx @pickbitsai/enview audit --strict --json . > audit-results.json
```

```yaml
# GitLab CI
audit:secrets:
  script:
    - npx @pickbitsai/enview audit --strict .
  allow_failure: false
```

## What It Detects

| Detection | Description |
|-----------|-------------|
| **Plaintext secrets** | API keys, tokens, passwords stored without encryption |
| **Missing .gitignore** | `.env` files that could be committed to version control |
| **Partial encryption** | Files where some keys are encrypted but others aren't |
| **Environment drift** | Keys present in dev but missing in production (or vice versa) |
| **Encryption type** | Identifies dotenvx, SOPS, age, and other encryption schemes |
| **Sensitive key patterns** | Flags keys matching `*_API_KEY`, `*_SECRET`, `*_PASSWORD`, `*_TOKEN`, etc. |

## Why AI-Safety Matters

AI coding agents (Claude Code, Cursor, Copilot, Aider) run in your terminal with access to your filesystem. A plaintext `.env` file is trivially readable by any process — including AI agents, npm postinstall scripts, and supply chain attacks.

enview helps you answer: **"Which of my projects have secrets that an AI agent could read right now?"**

Pair it with [dotenvx](https://dotenvx.com) to encrypt everything it flags.

## Options

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (all commands) |
| `--strict` | Exit code 1 on critical findings (audit only) |
| `-d, --depth <n>` | Max directory depth (default: 6) |

## Encryption Detection

enview automatically identifies:

- **[dotenvx](https://dotenvx.com)** — `encrypted:` prefix with `DOTENV_PUBLIC_KEY` header
- **[SOPS](https://github.com/getsops/sops)** — `ENC[AES256_GCM,...]` values or `sops` metadata
- **[age](https://github.com/FiloSottile/age)** — `age-encryption.org` markers

## Ignores (by default)

- `node_modules`, `.git`, `vendor`, `dist`, `build`, `target`, etc.
- `.env.example`, `.env.sample`, `.env.template`
- `.env.keys` (dotenvx private key files — never scanned)

## Contributing

PRs welcome. Some ideas:

- [ ] `enview rotate` — Track key rotation history via git log
- [ ] `enview init` — Bootstrap dotenvx encryption for unprotected projects
- [ ] `enview watch` — File watcher that alerts on new plaintext secrets
- [ ] TUI dashboard mode (blessed/ink)
- [ ] 1Password / Bitwarden vault cross-reference
- [ ] Pre-commit hook integration
- [ ] `.enviewrc` config file for custom scan roots

## License

MIT
