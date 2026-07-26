# Contributing

Thanks for looking. enview is small on purpose — a scanner, a reporter, a local UI — so most changes are self-contained.

```bash
git clone https://github.com/MrPickering/enView.git
cd enView
npm install
npm test          # 37 checks, no network access required
node bin/enview.js scan .
```

## Before you open a PR

- `npm test` passes on your platform. If your change touches git behaviour, say which platform you ran on — several bugs here have been platform-specific.
- `node bin/enview.js protect .` exits 0, so the repo does not flag itself.
- No real secret appears anywhere, including in a test fixture. Fixtures that must *look* like credentials carry a `// gitleaks:allow` comment explaining why.

## The one rule that is not negotiable

**No API may return a secret value, except `enview ui`.**

`scan`, `audit`, `keys`, `drift`, `history` and the library API read values only to classify them, then discard them. They return key names, counts, encryption status, git status and timestamps. This is what lets people pipe `--json` into a CI log or embed the library in a dashboard without thinking about it, and it is a promise made in the README and SECURITY.md.

`enview ui` is the deliberate exception, because managing a value requires seeing it. Anything added there needs to hold the security model in SECURITY.md: localhost bind, Host and Origin validation, token, no CORS, backup before write, allowlist rather than path sanitising.

## Testing git behaviour

Shell out with `execFileSync('git', [...args])`, never a command string. Two reasons, both learned the hard way:

- A string needs `2>/dev/null` to stay quiet, and `cmd.exe` cannot resolve that path. That made `git check-ignore` throw on every Windows invocation, the catch set `ignored = false`, and **every file in every project reported "NOT gitignored"** — the most important signal in the audit was a permanent false alarm.
- Quoting differs between platforms, and argv does not need quoting.

Ask git the question you actually mean. `tracked` used to be inferred from `git log -- <file>`, which matches anything that ever appeared in history including files since removed — three of six real files were reported tracked when git did not track them. `git ls-files --error-unmatch` answers "tracked right now"; `git log` answers "was ever committed". Both matter, and they need different remedies.

## Testing the server

Test `Host` validation with `node:http`, not `fetch`. `fetch` treats `Host` as a forbidden header and silently drops it, so the request arrives with the real host and the test passes while proving nothing.

If the UI renders blank, check the Content Security Policy before anything else. `default-src 'none'` blocks the page's own `fetch` calls unless `connect-src 'self'` is present — and every API-level test still passes while the page is empty.

## Reporting a scan bug

Include a **synthetic** reproduction: a throwaway directory, the `.env` shape that triggered it, and what you expected. Never attach a real report — key names reveal your stack and paths reveal your layout. See SECURITY.md.
