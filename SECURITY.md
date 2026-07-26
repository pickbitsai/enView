# Security policy

## Supported versions

Security fixes are applied to the latest version on the default branch.

## Reporting a vulnerability

Please do not open a public issue containing real secrets, key names, local paths, or exploit details. Use GitHub Private Vulnerability Reporting when it is enabled for this repository. If it is unavailable, contact the maintainer through a private channel listed on the repository owner's profile, and include a minimal reproduction built from **synthetic** values.

You should receive an acknowledgement within seven days. Please allow time for a fix before public disclosure.

## What this tool does with your secrets

This matters more here than in most projects, so it is stated precisely.

**The scanner, the CLI, and the library API never return a secret value.** Values are read only to classify them — is this encrypted? is it a placeholder? does the key *name* look like a credential? — and are then discarded. What comes back is key names, counts, encryption status, git status and timestamps. That is what makes `enview scan --json` safe to pipe into a CI log or a dashboard.

**`enview ui` is the one exception, and deliberately the only one.** It is a local management interface, so it can reveal and edit values. Its security model:

- binds `127.0.0.1` only
- validates the `Host` **and** `Origin` headers on every request — this is what defeats DNS rebinding, where a remote page resolves its own domain to `127.0.0.1` to read your files through your browser
- requires a token, generated per run and printed once in your terminal
- sends no CORS headers; sets a restrictive Content Security Policy that permits no outbound connection except back to itself
- serves `Cache-Control: no-store`, so revealed values are not written to a browser disk cache
- returns one value per request, only when explicitly asked
- can only touch files that the scan discovered — an allowlist, not path sanitising
- writes a timestamped `.bak` before every modification
- makes no external network request and collects no telemetry

It has no concept of multiple users and is not built to be exposed. **Do not place it behind a tunnel, port-forward, reverse proxy, or any public network interface.**

## Nothing leaves your machine

enview makes no network requests. It does not phone home, check for updates, or transmit findings. Everything it reports is derived from your local filesystem and local `git`.

Note that this is also its limitation: enview can tell you a credential is exposed, but not whether it is still *live*. For that, a verifying scanner such as [TruffleHog](https://github.com/trufflesecurity/trufflehog) sends the credential to the issuing service to test it — a deliberate outbound action you should opt into knowingly.

## Reports and backups

`--json` output contains key names and file paths. Both are sensitive: a key name reveals which services you use, and a path reveals your layout. Treat a saved report as confidential, and do not attach one to a public issue.

`.bak` files written by `enview ui` contain the values that were in the file before your edit — including any secret you just rotated away. They are ordinary files next to the original: make sure your `.gitignore` covers `*.bak.*`, and delete them once you no longer need the rollback.
