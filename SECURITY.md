# Security Policy

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Instead, report them privately via **GitHub Private Vulnerability Reporting**:

1. Go to the [Security tab](../../security/advisories/new) of this repository
2. Click **Report a vulnerability**
3. Describe the issue with as much detail as possible (reproduction steps, impact, suggested fix if any)

You should receive an acknowledgement within a few days. Once the issue is confirmed and fixed, a security advisory will be published and you will be credited (unless you prefer to remain anonymous).

## Supported versions

Only the latest commit on the `main` branch is actively maintained. There are no long-term support branches.

## Scope

In-scope:
- The Worker code in [`src/`](src/)
- The dashboard frontend in [`public/`](public/)
- Configuration handling (secrets, Worker bindings)

Out of scope:
- Vulnerabilities in third-party dependencies — please report those upstream (Cloudflare, Chart.js, etc.)
- Misconfiguration of your own Cloudflare Access policy or API tokens
- Social engineering, physical attacks, denial-of-service against Cloudflare itself

## Security model recap

This project relies on:

- **Cloudflare Access** in front of the Worker — without it, the dashboard would be public. The README explicitly requires it.
- **Read-only Cloudflare API tokens** stored as Worker secrets — never committed to the repo, never sent to the browser.
- **CSV-injection escaping** on raw event export (`=+-@\t\r` are prefixed with `'`).
- **HTML escaping** of all user-controlled strings rendered into the DOM.

If you find a way around any of these, please report it via the channel above.
