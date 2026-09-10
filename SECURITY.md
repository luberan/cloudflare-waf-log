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

- **Cloudflare Access** in front of the Worker plus mandatory in-code JWT verification for every API request. Missing production JWT configuration fails closed with `503`.
- **Zone ownership checks** through the Cloudflare REST API before every zone-scoped operation, including cache hits. A token with broader permissions does not grant access to zones outside the configured account.
- **JWT time validation** rejects expired tokens, tokens at their expiration boundary, and tokens with a future or malformed not-before claim.
- **Read-only Cloudflare API tokens** stored as Worker secrets — never committed to the repo, never sent to the browser.
- **Credential-scoped analytics caches** use the actual account identity, a non-plaintext credential fingerprint and exact time bounds. Token rotation or account reassignment changes the cache scope. For immediate invalidation after an in-place permission edit, rotate the token or purge cached data.
- **CSV-injection escaping** on raw event export (`=+-@\t\r` are prefixed with `'`).
- **HTML escaping** of all user-controlled strings rendered into the DOM.
- **Worker-first static asset handling** so CSP, `frame-ancestors 'none'`, `X-Frame-Options`, and the other security headers are applied to every asset.

`ALLOW_UNAUTHENTICATED_LOCAL_DEV=true` is exclusively for local `.dev.vars` and is honored only on `localhost`/loopback request URLs. It cannot disable authentication on a deployed hostname. All identities admitted by one Access application can read all Cloudflare accounts configured in that Worker.

If you find a way around any of these, please report it via the channel above.
