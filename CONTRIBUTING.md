# Contributing

Thanks for taking the time to contribute! This is a small project — issues and pull requests are welcome.

## Reporting bugs

Before opening an issue, please check the [existing issues](../../issues) to avoid duplicates.

When filing a bug report, include:
- What you were doing
- What you expected to happen
- What actually happened (error messages, screenshots, network responses)
- Browser / OS, Cloudflare plan (Free / Pro / Biz / Ent), and roughly how many WAF events your zone produces per day

For **security vulnerabilities**, please follow [SECURITY.md](SECURITY.md) instead.

## Suggesting features

Open an issue describing the use case. Keep in mind the project's scope:

- Multi-account WAF event dashboard
- Must keep working on the **Cloudflare Free tier**
- No build step (vanilla HTML/JS frontend, TypeScript Worker)
- No backing database — everything is computed on demand from the Cloudflare GraphQL API + Worker Cache API

Features that would require a paid CF plan, a build pipeline, or persistent storage are unlikely to be merged into the core. They are great candidates for forks.

## Development setup

Use Node.js 22 or newer (CI runs Node.js 22).

```powershell
git clone https://github.com/<your-fork>/cloudflare-waf-log.git
cd cloudflare-waf-log
npm ci

# Create .dev.vars with at least one account (NEVER commit this file)
@'
CFACC_PERSONAL_LABEL=My account
CFACC_PERSONAL_ACCOUNT=00000000000000000000000000000000
CFACC_PERSONAL_TOKEN=cf_xxx
ALLOW_UNAUTHENTICATED_LOCAL_DEV=true
'@ | Out-File -Encoding utf8 .dev.vars

npm run dev
```

Open <http://localhost:8787>.

See the [README](README.md#cloudflare-api-token--how-to-create-one) for token creation instructions.

## Coding conventions

- **TypeScript** (Worker) — strict mode, no unused vars, no `any` unless interfacing with untyped GraphQL responses.
- **Vanilla JS** (frontend) — no framework, no build step. Keep it dependency-free.
- **2 spaces** indentation everywhere.
- **Comments in English**, kept short and useful (explain *why*, not *what*).
- **No emojis in code** (the one in the dashboard title is intentional).
- **Avoid over-engineering** — this is a small dashboard, not a platform. Don't add abstractions for one-time operations.

Run the same checks as CI, including a production dry-run and dependency audit, before pushing:

```powershell
npm run check:ci
```

This runs `npm run check`, `npm run deploy:dry-run`, and `npm audit --audit-level=high`.
The audit includes development tools because they execute during development and deployment.
It can fail on a newly disclosed dependency vulnerability even when all tests pass.
Update the affected upstream dependency and commit both `package.json` and `package-lock.json`;
do not bypass the audit or use `npm audit fix --force` to make CI pass.
CI also runs daily at 06:17 UTC on `main` to detect new advisories without waiting for a PR,
and can be started manually from GitHub Actions.

For async UI regression tests, wait for the mocked response to finish processing before asserting
that stale data was ignored. Verify that removing the relevant guard makes the test fail.
Close JSDOM windows in `afterEach` so cleanup also runs after a failed assertion.

## Pull request process

1. **Fork** the repo and create a feature branch from `main`.
2. **Make your change.** Keep the diff focused — one logical change per PR.
3. **Update [README.md](README.md)** if you add/change a user-visible feature or an API endpoint.
4. **Test locally** with `npm run dev`. Verify the dashboard still loads and the affected feature works end-to-end. Run `npm run check:ci` for the automated checks, Wrangler dry-run, and dependency audit.
5. **Open a PR** against `main`. The PR title becomes the squash-merge commit message, so make it descriptive (e.g. `Add CSV export filter for ASN`).
6. **Wait for review.** Copilot code review runs automatically; a maintainer will follow up.

PRs are merged via **squash merge** so each PR produces exactly one commit on `main`.

## Commit messages

Use the imperative mood ("Add X", "Fix Y", not "Added"/"Fixes"). Keep the first line under ~72 chars. Body optional but appreciated for non-trivial changes.

## License

By submitting a contribution, you agree that your code will be released under the same [MIT License](LICENSE) as the rest of the project.
