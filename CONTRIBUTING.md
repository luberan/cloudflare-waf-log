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

```powershell
git clone https://github.com/<your-fork>/cloudflare-waf-log.git
cd cloudflare-waf-log
npm install

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

Run the full automated check and a production dry-run before pushing:

```powershell
npm run check
npm run deploy:dry-run
```

## Pull request process

1. **Fork** the repo and create a feature branch from `main`.
2. **Make your change.** Keep the diff focused — one logical change per PR.
3. **Update [README.md](README.md)** if you add/change a user-visible feature or an API endpoint.
4. **Test locally** with `npm run dev`. Verify the dashboard still loads and the affected feature works end-to-end. CI also runs `npm run check`, the Wrangler dry-run, and `npm audit`.
5. **Open a PR** against `main`. The PR title becomes the squash-merge commit message, so make it descriptive (e.g. `Add CSV export filter for ASN`).
6. **Wait for review.** Copilot code review runs automatically; a maintainer will follow up.

PRs are merged via **squash merge** so each PR produces exactly one commit on `main`.

## Commit messages

Use the imperative mood ("Add X", "Fix Y", not "Added"/"Fixes"). Keep the first line under ~72 chars. Body optional but appreciated for non-trivial changes.

## License

By submitting a contribution, you agree that your code will be released under the same [MIT License](LICENSE) as the rest of the project.
