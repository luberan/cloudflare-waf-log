# Cloudflare WAF Dashboard

Cloudflare Worker, který vizualizuje WAF / Security events napříč **více Cloudflare účty** (vlastní + zákaznické).
Funguje na **Free tieru** (retence eventů 24 h).

## Co umí

- **Přepínání mezi Cloudflare účty** — každý účet má svůj API token
- Přepínání mezi zónami v rámci zvoleného účtu
- Filtrování podle akce: `block`, `managed_challenge`, `jschallenge`, `challenge`, `allow`, `log`, `skip`
- Filtrování podle zemí (ISO2) a hostname
- Časový rozsah 1 / 6 / 24 h (Free tier — víc retence nedá)
- KPI karty + grafy: stacked time series, podle akce, top země, top hostnames, zdroj (`source`), top rule IDs
- Tabulka s posledními ~500 eventy

## Architektura

| Část | Soubor | Co dělá |
|---|---|---|
| Worker (TypeScript) | [src/index.ts](src/index.ts) | API endpointy `/api/accounts`, `/api/zones`, `/api/log`, `/api/stats` — proxy na Cloudflare GraphQL Analytics API |
| Dashboard | [public/index.html](public/index.html) | Vanilla HTML/JS + Chart.js z CDN (žádný build step) |
| Konfigurace | [wrangler.jsonc](wrangler.jsonc) | Worker entrypoint + assets binding (nic citlivého) |

## Konfigurace tajemství

**Vše citlivé je jen ve Worker secretech.** V repu ani ve `wrangler.jsonc` nic není.

Pro **každý CF účet** vytvoř TŘI secrety:

| Secret name | Popis | Příklad |
|---|---|---|
| `CFACC_<ID>_LABEL` | Co se ukáže v UI dropdownu | `Můj účet` |
| `CFACC_<ID>_ACCOUNT` | Cloudflare Account ID (32 hex znaků) | `abc123abc123...` |
| `CFACC_<ID>_TOKEN` | Cloudflare API token (read-only) | `cf_xxx...` |

`<ID>` je libovolný krátký identifikátor, který si zvolíš (`PERSONAL`, `ACME`, `NOVA`, …). Objevuje se v URL `?account=<id>` (Worker ho normalizuje na lowercase).

**Přidání nového účtu** = vytvoříš tři nové secrety. Žádné existující se nemění a nemusíš nikam ukládat staré tokeny.
**Rotace tokenu** = přepíšeš jen `CFACC_<ID>_TOKEN`.

### Cloudflare API token — jak ho vytvořit (nové UI 2026)

1. **Cloudflare dashboard → My Profile → API Tokens → Create Token → Custom token**
2. Pojmenuj např. `waf-log-acme`
3. **Permission policy** → klikni na resource selector a vyber **Entire Account** (pro daný účet)
4. V kategoriích zaškrtni:
   - **Analytics & Logs → Analytics : Read**
   - **DNS & Zones → Zone : Read**
5. *(volitelně)* Client IP filtering, TTL — můžeš nechat default
6. **Continue → Create Token** → zkopíruj token (zobrazí se jen jednou)

> **Pozor**: token vždy generuj **přepnutý do toho účtu, jehož data chceš číst** (přepínač účtu vlevo nahoře v CF dashboardu). Token je vázaný na účet, kde byl vytvořen.

## Setup

### Lokální vývoj

```powershell
npm install

# Vytvoř .dev.vars (NEcommitovat — je v .gitignore).
@'
CFACC_PERSONAL_LABEL=Můj účet
CFACC_PERSONAL_ACCOUNT=abc123abc123abc123abc123abc123
CFACC_PERSONAL_TOKEN=cf_xxx
'@ | Out-File -Encoding utf8 .dev.vars

npm run dev
```

Otevři <http://localhost:8787>.

### Produkce — Worker secrets

V dashboardu: **Workers & Pages → tvůj Worker → Settings → Variables and Secrets → Add → Type: Secret**

Pro každý účet přidej tři secrety (`CFACC_<ID>_LABEL`, `CFACC_<ID>_ACCOUNT`, `CFACC_<ID>_TOKEN`).
Po přidání všech klikni **Deploy** (jednou — aplikuje všechny najednou).

Nebo přes CLI:
```powershell
"Můj účet"  | npx wrangler secret put CFACC_PERSONAL_LABEL
"abc123..."  | npx wrangler secret put CFACC_PERSONAL_ACCOUNT
"cf_xxx..." | npx wrangler secret put CFACC_PERSONAL_TOKEN
```

### Deploy přes GitHub → Cloudflare Workers Builds

1. Push repo na GitHub.
2. **Workers & Pages → Create → Workers → Connect to Git**, vyber repo.
3. Build command: *(prázdné)*, Deploy command: `npx wrangler deploy`.
4. Po prvním deployi přidej secrety (viz výše).
5. Každý push do `main` od teď spustí auto deploy.

### Ochrana přístupu — Cloudflare Access (Zero Trust)

Worker je veřejný — proto MUSÍ být před ním Access policy:

1. **Zero Trust dashboard → Access → Applications → Add application → Self-hosted**
2. Domain: `<worker-name>.<tvuj-subdomain>.workers.dev`
3. Policy: `Allow` pro tvůj email (One-time PIN / Google / GitHub IdP)

## Omezení Free tieru

- **Retence WAF eventů**: 24 h (Pro 72 h, Biz 30 d, Ent 6 m)
- **Worker quoty**: 100 000 req/den, 10 ms CPU
- **GraphQL**: ~1 200 req/5 min na token (každý účet má vlastní)

## Bezpečnostní poznámky

- Tokeny mají read-only práva — i v případě úniku secretů nelze nic v CF účtech měnit
- Frontend nikdy nedostane token — `GET /api/accounts` vrací jen `id` + `label`
- Worker musí být za Cloudflare Access — jinak je dashboard veřejný
- `.dev.vars` je v [.gitignore](.gitignore)

## Možná rozšíření

- Cache odpovědí GraphQL v KV / Cache API
- Export do CSV
- Cron Trigger → ukládat agregace do D1/R2 pro historii delší než 24 h
- Alerting webhook (Slack/Discord) při překročení prahu blokovaných requestů
