# Cloudflare WAF Dashboard

Cloudflare Worker, který vizualizuje WAF / Security events napříč **více Cloudflare účty** (vlastní + zákaznické).
Funguje na **Free tieru** (retence eventů 24 h).

## Co umí

- **Přepínání mezi Cloudflare účty** (vlastní i zákaznické) — každý účet má svůj API token
- Přepínání mezi zónami v rámci zvoleného účtu
- Filtrování podle akce: `block`, `managed_challenge`, `jschallenge`, `challenge`, `allow`, `log`, `skip`
- Filtrování podle zemí (ISO2, např. `CZ,DE,RU`) a hostname
- Časový rozsah 1 / 6 / 24 h (Free — víc retence nemá)
- KPI karty + grafy: stacked time series, podle akce, top země, top hostnames, zdroj (`source`), top rule IDs
- Tabulka s posledními ~500 eventy (čas, akce, IP, země, host, cesta, ray ID, …)

## Architektura

| Část | Soubor | Co dělá |
|---|---|---|
| Worker (TypeScript) | [src/index.ts](src/index.ts) | API endpointy `/api/accounts`, `/api/zones`, `/api/events`, `/api/summary` — proxy na Cloudflare GraphQL Analytics API |
| Dashboard | [public/index.html](public/index.html) | Vanilla HTML/JS + Chart.js z CDN (žádný build step) |
| Konfigurace | [wrangler.jsonc](wrangler.jsonc) | Worker entrypoint + assets binding (nic citlivého) |

## Konfigurace tajemství

**Vše citlivé je v jednom Worker secretu** `ACCOUNTS` — JSON pole. V repu ani ve `wrangler.jsonc` nic není.

Příklad obsahu `ACCOUNTS`:

```json
[
  {
    "id": "personal",
    "label": "Můj účet",
    "accountId": "abc123abc123abc123abc123abc123",
    "token": "cf_token_xxx"
  },
  {
    "id": "acme",
    "label": "ACME s.r.o.",
    "accountId": "def456def456def456def456def456",
    "token": "cf_token_yyy"
  }
]
```

Klíče:
- `id` — krátký interní identifikátor (objevuje se v URL `?account=...`)
- `label` — co se zobrazí v UI dropdownu
- `accountId` — Cloudflare Account ID (najdeš v CF dashboardu vpravo dole u libovolné zóny daného účtu)
- `token` — API token vygenerovaný **v rámci toho účtu** s těmito právy:

| Scope | Resource | Permission |
|---|---|---|
| Account | tento účet | `Account Analytics: Read` |
| Zone | All zones (toho účtu) | `Zone: Read` |
| Zone | All zones (toho účtu) | `Analytics: Read` |

> U zákaznických účtů si nech token vygenerovat zákazníkem (nebo na účtu admin) — token pak vloží jako další položku pole.

## Setup

### Lokální vývoj

```powershell
npm install

# Vytvoř .dev.vars (NEcommitovat — je v .gitignore).
# Hodnota MUSÍ být na jednom řádku, jinak ji Wrangler nepřečte:
'ACCOUNTS=[{"id":"personal","label":"Můj účet","accountId":"abc...","token":"cf_xxx"}]' `
  | Out-File -Encoding utf8 .dev.vars

npm run dev
```

Otevři <http://localhost:8787>.

### Produkce — Worker secret

```powershell
npx wrangler secret put ACCOUNTS
# pak vlož JSON (na jednom řádku) a stiskni Enter / Ctrl+Z
```

Nebo v dashboardu: **Workers & Pages → tvůj Worker → Settings → Variables and Secrets → Add → Type: Secret → Name: `ACCOUNTS`**.

> Po každé změně `ACCOUNTS` (přidání nového účtu, rotace tokenu) jen znovu nahraj secret — kód redeployovat nemusíš.

### Deploy přes GitHub → Cloudflare Workers Builds

1. Push repo na GitHub.
2. **Workers & Pages → Create → Workers → Connect to Git**, vyber repo.
3. Build settings (Workers Builds detekuje automaticky):
   - Build command: *(prázdné)*
   - Deploy command: `npx wrangler deploy`
4. Po prvním deployi nastav secret `ACCOUNTS` (viz výše).
5. Každý push do `main` od teď spustí auto deploy.

### Ochrana přístupu — Cloudflare Access (Zero Trust)

Worker sám o sobě je veřejný — proto MUSÍ být před ním Access policy, jinak by k datům zákazníků mohl kdokoliv se znalostí URL:

1. **Zero Trust dashboard → Access → Applications → Add application → Self-hosted**
2. Domain: `<worker-name>.<tvuj-subdomain>.workers.dev` (nebo custom doména)
3. Policy: `Allow` pro tvůj email (One-time PIN / Google / GitHub IdP)
4. Hotovo — bez autentizace IdP nikdo na dashboard nedosáhne.

## Omezení Free tieru

- **Retence WAF eventů**: 24 h (Pro 72 h, Biz 30 d, Ent 6 m) — per zóna, ne per účet
- **Worker quoty**: 100 000 req/den, 10 ms CPU
- **GraphQL**: rate limit ~1 200 req/5 min na token (každý účet má vlastní → škáluje s počtem účtů)

## Bezpečnostní poznámky

- Tokeny v `ACCOUNTS` mají read-only práva — i v případě úniku secretu nelze nic v CF účtech měnit
- Frontend nikdy nedostane token — `GET /api/accounts` vrací jen `id` + `label`
- Worker je za Cloudflare Access — nikdo neautentizovaný se k API nedostane
- `.dev.vars` je v [.gitignore](.gitignore)

## Možná rozšíření

- Cache odpovědí GraphQL v KV / Cache API
- Export do CSV
- Cron Trigger → ukládat agregace do D1/R2 pro historii delší než 24 h
- Alerting webhook (Slack/Discord) při překročení prahu blokovaných requestů
