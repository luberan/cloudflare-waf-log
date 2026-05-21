# Cloudflare WAF Dashboard

Cloudflare Worker, který vizualizuje WAF / Security events napříč **více Cloudflare účty** (vlastní + zákaznické).
Plně funkční na **Free tieru** (retence WAF eventů 24 h).

## Co umí

- **Přepínání mezi Cloudflare účty** — každý účet má svůj API token uložený jako Worker secret
- **Přepínání mezi zónami** v rámci zvoleného účtu
- Filtrování podle:
  - **akce** (chipy: `block`, `managed_challenge`, `jschallenge`, `challenge`, `allow`, `log`, `skip`)
  - **hostname** (např. `www.example.com`)
  - **cesty** (např. `/wp-login.php`)
  - **Rule ID** (UUID firewall pravidla, comma-separated)
  - **země** (ISO2 kódy: `CZ,DE,RU,...`)
  - **ASN** (Čísla AS, comma-separated: `13335,15169`)
  - **User-Agent** (přesná shoda)
- Časový rozsah: posledních **1 / 6 / 24 h** (Free tier — víc retence Cloudflare neukládá)
- **KPI karty**: celkem / blokované / challenge / allow+log
- **Grafy**:
  - Stacked time series (eventy po hodině, barevně rozdělené dle akce)
  - Doughnut podle akce
  - Top 15 zemí (horizontal bar)
  - Top 15 hostnames
  - Doughnut podle zdroje (`waf`, `firewallrules`, `botManagement`, …)
- **Tabulky**:
  - Top 30 Rule IDs *(klik = filtr na Rule ID)*
  - Top 50 cest *(klik = filtr na Cestu)*
  - Top 50 ASN *(klik = filtr na ASN)*
  - Top 50 User-Agents *(klik = filtr na UA)*
  - Posledních ~500 eventů (čas, akce, IP, ASN, země, host, cesta, metoda, rule, ray ID)
- **Vyčistit filtry** — jedním tlačítkem zruší všechny chipy a inputy
- **Export CSV** — stažení raw eventů s aktuálně nastavenými filtry (až 10 000 řádků, UTF-8 + BOM, otevře se rovnou v Excelu)

## Architektura

| Část | Soubor | Co dělá |
|---|---|---|
| Worker (TypeScript) | [src/index.ts](src/index.ts) | API endpointy — proxy na Cloudflare GraphQL Analytics API |
| Dashboard | [public/index.html](public/index.html) | Vanilla HTML/JS + Chart.js z CDN (žádný build step) |
| Konfigurace | [wrangler.jsonc](wrangler.jsonc) | Worker entrypoint + assets binding + vypnutí default domén |

### API endpointy

| Endpoint | Popis |
|---|---|
| `GET /api/accounts` | Seznam nakonfigurovaných účtů (jen `id` + `label`, nikdy token) |
| `GET /api/zones?account=<id>` | Seznam zón daného účtu |
| `GET /api/stats?account=<id>&zone=<id>&...filters` | Agregace + posledních 500 eventů (vše v jednom requestu) |
| `GET /api/log?account=<id>&zone=<id>&...filters` | Jen eventy (limit ovládatelný přes `&limit=`) |
| `GET /api/export.csv?account=<id>&zone=<id>&...filters` | CSV export raw eventů (až 10 000 řádků, `Content-Disposition: attachment`) |

### Pozn. k Free tieru — agregace v Workeru

Cloudflare dataset `firewallEventsAdaptiveGroups` (server-side agregace) **vyžaduje Pro+ plán**. Na Free je dostupný jen `firewallEventsAdaptive` (raw eventy, 24 h, max 10 000 řádků per request). Worker proto stahuje raw eventy a všechny statistiky (`byAction`, `byCountry`, `byHost`, `byPath`, `byRule`, `bySource`, `series`) počítá JS-em. V odpovědi je `totalSampled` a `truncated` — pokud zóna překročí 10 000 eventů za 24 h, dashboard tě upozorní, že statistiky jsou ze sample.

## Konfigurace tajemství

**Vše citlivé je jen ve Worker secretech.** V repu ani ve `wrangler.jsonc` nic citlivého není.

Pro **každý CF účet** vytvoř TŘI secrety:

| Secret name | Popis | Příklad |
|---|---|---|
| `CFACC_<ID>_LABEL` | Co se ukáže v UI dropdownu | `Můj účet` |
| `CFACC_<ID>_ACCOUNT` | Cloudflare Account ID (32 hex znaků) | `b151c3e2ed3c7da7c439c74fb09fad63` |
| `CFACC_<ID>_TOKEN` | Cloudflare API token (read-only, viz níže) | `cf_xxx...` |

`<ID>` je libovolný krátký identifikátor (`PERSONAL`, `ACME`, `NOVA`, …). Objevuje se v URL `?account=<id>`. Worker interně normalizuje na lowercase.

**Přidání nového účtu** = vytvoříš tři nové secrety. Žádné existující se nemění, nemusíš znát staré tokeny.
**Rotace tokenu** = přepíšeš jen `CFACC_<ID>_TOKEN`.
**Smazání účtu** = smaž jeho tři secrety.

### Cloudflare API token — jak ho vytvořit

> **Přepni se nejdřív do toho účtu**, jehož data chceš číst (levý horní roh dashboardu). Token je vázaný na účet, kde byl vytvořen — token vytvořený na jiném účtu nebude vidět cizí zóny.

1. **My Profile → API Tokens → Create Token → Custom token**
2. **Token name**: např. `waf-log-personal`
3. **Permission policy** — vlevo nahoře v selectoru Resources zvol **All Domains**
   *(NE "Entire Account" — pod tím nejsou zone-level permissiony jako Zone:Read a Zone Analytics:Read)*
4. V kategoriích zaškrtni:
   - **DNS & Zones → Zone : Read**
   - **Analytics & Logs → Analytics : Read**
5. *(volitelně)* Client IP filtering, TTL — nech default
6. **Continue → Create Token** → zkopíruj (zobrazí se jen jednou)

## Setup

### Lokální vývoj

```powershell
npm install

# Vytvoř .dev.vars (NEcommitovat — je v .gitignore).
@'
CFACC_PERSONAL_LABEL=Můj účet
CFACC_PERSONAL_ACCOUNT=b151c3e2ed3c7da7c439c74fb09fad63
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

1. Push repo na GitHub
2. **Workers & Pages → Create → Workers → Connect to Git**, vyber repo
3. Build settings:
   - **Build command**: *(prázdné — žádný build není potřeba)*
   - **Deploy command**: `npx wrangler deploy`
   - **Non-production deploy command**: `npx wrangler versions upload`
   - **Builds for non-production branches**: nech vypnuté (preview URL jsou stejně zakázané v configu)
4. Po prvním deployi přidej secrety (viz výše)
5. Každý push do `main` od teď spustí auto deploy

### Custom doména

`*.workers.dev` URL je vypnutá ([wrangler.jsonc](wrangler.jsonc) — `workers_dev: false`), takže Worker je přístupný pouze přes custom doménu. Nastavení:

1. **Worker → Settings → Domains & Routes → Add → Custom Domain**
2. Zadej doménu, např. `cf.tvojedomena.cz` (musí být zóna v CF na stejném účtu jako worker)
3. CF automaticky vytvoří `CNAME` a TLS cert

### Ochrana přístupu — Cloudflare Access (Zero Trust)

Worker je bez ochrany veřejný a vystavoval by data všech zákaznických účtů. **MUSÍ být za Access:**

1. **Zero Trust dashboard → Access → Applications → Add application → Self-hosted**
2. Application domain: `cf.tvojedomena.cz` (custom doména z předchozího kroku)
3. Path: nech prázdné (chrání celý hostname včetně `/api/*`)
4. **Policy** → Add policy:
   - Action: `Allow`
   - Include: `Emails: tvuj@email.cz` (nebo IdP group, …)
5. Save & deploy aplikaci

Bez platné Access session vrátí Worker 302 na CF Access login page.

## Důležité — vypnutí default domén

V [wrangler.jsonc](wrangler.jsonc) jsou natvrdo:
- `workers_dev: false` — vypíná `<worker>.<subdomain>.workers.dev`
- `preview_urls: false` — vypíná preview URL z `wrangler versions upload`

Bez toho Wrangler při každém deployi default domény znovu zapne, což by obešlo Access (preview URL nemá Access policy nastavenou). Pokud potřebuješ default doménu zase zapnout, smaž tyhle řádky z configu.

## Omezení Free tieru

- **Retence WAF eventů**: 24 h (Pro 72 h, Biz 30 d, Ent 6 m) — limit Cloudflare, ne tohoto kódu
- **Max 10 000 eventů per request** — pokud zóna překročí, statistiky jsou ze sample (vidíš varování `truncated: true` v response)
- **Worker quoty**: 100 000 req/den, 10 ms CPU
- **GraphQL rate limit**: ~1 200 req/5 min na token (každý účet má vlastní → škáluje s počtem účtů)
- **`firewallEventsAdaptiveGroups` (server-side agregace) je Pro+ only** — proto Worker agreguje raw eventy v JS

## Bezpečnostní poznámky

- Tokeny mají read-only práva — i v případě úniku secretu nelze v CF účtech nic měnit
- Frontend nikdy nedostane token — `GET /api/accounts` vrací jen `id` + `label`
- Worker musí být za Cloudflare Access — bez něj je dashboard veřejný
- `.dev.vars` je v [.gitignore](.gitignore)

## Možná rozšíření

- Cache odpovědí GraphQL v KV / Cache API
- Cron Trigger → ukládat agregace do D1/R2 pro historii delší než 24 h
- Alerting webhook (Slack/Discord) při překročení prahu blokovaných requestů