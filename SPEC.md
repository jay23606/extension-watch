# Extension Watch: specification (Galuxium Nexus V2 hackathon, SaaS)

_Original build spec. The README describes the current version._

Problem: every company runs dozens of Chrome extensions it never reviewed. An extension that was harmless when installed can
gain "read all your data on all websites" in a silent update. Security teams have no cheap way to see which extensions their
staff use, what each one can do, and when that changes.

Extension Watch: a team pastes the extension IDs its staff use (or the Chrome Web Store URLs, or a Chrome policy export).
The service downloads each extension's current package from Google's public update service, reads its manifest, scores the
risk with a transparent rule set, and keeps a snapshot. A daily check compares new versions with the last snapshot and raises
an alert when an update adds permissions or site access. Built by Michael Lip, who maintains 108 Chrome extensions with
more than 150,000 users.

Runtime: Cloudflare Workers + Workers KV (one record per watchlist, one shared record per extension per day) + a Cron Trigger every 10 minutes that re-checks lists due for their daily check. TypeScript ESM. No paid services. Node 24 toolchain.
Tests never hit the network: fake fetch and fixture packages.
`PATH=$HOME/paybox-hackathon-2026-10-17/.node/node-v24.21.0-darwin-arm64/bin:$PATH npx tsx --test test/<file>.test.ts`.

## Shared contract (src/types.ts, orchestrator owns it)

```ts
export interface Manifest { id: string; name: string; version: string; manifestVersion: number; permissions: string[];
  optionalPermissions: string[]; hostPermissions: string[]; contentScriptMatches: string[]; externallyConnectable: string[];
  hasBackground: boolean; csp: string | null; updateUrl: string | null; description: string }
export type Severity = "critical" | "high" | "medium" | "low";
export interface Finding { code: string; severity: Severity; title: string; detail: string; points: number }
export interface Assessment { score: number; grade: "A" | "B" | "C" | "D" | "F"; findings: Finding[]; summary: string } // score 0..100, higher = riskier
export interface Change { kind: "permission_added" | "permission_removed" | "host_added" | "host_removed" | "mv_changed" | "new_extension" | "removed_from_store"; value: string; severity: Severity }
export class FetchError extends Error { constructor(public status: number, message: string) { super(message); } }
```

## Modules and owners

| File | Owner | Exports |
|---|---|---|
| src/crx.ts + test/crx.test.ts | W1 | `fetchManifest(id, fetchFn?): Promise<Manifest>`; `parseCrx(bytes: Uint8Array, id): Manifest`; `normalizeId(input): string \| null` |
| src/risk.ts + src/diff.ts + tests | W2 | `assess(m: Manifest): Assessment`; `diff(prev: Manifest \| null, next: Manifest \| null): Change[]` |
| web/ (index.html, app.js, styles.css) | W3 | the SaaS front end |
| src/types.ts, src/store.ts, src/worker.ts | orchestrator | API, storage, cron |

### CRX (W1)
- Download: GET `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=141.0.0.0&acceptformat=crx2,crx3&x=id%3D<ID>%26uc`
  (follow redirects). HTTP 204 or an empty body means the extension is not on the Web Store: throw FetchError(404, "Not on the Chrome Web Store").
  Timeout 8 s. Stream the package and stop after manifest.json and the locale file (8 MB scan window); use range requests when Google honours them.
- CRX3/CRX2: find the ZIP inside (CRX3 header: "Cr24", version 3, header length at bytes 8..11; ZIP starts at 12 + header length; CRX2: 16 + pubkey len + sig len).
  Read the ZIP central directory and inflate ONLY manifest.json and, when needed, _locales/<default_locale>/messages.json (and en as fallback),
  using `DecompressionStream("deflate-raw")` (available in Workers and Node 24). No zip library.
- Resolve "__MSG_x__" names and descriptions from messages.json (keys are case-insensitive). Strip a UTF-8 BOM; manifests may contain comments: strip // and /* */ comments outside strings before JSON.parse.
- normalizeId: accept a 32-char a-p id, a Web Store URL (chromewebstore.google.com/detail/<slug>/<id> or chrome.google.com/webstore/detail/...), or junk -> null.
- Tests: build small CRX3 fixtures in the test (zip with deflate via node:zlib deflateRawSync), locales, comments, CRX2, 204, oversize, garbage.

### Risk and diff (W2)
Transparent points table (document it in code and expose it): broad host access (<all_urls>, *://*/*, http(s)://*/*) 30; debugger 30;
nativeMessaging 20; userScripts 20; webRequest+webRequestBlocking 20 (MV2) / declarativeNetRequest 8; cookies 15; history 12;
management 15; proxy 15; privacy 12; tabs 6; scripting 8 (25 if combined with broad hosts); clipboardRead 10; desktopCapture/tabCapture 12;
downloads 6; geolocation 6; manifest version 2 = 10 (deprecated); content scripts on all sites 20; externally_connectable to all sites 15;
CSP allowing 'unsafe-eval' or remote script hosts 20; update_url outside Google 15. Cap 100. Grade: 0-19 A, 20-39 B, 40-59 C, 60-79 D, 80+ F.
Severity per finding from its points: >=25 critical, >=15 high, >=8 medium, else low. Summary: one plain sentence naming the top 2 findings.
diff: added/removed permissions and hosts (ignore order and duplicates), manifest version change, new extension (prev null), removed (next null).
Severity of a change = severity that permission would have in the table (host broadening is critical).
Tests: 20+ including a real-looking Google Translate manifest (activeTab, contextMenus, storage, offscreen, scripting, host <all_urls>) and diffs.

### Front end (W3)
A clean, credible B2B SaaS look (security product: calm, precise, trustworthy; think Linear or Vanta). Pages in one app:
1) Landing: headline, the silent-update problem in 3 lines, a "Try it" box (paste extension IDs or Web Store URLs, one per line) and pricing (Free: 10 extensions,
weekly check; Team 29 USD/month: 250 extensions, daily checks, email and Slack alerts, CSV export; Business 99 USD/month: unlimited, SSO, policy export, audit log).
2) Workspace (after "Try it"): POST /api/scan {ids} -> table: name, version, grade badge, score, top finding, "details" drawer with every finding and its points,
and the manifest permissions. A "Watch this list" button: POST /api/watchlists {name, ids} -> returns a private link (/w/<token>) that shows the list, its last check time
and the change log (GET /api/watchlists/<token>). 3) Methodology page: the full points table from GET /api/rules. No frameworks, no external assets, no emojis,
textContent only, accessible, 375 px and 1280 px. Footer: "Extension Watch by Michael Lip, github.com/theluckystrike. Not affiliated with Google."

## Hard rules
No secrets. No personal data stored: a watchlist holds a name, extension IDs and snapshots; the link token is the only key (32 random bytes, base64url).
Functions under 60 lines. No while(true). No empty catch. Edit only your files. Plain English. No emojis.
