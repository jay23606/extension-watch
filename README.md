# Extension Watch

<img src="docs/cover.jpg" alt="Extension Watch" width="800">

Know what your team's Chrome extensions can do, and hear about it when that changes. Built by Michael Lip ([github.com/theluckystrike](https://github.com/theluckystrike)), who maintains 108 Chrome extensions with more than 150,000 users. Live at https://extension-watch.lipmichal.workers.dev

## The problem

Every company runs dozens of browser extensions that nobody reviewed. Extensions update themselves silently. An extension that only needed one site when someone installed it can, after an update, ask to "read and change all your data on all websites", and the browser shows no warning when an update keeps the extension enabled under policy. Security teams find out after an incident, if at all.

## What it does

1. Paste the extension IDs or Chrome Web Store links your team uses.
2. Extension Watch reads each extension's current package straight from Google's public update service. It does not trust store listings; it reads the manifest the browser itself would run.
3. It grades each extension's access from A (little) to F (a lot) with a published rule set, and lists every finding with its points.
4. "Watch this list" saves an admin link and a read-only link. Every day it reads every extension again (a list larger than one run's download budget finishes over the next runs, and stays due until every extension got an answer) and records each change: a permission or site access added, content scripts that reach new sites, a looser script policy, updates moved off the Web Store, a jump in the access score, a new version, an extension pulled from the store.
5. Add a Slack, Discord or Google Chat webhook (or any public https endpoint that takes JSON) and changes of medium severity or higher arrive as one message after each check.

The grade measures access, not intent. A password manager needs to read every page, so it grades high (Bitwarden C 46, 1Password F 97 when checked on 18 October 2026), and that is fine when you trust its publisher. What matters is knowing it, and being told when an extension you trusted asks for more.

## Screenshots

Scan results: each extension's access grade, its highest finding, and a details drawer with every rule that fired.

<img src="docs/results.png" alt="Scan results" width="800">

A watchlist: the private link (blurred here), the change log, the extensions and the alert webhook.

<img src="docs/watchlist.png" alt="Watchlist" width="800">

## How it works

```
Browser ── /api/scan ──────────► Cloudflare Worker ──► Google update service (CRX package, streamed)
        ── /api/watchlists ───►        │  find manifest + locale, grade, diff
        ◄── /w/<private link> ──       ├─► Workers KV: one record per watchlist + one shared record per extension per day
Cron Trigger every 10 min ──── re-checks lists not checked for 23 h, oldest first ──► webhook alerts
```

- No browser extension to install and no agent on employee machines. The service only needs extension IDs.
- Packages are streamed, never stored. Google ignores range requests for large packages, so the Worker streams the whole package once and keeps only three things: the first 64 KB, the last 2 MB (where the ZIP index lives), and the bytes after each local header named `manifest.json` or `_locales/<x>/messages.json`. It then reads `manifest.json` at the offset the ZIP index gives and checks that the local header there carries the same name, so a decoy manifest hidden inside another file cannot change the grade. A package with two index entries for `manifest.json` is refused, and a package that could be read before but not after an update is logged and alerted as a high-severity change. Memory follows the size of the wanted entries, not the package: captures end at the next local header, and entries that inflate past 4 MB are refused. In production, Keeper (a 143 MB package) and RoboForm were read together in 5.5 s. When Google does honour ranges, only the needed parts are fetched. If the name is still a locale key, the display name comes from the extension's Web Store page.
- The ZIP and DEFLATE decoding is written in the Worker, with no zip library. It handles CRX2, CRX3, data-descriptor entries, comments and a BOM in manifests.
- Each extension is downloaded at most once a day, whatever the number of watchlists that contain it, and definitive failures (removed from the store, unreadable) are cached for the day too. A cron run checks at most 150 due lists, downloads at most 40 packages and spends at most 800 KV operations (Cloudflare allows 1,000 per invocation); whatever is left waits for the next run, 10 minutes later. In a test with 600 watchlists sharing one extension, 4 runs (40 minutes) checked all 600 with 1 download.
- Scans run 5 extensions at a time. A scan holds at most 25 extensions and a watchlist at most 50. A Cloudflare rate limiting binding is configured for writes (20 a minute per address); Cloudflare applies it per location and approximately, so treat it as a brake, not a hard cap. Daily counters (200 scans, 20 watchlists and 10 test alerts per address) are approximate under parallel requests too.

## Data model (Workers KV)

| Key | Value | Expiry |
|---|---|---|
| `wl:<admin token>` | `{ name, ids[], snapshots{id: {manifest, assessment, error, checkedAt}}, changes[], createdAt, lastCheck, viewedAt, webhook, viewToken }`, with `{ lastCheck }` as key metadata so the scheduler can pick due lists from a listing alone | 90 days, renewed by every save |
| `vw:<read-only token>` | The admin token it belongs to | 400 days |
| `ext:<extension id>` | The day's snapshot of one extension, shared by every watchlist | 3 days |
| `rl:<action>:<day>:<address>` | Daily counter for scans, new watchlists and test alerts | 2 days |

A change is `{ kind, value, severity, id, at }`. The change log keeps the last 200 entries.

## API

| Method and path | Purpose |
|---|---|
| `POST /api/scan` `{ ids }` | Grade up to 25 extensions |
| `POST /api/watchlists` `{ name, ids }` | Create a watchlist (up to 50 extensions); returns the private token |
| `GET /api/watchlists/<token>` | Read a watchlist. With the admin token: `role: admin`, the read-only token and the webhook host. With the read-only token: `role: viewer`, no webhook |
| `PUT /api/watchlists/<admin token>` `{ webhook }` | Set or clear the alert webhook |
| `DELETE /api/watchlists/<admin token>` | Delete a watchlist and its read-only link |
| `POST /api/test-alert` `{ token: <admin token> }` | Send a labelled test message to the saved webhook |
| `GET /api/rules` | The full points table |

## Methodology

The full points table is public at `/api/rules` and on the Methodology page. Examples:

| Finding | Points |
|---|---|
| Access to all websites (`<all_urls>`, `*://*/*`, `https://*/`) | 30 |
| `debugger` | 30 |
| Content scripts on all sites | 20 |
| `nativeMessaging`, `userScripts`, blocking `webRequest` | 20 each |
| Script policy that allows `'unsafe-eval'` or remote script | 20 |
| `cookies`, `management`, `proxy` | 15 each |
| Updates from a server other than Google | 15 |
| Manifest V2 (deprecated) | 10 |

Rules that describe the same power are grouped, and a group counts once at its highest value. For example, broad host access, content scripts on all sites and script injection all mean "can run code on every site", so together they count 30, not 58. Grades: 0 to 19 A, 20 to 39 B, 40 to 59 C, 60 to 79 D, 80 and above F. Optional permissions are listed as "can request later" with 0 points, because the browser does not grant them at install. Every rule is deterministic: the same manifest always gives the same grade, and no model is involved.

Checked against 50 popular extensions in production on 17 October 2026 (UTC), with the shared cache cleared so only the deployed code ran: 46 read (the other 4 are no longer in the store), graded 9 A, 12 B, 16 C, 6 D and 3 F, with no `'wasm-unsafe-eval'` policy mistaken for `'unsafe-eval'`. Password managers: Bitwarden C 46, Keeper C 56, LastPass C 59, Dashlane D 71, RoboForm F 83, 1Password F 97.

## Privacy and security

- Stored per watchlist: a name you choose, extension IDs, manifest snapshots and the change log. No email, no user account, no employee data.
- Each watchlist has two links, each 32 random bytes (base64url). The admin link can change alerts and delete the list; the read-only link, the one the page tells you to share, can only view it. The service has no list of watchlists that anyone can browse. A list nobody opens for 90 days (365 days when it has a webhook, because that team reads it in chat) stops being checked and then expires. A saved webhook is shown back as its host name only, because a chat webhook lets anyone who has it post to the channel.
- The Worker fetches only from Google (update service and Web Store page) and from the one webhook a list's admin sets. Extension IDs are validated (32 characters a to p) before any request. Webhooks must be https on the standard port with a host name: IP addresses, user names, and internal or loopback names such as `localhost`, `.internal` or `lvh.me` are refused, and redirects are not followed. Alerts always carry the read-only link, never the admin link, because chat channels are shared.
- The API accepts only `application/json` (the MIME type is parsed, not substring-matched), so neither a form nor a simple cross-site request from another page can start work in a visitor's browser.
- Pages are served with a strict Content Security Policy (no inline script, no eval), `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. Text from manifests is rendered with `textContent`, never as HTML.

## Pricing (planned; billing is not connected in this version)

| Plan | Price | For |
|---|---|---|
| Free | 0 | 10 extensions, weekly check |
| Team | 29 USD a month | 250 extensions, daily checks, Slack and email alerts, CSV export |
| Business | 99 USD a month | Unlimited extensions, SSO, policy export for Chrome Enterprise, audit log |

The cost to serve a watchlist is at most one streamed download per extension per day on Cloudflare Workers, shared across every customer who watches that extension (an estimate, not yet measured at scale), so the gross margin on Team stays above 90 percent. Revenue grows with the number of extensions watched, which grows with company size.

## Run it

```bash
npm install
npx wrangler kv namespace create WATCHLISTS   # put the id in wrangler.jsonc
npx wrangler dev
npx tsx --test test/*.test.ts                 # 118 tests, no network
```

## License

MIT. Not affiliated with Google. Chrome is a trademark of Google LLC.
