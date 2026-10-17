# Extension Watch

Know what your team's Chrome extensions can do, and hear about it when that changes. Built by Michael Lip ([github.com/theluckystrike](https://github.com/theluckystrike)), who maintains 108 Chrome extensions with more than 150,000 users. Live at https://extension-watch.lipmichal.workers.dev

## The problem

Every company runs dozens of browser extensions that nobody reviewed. Extensions update themselves silently. An extension that only needed one site when someone installed it can, after an update, ask to "read and change all your data on all websites", and the browser shows no warning when an update keeps the extension enabled under policy. Security teams find out after an incident, if at all.

## What it does

1. Paste the extension IDs or Chrome Web Store links your team uses.
2. Extension Watch reads each extension's current package straight from Google's public update service. It does not trust store listings; it reads the manifest the browser itself would run.
3. It grades each extension's access from A (little) to F (a lot) with a published rule set, and lists every finding with its points.
4. "Watch this list" saves a private link. Every day it reads every extension again and records each change: a permission added or removed, new site access, a manifest version change, an extension pulled from the store.

The grade measures access, not intent. A password manager needs to read every page, so it grades F, and that is fine when you trust its publisher. What matters is knowing it, and being told when an extension you trusted asks for more.

## How it works

```
Browser ── /api/scan ──────────► Cloudflare Worker ──► Google update service (CRX package, HTTP ranges)
        ── /api/watchlists ───►        │  parse manifest + locales, grade, diff
        ◄── /w/<private link> ──       └─► Workers KV (one record per watchlist)
Daily Cron Trigger ── re-reads every watched extension, records changes
```

- No browser extension to install and no agent on employee machines. The service only needs extension IDs.
- Packages are read with HTTP range requests. For a 25 MB package (Bitwarden), Extension Watch reads the ZIP directory at the end of the file and then only `manifest.json` and the locale files, not the whole package. A tested fixture reads less than a quarter of a 3 MB package.
- The ZIP and DEFLATE decoding is written in the Worker, with no zip library.
- Scans run 5 extensions at a time. A scan holds at most 25 extensions and a watchlist at most 50.

## Methodology

The full points table is public at `/api/rules` and on the Methodology page. Examples:

| Finding | Points |
|---|---|
| Access to all websites (`<all_urls>`, `*://*/*`) | 30 |
| `debugger` | 30 |
| Content scripts on all sites | 20 |
| `nativeMessaging`, `userScripts` | 20 each |
| `cookies`, `management`, `proxy` | 15 each |
| Manifest V2 (deprecated) | 10 |

Grades: 0 to 19 A, 20 to 39 B, 40 to 59 C, 60 to 79 D, 80 and above F. Optional permissions are listed but do not count, because the browser does not grant them at install. Every rule is deterministic: the same manifest always gives the same grade, and no model is involved.

## Privacy and security

- Stored per watchlist: a name you choose, extension IDs, manifest snapshots and the change log. No email, no user account, no employee data.
- The private link is 32 random bytes (base64url). It is the only key; the service has no list of watchlists that anyone can browse.
- The Worker only fetches from Google's update service. Extension IDs are validated (32 characters a to p) before any request.
- Text from manifests is rendered with `textContent`, never as HTML.

## Pricing

| Plan | Price | For |
|---|---|---|
| Free | 0 | 10 extensions, weekly check |
| Team | 29 USD a month | 250 extensions, daily checks, email and Slack alerts, CSV export |
| Business | 99 USD a month | Unlimited extensions, SSO, policy export for Chrome Enterprise, audit log |

The cost to serve a watchlist is a few range requests per extension per day on Cloudflare Workers, so the gross margin on Team stays above 90 percent. Revenue grows with the number of extensions watched, which grows with company size.

## Run it

```bash
npm install
npx wrangler kv namespace create WATCHLISTS   # put the id in wrangler.jsonc
npx wrangler dev
npx tsx --test test/*.test.ts                 # 64 tests, no network
```

## License

MIT. Not affiliated with Google. Chrome is a trademark of Google LLC.
