# Extension Watch Devpost submission text (Galuxium Nexus V2)

## Project name
Extension Watch

## Tagline
Know what your team's Chrome extensions can do, and hear about it the day an update asks for more.

## Executive briefing

### The problem
Browser extensions are the least reviewed software in most companies. They install in one click, update silently, and run inside the browser where people read email, handle customer data and log in to everything. An extension that asked for access to one site when someone installed it can ask for access to every site in a later update, and nobody in the company reviews that change. Security reviews of extensions today are manual: open the store page, read the description, guess.

### The product
Extension Watch reads each extension's real package from Google's update service, grades how much it can do with a published rule set, and watches the list every day. When an update adds a permission or new site access, the change appears in the watchlist with its severity. Teams paste extension IDs or store links; there is nothing to install on employee machines.

### Target cohort
IT and security leads at companies with 20 to 2,000 people who manage Chrome (often with Google Workspace or Chrome Enterprise) and have no budget or time for an enterprise browser security platform. Second cohort: agencies and consultancies who must answer client security questionnaires about the tools their staff use.

## Architecture
- Cloudflare Workers for the API and the web app; Workers KV for watchlists; a daily Cron Trigger for re-checks.
- Packages are read with HTTP range requests: the ZIP directory first, then only manifest.json and the locale files. A 25 MB password manager package is read without downloading it.
- ZIP and DEFLATE decoding written in the Worker, with no zip library.
- Deterministic grading: a public points table (/api/rules), the same manifest always gives the same grade, no model involved.

Each watchlist is one record (name, extension IDs, manifest snapshots, change log), and its private link is a 32-byte random token. 64 automated tests cover CRX3, CRX2, locales, comments in manifests and range reads, with fixtures built inside the tests.

## Governance and compliance
- Data minimisation: no accounts, no email, no employee data. A watchlist holds only extension IDs and public manifest data.
- The Worker fetches only from Google's update service, after validating each ID, so it cannot be used to fetch other URLs.
- Algorithmic transparency: every finding shows its points; the full table is public. The grade measures access, not intent, and the product says so on the results page.
- All text from manifests is rendered as text, never as HTML.

## Fiscal architecture (monetisation)
- Free: 10 extensions, weekly check.
- Team, 29 USD a month: 250 extensions, daily checks, email and Slack alerts, CSV export.
- Business, 99 USD a month: unlimited extensions, SSO, a Chrome Enterprise policy export (allow and block lists from the grades), audit log.
- Cost to serve: a few range requests per extension per day on Workers, under 0.50 USD a month for a 250-extension Team list, so gross margin stays above 90 percent.
- Expansion: revenue grows with the number of extensions watched, which grows with headcount. The policy export turns the product from "report" into "control", which is what the Business tier sells.

## What is built today
The live service scans extensions, grades them, creates watchlists with private links, records changes, and re-checks every list daily. Billing is described above but not connected in the demo.

## Built with
TypeScript, Cloudflare Workers, Workers KV, Cron Triggers, Chrome extension CRX format, HTTP range requests.

## Links
- Live: https://extension-watch.lipmichal.workers.dev
- Code: https://github.com/theluckystrike/extension-watch
- Video: (YouTube link, to add)

Built by Michael Lip, github.com/theluckystrike. Not affiliated with Google.
