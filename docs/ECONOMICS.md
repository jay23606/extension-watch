# Unit economics of a scheduled check

Measured on 19 October 2026 with `npm run economics`.

This is a local simulation with a fake KV and a fake Google update service. It is not a measurement
on Cloudflare. The script runs the real Cron Trigger handler from `src/worker.ts`
(`worker.scheduled`) against an in-memory Workers KV that records every call, so the counts come from
the shipped check code and not from a hand-written model. The package bytes come from a local CRX
fixture, so no request leaves the machine.

Run it with the project tooling.

```
npx tsx scripts/economics.ts
```

## Scenario

- 300 watchlists, each holding the same 20 extension ids, so the shared daily cache has one copy per
  extension for the whole fleet.
- Every list is due for its daily check at the start.
- One simulated day of 144 scheduled runs, the same handler a Cron Trigger calls every 10 minutes.

## Measured counts

| Metric | First run | One day of 144 runs |
|---|---|---|
| KV reads | 560 | 1,560 |
| KV writes | 128 | 320 |
| KV deletes | 0 | 0 |
| KV list calls | 1 | 144 |
| Outbound subrequests (fetches) | 20 | 20 |

The first run checks 108 lists, then its KV budget stops it and the next run continues. Per checked
list the code reads the list record twice, once to load it and once again before saving, reads the
tombstone once just before the save and twice inside `save`, and writes the record once. It also reads
and writes the 20 shared extensions once each, because the cache is empty. The second run checks 110
lists, then its budget stops it, and the third run checks the remaining 82. Those two runs read the
extensions from the shared daily cache, so they download nothing. The other 141 runs find no list due,
because each list is checked once a day, and spend one KV list call each. The busiest run spends 689
KV operations, inside the 1,000 per invocation cap.

## Free plan limits it is measured against

Cloudflare publishes these Workers Free and Workers KV Free limits.

| Limit | Free plan |
|---|---|
| Worker requests | 100,000 per day |
| Subrequests per invocation | 50 |
| KV keys read | 100,000 per day |
| KV keys written | 1,000 per day |
| KV list requests | 1,000 per day |
| KV operations per Worker invocation | 1,000 |

## What it fits

- Per invocation, the 689 KV operations of the busiest run are inside the 1,000 per invocation cap,
  and its 20 subrequests are inside the cap of 50.
- Per day, 300 lists spend 1,560 KV reads, 320 KV writes and 144 KV list calls, all inside the Free
  daily limits.
- KV writes are the first limit to bind. Each list costs one write a day, plus one write per distinct
  extension in the shared cache, so with 20 shared extensions 980 lists fit the 1,000 writes a
  day of the Free plan, the figure `npm run economics` prints. Past that the Workers Paid plan is
  needed. Production runs on a Workers Paid setting, `cpu_ms` 10000 in `wrangler.jsonc`, so the 10 ms
  Free CPU limit is not the binding one.
- CPU time is not measured here. The check mostly waits on the network, so the KV and subrequest
  counts are the ones to watch.

The code also caps each run on its own, at 800 KV operations, 40 downloads and 150 lists, so a run
stays inside the platform limits as the fleet grows and the remaining lists wait for the next run.
