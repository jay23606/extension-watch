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
| KV reads | 320 | 640 |
| KV writes | 170 | 320 |
| KV deletes | 0 | 0 |
| KV list calls | 1 | 144 |
| Outbound subrequests (fetches) | 20 | 20 |

The first run checks 150 lists, which is the `MAX_LISTS_PER_RUN` cap in the code, and downloads each
of the 20 shared extensions once. The second run checks the other 150 lists and reads the 20
extensions from the shared daily cache, so it downloads nothing. The other 142 runs find no list due,
because each list is checked once a day, and spend one KV list call each. Per checked list the code
reads the list twice (once to check it and once again before saving) and writes it once.

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

- Per invocation, the 491 KV operations of the busiest run are inside the 1,000 per invocation cap,
  and its 20 subrequests are inside the cap of 50.
- Per day, 300 lists spend 640 KV reads, 320 KV writes and 144 KV list calls, all inside the Free
  daily limits.
- KV writes are the first limit to bind. Each list costs one write a day, plus one write per distinct
  extension in the shared cache, so with 20 shared extensions about 980 lists fit the 1,000 writes a
  day of the Free plan. Past that the Workers Paid plan is needed.
- CPU time is not measured here. The check mostly waits on the network, so the KV and subrequest
  counts are the ones to watch.

The code also caps each run on its own, at 800 KV operations, 40 downloads and 150 lists, so a run
stays inside the platform limits as the fleet grows and the remaining lists wait for the next run.
