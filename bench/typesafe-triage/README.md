# A System One model triaging real infection captures

English | [中文](README.zh.md)

Not a simulation. Seven captures from [malware-traffic-analysis.net][mta] are
downloaded, `tshark` reduces each to one observation per outbound destination,
and TypeSafe judges every destination against the hand-coded heuristic the
`analyst` plugin ships today. The post's own notes file says who was right.

```sh
node bench/typesafe-triage/fetch.mjs     # download + unzip the corpus
node bench/typesafe-triage/bench.mjs     # grade jev against the shipped rule
node bench/typesafe-triage/bench.mjs --case=2026-08-10
```

Needs `~/.config/typesafe/api_key` (or `$TYPESAFE_API_KEY`), `tshark`, and
`pnpm run build` — the baseline is imported from the built plugin, never
reimplemented. No LLM runs: Jev returns typed probabilities, and everything else
is tshark and pure functions. A full seven-capture run is 97 calls and $0.003.

## The corpus

Infection writeups only; the "seven days of scans and probes" posts have no
victim and no C2. Each case is a capture plus the notes file, extracted with the
site's published `infected_YYYYMMDD` scheme (stated on its about page as an
image, so it does not scrape). `files-from-*` and `malware*` zips sit on the
same pages and are never downloaded — nothing here can be executed by accident.

## Reading the traffic

A destination is judged from what the packets show and nothing else. `observe.mjs`
walks every frame, keeps the pairs where a LAN host talked to something off the
LAN, and reduces each destination to a bucketed, semantic state:

- **names** from DNS answers, TLS SNI, and HTTP `Host` — up to four.
- **volume and shape** as buckets (`a few KB`, `tens to hundreds of KB`), not raw
  counts, so the judgment does not turn on a number the model cannot calibrate.
- **when and for how long** relative to the start of the capture.
- **HTTP requests and user agents**, truncated, when the traffic is cleartext.

Two things deliberately stay out of the state: the capture's file name — MTA
names captures after the malware family, which would hand the answer over — and
anything at all from the notes file.

## What the model is asked

Four questions over the same state in one request. They are independent, so they
run in parallel and cannot see one another's answers.

    attacker_infra     Noul     attacker-owned server or domain
    malware_used_it    Noul     malware drove this, legitimate host or not
    benign_background  Noul     CDN / update / telemetry / OCSP
    label              Choice   c2 | abused_service | cdn | update | distractor

The split is not decoration. The first run asked one question — "is this part of
the infection?" — and got 0.07 for `accounts.google.com` and 0.08 for
`ip-api.com`. Both are correct answers to that question, and both are listed by
their posts, because the malware used them. A post's IOC list is the union of two
different things, so it takes two questions. `suspicion()` composes them in code,
which means changing a threshold costs no inference.

## Ground truth

Each post publishes the domains and IPs belonging to the infection. A destination
in the capture is positive when its IP, or a name the capture resolved for it,
appears in that list. Grading starts from the capture, so hosts the notes mention
but the capture never contacted — sandbox links, mail relays in `Received:`
headers — never come up.

Stated rather than hidden: a destination that was part of the infection but that
the post did not list scores as a negative. Cloudflare-fronted domains resolve to
several addresses and count once per address. `iocMatch` also matches a name
against an IOC in both suffix directions, so a bare `example.com` would match an
IOC of `sub.example.com`; nothing in this corpus triggers it.

## The pilot to beat

`baseline.mjs` imports `isCdnOrUpdateName`, `isCloudflareIpv4`, `isFastlyIpv4`
and `isLanIpv4` from the built plugin. A non-LAN destination is a C2 candidate
unless one of them fires. That is the whole of the plugin's semantic
understanding of a destination — a 19-entry suffix list and two published anycast
prefix sets — and it sees the identical observation, which is what makes the
comparison about judgment rather than evidence.

## What the run says

97 destinations, 37 of them published IOCs:

    pilot                       precision   recall      F1     FP    FN
    shipped heuristic               41%        57%    0.48     30    16
    jev choice c2|abused            81%        46%    0.59      4    20

The Noul scale is compressed — almost nothing clears 0.5 — but the calibration is
monotonic (0.0-0.1 → 17% observed, 0.2-0.3 → 63%, 0.3+ → 100%), so it is a good
ranker read at the wrong threshold. Swept on this data it defines three bands:

- `>= 0.25` — 13 destinations, **100% precision**. Straight onto the Plan.
- `< 0.06` — 34 of 97 destinations, **no published IOC below it**. Drop.
- between — where the answer actually lives, and what a slow tier should read.

## The finding

All 16 destinations the shipped heuristic calls benign but the notes call IOCs
are dropped by the Cloudflare/Fastly prefix rule — 15 distinct malicious domains
across 6 of the 7 captures, including `kernel-87.com`, `newlycrack.com`, and
`beeflex.online`.

`bind.ts`'s `ipIsCdnOrUpdate` tests the anycast prefix **before** it looks at the
hostname, so an evidenced name that is plainly not a CDN cannot rescue the
address. This is not only a reporting omission: `uniqueC2IsCdnOrUpdate` feeds
`CDN_C2_REASON` at [`bind.ts:659`](../../packages/analyst/investigation/src/bind.ts),
so `bind_relationship` **refuses the bind**, `case_report` stays denied for want
of a live bind, and `agent/turn-stopping` refuses the close. A Cloudflare-fronted
C2 does not produce a worse report; it produces no report.

`harvest.ts` notes that "live-case gold IPs are not listed" in those prefix
tables — the fixtures were built so this path never fires, which is why per-file
100% coverage did not catch it.

## The verifier

`verify.mjs` is the rung between the rungs, in the shape the [SDE cascade
cookbook][cascade] gives: narrow "is something wrong?" questions, one per failure
mode, max-aggregated behind a single gate so one confident red flag cannot be
averaged away by four calm ones. The failure modes are not invented — they are
`bind.ts`'s own deny reasons.

The exact ones stay exact. Whether `10.9.10.101` is RFC1918, and whether exactly
one endpoint is the victim, are arithmetic; `exactDenial` keeps them in code and
they never cost a call. Only the judgments that need to know what a thing *is*
are asked. A dimension with no evidence is not asked either: the first run put
`user_is_machine_account` at 0.39–0.44 on victims that had no recorded account at
all, and under max-aggregation that noise became the reported worst dimension.

    node bench/typesafe-triage/verify-bench.mjs

97 bind proposals, 37 the notes back, 97 calls, $0.0036:

    gate                        correct   wrongly rejected   wrongly accepted
    shipped ipIsCdnOrUpdate       53%                 16                 30
    verifier >= 0.60              76%                  5                 18

(`GATE` defaults to 0.7, the cookbook's number — a cold run prints 71%/4/24.
0.60 is the best row of the sweep below, on this corpus.)

Only one dimension is graded here. `c2_is_benign_service` was the max on all 97
proposals; `roles_inverted` (0.07-0.17) and `victim_is_infrastructure`
(0.16-0.22) never fired, because this corpus gives the victim side no evidence to
judge and contains no inverted proposal, and the hostname and account dimensions
were not asked at all. They are designed, not measured. The numbers above are
therefore a single-dimension result, and gating on `c2_is_benign_service` alone
reproduces them exactly.

The verifier is better at **both** error types at once, which is the unusual
part — it is not trading recall for precision, it is replacing a rule that was
wrong in both directions. 15 of the 16 Cloudflare-fronted C2s the shipped gate
refuses are allowed through; the one it still stops is `reallyfreegeoip.org`
(0.74), a genuinely legitimate service the malware was abusing.

Swept, the gate is a dial between two different jobs:

    gate    correct   wrongly rejected   wrongly accepted
    0.35       75%                 23                  1
    0.60       76%                  5                 18
    0.70       71%                  4                 24

At 0.35 almost nothing benign gets through, at the price of flagging 23 real C2s
— useless as a final answer, ideal as **the queue for the slow tier**. At 0.60 it
is the best standalone gate. The cookbook's own 0.7 is for a different task and
should not be borrowed; the docs say as much.

## Scoring a finished investigation

The bench above grades per-destination classification. `scorecard.mjs` grades
what the harness actually produces — a bound relationship and a 5W1H report —
and appends one record per run to `runs/scorecard.jsonl`.

```sh
node bench/typesafe-triage/scorecard.mjs <run-dir> --case=2026-09-10 --build=<label>
node bench/typesafe-triage/trend.mjs
```

Metrics split in two, and the split is the point. **Production** metrics need no
answer key, so they run on a customer's own captures: groundedness (every
address and name the report asserts exists in the packets), citation rate, time
to first bind against time to report, cost, and the fields the harness lost
between what the model submitted and what it persisted. **Bench** metrics need
the published notes and cannot ship: bound-C2 correctness and IOC coverage.

Groundedness is the one that matters commercially. It catches a confidently
fabricated indicator — the failure that ends analyst trust — with no ground
truth at all. It also caught benchmark contamination: one run searched a
destination name, reached this corpus's own source site, and cited it, which
showed up as two asserted hosts the capture never carried.

`--build` is operator-supplied because the session log carries no plugin
config. Without it the trend silently compares different harnesses and reports
the difference as variance.

Cost is a rate card times an empirically measured scale, printed beside the raw
token counts so a wrong card cannot hide the measurement underneath it.

## Grading without the answer key on the network

`web_search` is not in the analyst preset; it arrives from the headless profile
underneath. On a corpus whose answers are published on the open web, that makes
every number one lucky search away from meaningless.

```sh
--patch bench/typesafe-triage/no-web.cordis.yml
```

This is a change to how the harness is **graded**, not to the product.
Searching threat intel for an unknown destination is legitimate tradecraft, and
a customer investigating their own traffic has no answer key to stumble into.

[cascade]: https://docs.typesafe.ai/cookbooks/sde_cascade.md
[mta]: https://www.malware-traffic-analysis.net/
