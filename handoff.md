# Handoff — analyst harness, TypeSafe + DeepSeek

Written 2026-09-17. Everything below is measured unless it says otherwise.

## Where things stand

Two PRs are merged to `master`:

- **#61 `2c96b2f477`** — `ctx.judgment`, a capability seam over System One models,
  plus `judgment-typesafe` and the bind verifier.
- **#62 `931d238b12`** — deterministic destination coverage (the enumeration gate),
  the per-investigation scorecard, and keyless grading.

The working branch `john-automates/hagfish-enumerate` is merged and can be deleted.

### Measured on the final build (web search off, N=4, two captures)

| | |
|---|---|
| Correct C2 | 4/4, stable across repeats |
| IOC coverage | 100% on both cases, both repeats |
| Groundedness | 100% |
| Closed unaided | 4/4 |
| Time to bound C2 | 2:31 – 4:12 (mean 3:17) |
| Wall clock | 3:38 – 5:15 (mean 4:23) |
| Cost | **$0.0325/investigation**, measured from balance delta |

`bench/typesafe-triage/runs/scorecard.jsonl` holds 17 records. Render with
`node bench/typesafe-triage/trend.mjs`.

**N is 4 runs across 2 captures. The ranges are honest; the means are optimistic.
Nothing here is a rate.**

## What to do next, in order

### 1. Negative controls — and the product gap they expose

**This is the highest-value item and it is blocked on a product decision.**

Every capture ever run has an infection. There is **zero evidence** the harness does
not also find a C2 in clean traffic. For a SOC buyer that is the metric that decides
trust: a false positive burns analyst minutes on every alert.

The mechanism, verified in source (not inferred):

- `completeDenyReason` (`mindset.ts:310`) needs a ready Plan and no leftover unbound
  LAN workstations. It does **not** require a bind, so the agent can declare the cue
  explicitly open and stop its turn.
- `caseReportDenyReason` (`bind.ts`) returns `UNBOUND_REASON` whenever
  `bind === undefined`. Filing a report without binding a victim to a C2 is
  **structurally impossible**.

So a clean capture yields narrative prose and **no structured record** — no
`investigation/report` event, no 5W1H, no machine-readable disposition. The scorecard
logs `closed: false` and reads it as failure. A "clean" verdict cannot be audited,
trended, or handed to a ticketing system.

Work:

1. Add a legitimate no-findings close path. This is a **product change**, not a test
   change, and it should be designed before the tests are written.
2. Add MTA's "seven days of scans and probes" entries to `corpus.mjs` with
   `kind: 'clean'`. They are deliberately excluded today (see the comment at the top
   of that file) — server-side traffic, no victim, no C2.
3. Teach `scorecard.mjs` a `shouldFindNothing` mode where a bound C2 is a **false
   positive**, and report FP rate alongside the existing metrics.

### 2. Run the five captures already downloaded

Everything reported so far comes from two of seven. All seven are already fetched
under `bench/typesafe-triage/cases/`.

Never run live: `2026-09-08` (XWorm), `2026-08-10` (Lumma), `2026-01-29` (njRAT),
`2026-08-21` and `2026-05-27` (SmartApeSG).

Two of them stress exactly what #62 built:

- **Lumma has 50 destinations** — the first real test of whether the enumeration gate
  stays affordable and whether the 0.06 drop band holds at scale. Two captures with
  8–9 destinations proved nothing about that.
- **njRAT has four plain-IP C2s** — the first multi-C2 case. Bind assumes one; what
  happens to coverage is unknown.

5 cases × 2 repeats ≈ **$0.35, about an hour wall**. N goes 4 → 14.

Always pass `--patch bench/typesafe-triage/no-web.cordis.yml`. See "Grading" below.

### 3. One command, then a regression gate

Sweeps have been assembled by hand four times. Write `bench/typesafe-triage/sweep.mjs`
taking build label, case list, repeat count and parallelism — run, score, append.

Then wire it into CI against the current build's floors: **IOC coverage ≥ 90% on
graded cases, grounded = 100%, closed = true**. Nothing runs the scorecard in CI
today, so every fix from #61 and #62 can silently regress.

### 4. Sweep reasoning effort

70% of output tokens are reasoning at `reasoningEffort: max` (set in
`bench/typesafe-triage/deepseek-max.cordis.yml`). Never swept. One capture × three
levels × two repeats ≈ $0.20. Largest untested lever on both cost and time.

### 5. Later — adversarial, and getting off this corpus

State contains attacker-controlled text: command lines, user agents, filenames. A
crafted capture where a real C2 is CDN-shaped, or where attacker text tries to steer
the verdict, would test whether the judgment seam can be nudged. No evidence either
way today.

Structural point worth keeping in mind: **production metrics need no answer key, so
they run on any pcap** — a clean office capture, a sandbox run, anything. That is how
to escape a corpus where every case has exactly one victim and one obvious C2, which
is not what real traffic looks like.

## Known defects, deliberately not fixed

- **The MIXED rule contradiction.** `ctx.get('judgment')` is `undefined` when
  `investigation` applies, because judgment registers afterward. A tool `description`
  is a fixed string, so `bindRelationshipDescription` returns the hard CDN rule while
  the prompt section — which re-evaluates per assembly — returns the softened one. The
  model sees both. Fix: `ctx.on('internal/service', …)` to re-register when judgment
  appears (pattern at `packages/api/gateway/src/index.ts:101`). Identified, not written.
- **`PROTOCOL_FIELD_VALUE = /^[a-z][a-z0-9]*\./`** (`harvest.ts`) rejects any
  `word.word` user, so a real `first.last` account never enters the ledger. Widening it
  would admit tshark field names like `ip.src`. Pinned by a test documenting current
  behavior rather than silently left.
- **No real-composition test** for judgment. `packages/AGENTS.md` wants it booted
  through the Loader with a test-only `cordis.yml`; what exists is `ctx.plugin(...)` in
  unit tests. This is a gate now that judgment ships in a preset.
- **Only `c2_is_benign_service` is graded.** `roles_inverted`,
  `victim_is_infrastructure`, `hostname_not_a_workstation` and
  `user_is_machine_account` are designed, not measured.
- **The verifier has never fired in a live run.** No capture in this corpus has a
  Cloudflare-only C2, so `judgeCdnOrUpdate` is proven only on the real code path in
  isolation (3/3 refused → bound), never end to end.

## Grading discipline — read before trusting any number

**`web_search` must be off.** It is not in the analyst preset; it arrives from the
headless profile underneath. On a corpus whose answers are published on the open web,
every number is one lucky search away from meaningless — one AMOS run searched a
destination name, reached malware-traffic-analysis.net, and cited it. Groundedness
caught it at 90%.

    --patch bench/typesafe-triage/no-web.cordis.yml

This is a change to how the harness is **graded**, not to the product: searching threat
intel for an unknown destination is legitimate tradecraft, and a customer investigating
their own traffic has no answer key to stumble into.

**Rename captures before running.** MTA names files after the malware family
(`2026-09-10-AMOS-Stealer-infection-traffic.pcap`), which hands over the answer. Copy
to `capture-1.pcap` etc. `scorecard.mjs` records `captureNamesNeutral` and the variance
grouping refuses to pool a named run with a neutral one.

**Always pass `--build=<label>`.** The session log carries no plugin config, so a run
cannot report which gates were compiled into it. Without the label the trend silently
compares different harnesses and reports the difference as variance — which it did
until the label existed.

**The cost scale is measured, not published.** Four investigations modelling to $0.5055
at list prices moved the balance $0.13, so the effective rate is ~26% of list.
Whether that is Flash pricing or an off-peak discount is **unverified**. Override with
`DSH_RATE_SCALE`. Re-derive it against a real contract before quoting a figure
externally. Raw token counts print beside the dollars for exactly this reason.

## Housekeeping

- **Rotate the DeepSeek API key.** It was pasted into a session transcript on
  2026-09-17 and is still live in the gitignored repo-root `.env`.
- `TYPESAFE_API_KEY` is in the same `.env`; the key file is at
  `~/.config/typesafe/api_key` (mode 600).
- The jev model is **pinned to `jev-1.13.0`**. Gates are calibrated against one
  version's probability scale; bumping it is a re-calibration event, not a version bump.
- `native/landlock-run/packages/linux-x64/bin/landlock-run` was built locally with
  plain `gcc` and is git-ignored. A fresh clone needs it rebuilt, or the sandbox is
  unusable and every `bash` call fails.
