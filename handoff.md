# Handoff — analyst harness, TypeSafe + DeepSeek

Written 2026-09-17. Everything below is measured unless it says otherwise.

## Where things stand

Two PRs are merged to `master`:

- **#61 `2c96b2f477`** — `ctx.judgment`, a capability seam over System One models,
  plus `judgment-typesafe` and the bind verifier.
- **#62 `931d238b12`** — deterministic destination coverage (the enumeration gate),
  the per-investigation scorecard, and keyless grading.

The working branch `john-automates/hagfish-enumerate` is merged and can be deleted.

### Measured on the final build (`keyless`, web search off, N=13, six captures)

Superseded the original N=4 table on 2026-09-17 after `sweep.mjs` ran the remaining
captures. The N=4 figures were measured on the two easiest captures in the corpus and
were optimistic on every axis.

| | N=4 (two easy captures) | **N=13 (six captures)** |
|---|---|---|
| Closed unaided | 4/4 | **13/13** |
| Correct C2 | 4/4 | **10/10 on gradeable cases**; `2026-05-27` ungradeable (see below) |
| IOC coverage | 100% | **88–100%** |
| Groundedness | 100% | **92–100%; 10/13 clean** |
| Wall clock | 3:38–5:15 (mean 4:23) | **3.5–11.2 min (mean 6.9)** |
| Cost, effective | $0.0325 | **$0.0433** (0.0172–0.0841) |
| Cost, at list | — | **$0.1686** |

Per case, so the scaling is visible:

| case | dests | n | C2 | IOC% | grounded% | $ mean | wall |
|---|---|---|---|---|---|---|---|
| `2026-08-06` Remcos | 4 | 2 | 2/2 | 100 | 100 | $0.0232 | 4.0m |
| `2026-05-27` SmartApeSG | 5 | 3 | 0/3 | 100 | 92–100 | $0.0415 | 7.5m |
| `2026-01-29` njRAT | 7 | 2 | 2/2 | 100 | 93–100 | $0.0340 | 3.5m |
| `2026-09-10` AMOS | 8 | 2 | 2/2 | 100 | 100 | $0.0418 | 4.7m |
| `2026-08-21` SmartApeSG | 22 | 2 | 2/2 | 100 | 100 | $0.0593 | 10.3m |
| `2026-08-10` Lumma | 50 | 2 | 0/2 | 88–100 | 99–100 | $0.0612 | 11.2m |

**The enumeration gate stays affordable at scale — the open question from item 2.**
7x the destinations (7 to 50) costs 1.8x the money and 3.2x the time. Cost tracks tool
calls, not destinations: the 2.4x spread inside `2026-08-21` ($0.0841 vs $0.0346) came
from 136 tool calls against 67 on identical input.

**The cost scale is still unverified.** `RATE_SCALE = 0.257` is empirical. If it is a
promotion rather than Flash pricing, every effective figure above multiplies by 3.9x.
The list column is the safe one to quote.

`bench/typesafe-triage/runs/scorecard.jsonl` holds 25 records, 13 of them `keyless`. Render with
`node bench/typesafe-triage/trend.mjs`.

**N is 13 runs across 6 captures. The ranges are honest; the means are still thin at
2–3 repeats per case. Nothing here is a rate.** The other 13 records span five different builds — `baseline`,
`harvest-fixes`, `slot-merge`, `enumeration`, `keyless` — so they are cross-build
history, not repeats, even though `trend.mjs` will render them as one series.

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

**The constraint the close path has to satisfy.** `undisposedDestinations`
(`bind.ts:1264`) opens with `if (bind === undefined || victim === undefined) return []`.
So a no-findings close bolted on today **bypasses the enumeration gate entirely** — the
gate #62 built to stop 29% coverage. A clean verdict would cost nothing to assert, and
negative controls would then measure the harness's willingness to say "clean", not its
correctness. A clean close must still disposition every evidenced WAN destination for
every harvested LAN host, which means generalizing
`wanPeersOfVictim(evidenceText, victim.addr)` off the single victim. That is the real
design work here.

Work:

1. Add a legitimate no-findings close path, satisfying the constraint above. This is a
   **product change**, not a test change, and it should be designed before the tests
   are written — and after `2026-08-21` has been run, because 22 destinations against
   6 IOCs is the closest preview this corpus offers of how disposition behaves on
   mostly-benign traffic.
2. Add MTA's "seven days of scans and probes" entries to `corpus.mjs` with
   `kind: 'clean'`. They are deliberately excluded today (see the comment at the top
   of that file) — server-side traffic, no victim, no C2. Note the limit: they are
   honeypot **inbound**, so `harvest` finds no LAN workstation and the close path under
   test is barely exercised. They are a weak control on their own.
3. The failure a SOC buyer actually fears is a workstation **browsing normally** bound
   to a CDN. That needs a synthetic clean capture — ten minutes of a VM hitting
   ordinary sites. Item 5's own observation makes it free to score: production metrics
   need no answer key.
4. Teach `scorecard.mjs` a `shouldFindNothing` mode where a bound C2 is a **false
   positive**, and report FP rate alongside the existing metrics.

### 2. Run the five captures already downloaded — **DONE 2026-09-17**

Four cases ran (`smartape1`, `smartape2`, `lumma`, `njrat`), 8 investigations, $0.39.
XWorm deliberately skipped — one destination. Results are in the headline table above
and in "Found while writing `sweep.mjs`" below. The rest of this section is kept
because the per-case rationale still explains what each capture is for.

Everything reported so far comes from two of seven. All seven are already fetched
under `bench/typesafe-triage/cases/`.

Never run live: `2026-09-08` (XWorm), `2026-08-10` (Lumma), `2026-01-29` (njRAT),
`2026-08-21` and `2026-05-27` (SmartApeSG).

Observed destinations per case, from `.observations.json` — this is the number that
predicts enumeration-gate load, not the IOC count:

| case | dests | IOC dests | what it is for |
|---|---|---|---|
| `2026-08-10` Lumma | **50** | 8 | scale |
| `2026-08-21` SmartApeSG | **22** | 6 | multi-C2, and 16 benign destinations |
| `2026-09-10` AMOS | 8 | 8 | graded |
| `2026-01-29` njRAT | 7 | 5 | abused legitimate services |
| `2026-05-27` SmartApeSG | 5 | 5 | |
| `2026-08-06` Remcos | 4 | 4 | graded |
| `2026-09-08` XWorm | 1 | 1 | near-trivial |

Run them in this order — `2026-05-27`, `2026-08-21`, `2026-08-10`, `2026-01-29`:

- **Lumma has 50 destinations** — the first real test of whether the enumeration gate
  stays affordable and whether the 0.06 drop band holds at scale. Two captures with
  8–9 destinations proved nothing about that. It is also the first case where the
  verifier must separate CDN-fronted IOC from CDN-fronted background at scale: six of
  its eight IOC destinations sit on Cloudflare, alongside a genuine
  `static.cloudflareinsights.com` and `cdn.tailwindcss.com`.
- **`2026-08-21` is the multi-C2 case**, not njRAT. Two RATs on one victim with two
  distinct C2s — `144.124.242.171:443` (encoded, not TLS) and `5.252.177.69:80`. Bind
  assumes one; what happens to coverage is unknown. Its 22 destinations against 6 IOCs
  also make it the closest thing this corpus has to mostly-clean traffic, which is why
  it should run **before** item 1 is designed.
- **njRAT is a single-C2 case.** The earlier claim of "four plain-IP C2s" does not
  survive the notes: one C2 IP, `104.248.130.195`, on two ports (7492, and 10042 which
  RSTs). What makes it worth running is different and better — its infection traffic
  runs over abused legitimate services (`api.telegram.org`, `cphost.qhoster.net:587`
  SMTP exfil), which is the `c2_is_benign_service` dimension in a live capture rather
  than in isolation.
- **XWorm has exactly one observed destination** — `43.228.157.141:7007`, no DNS names.
  It is a smoke test, not a case. One run or none.

4 cases × 2 repeats ≈ **$0.25, under an hour wall**. N goes 4 → 12.

`sweep.mjs` (item 3) now enforces the grading discipline below, so prefer:

    node bench/typesafe-triage/sweep.mjs --build=keyless --cases=smartape1,smartape2,lumma,njrat --repeats=2

### 3. One command, then a regression gate

`bench/typesafe-triage/sweep.mjs` is **written**. It stages captures under neutral
names read-only, composes the three overlays, runs, scores, and appends — build label,
case list, repeat count and parallelism as flags, `--dry-run` to see the plan. It
refuses a `--build`-less run and refuses a run name that would alias an existing
session log, because `scorecard.mjs` locates a log by run-dir basename and takes the
largest match.

Still to do: wire it into CI against the current build's floors — **IOC coverage ≥ 90%
on graded cases, grounded = 100%, closed = true**. Nothing runs the scorecard in CI
today, so every fix from #61 and #62 can silently regress.

Prerequisites the gate needs, none of them satisfied yet:

- Both API keys as repository secrets.
- `native/landlock-run/.../landlock-run` rebuilt in the runner — it is gitignored, and
  without it every `bash` call fails.
- Budget: ~4–5 min wall per investigation, so a gating sweep is tens of minutes.
- **N > 2 per case.** Two repeats cannot separate flake from regression when
  pre-enumeration coverage was 29–100% on the same capture. Either aggregate the floor
  across cases or use 3+ repeats on the cases that gate.

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

## Found while writing `sweep.mjs` (2026-09-17, second session)

- **`2026-05-27` cannot be graded on `c2Correct`, and it is the corpus's fault.** The
  file is `part-01` of a multi-part capture. Its five destinations are the delivery
  chain only — `ybtoner.com` (the compromised legitimate site), `hiddenplanetlab.top`
  (fake CAPTCHA), `silverharvestnetwork.com` and two plaintext stagers. The notes' two
  actual post-infection C2s, `89.110.110.119` and `185.163.47.217`, **are not in the
  packets**. `c2Correct` tests `truth.ips.has(boundC2)`, so this case scores `false` no
  matter what the harness does. Either fetch the remaining parts or mark the case
  `deliveryChainOnly` and exempt it from `c2Correct`.

  **But the C2 slot is unstable across repeats, and one run got it wrong.** With the
  true C2 unavailable, the three runs filled the slot differently:

  | run | bound as C2 | what it is | verifier | refusals |
  |---|---|---|---|---|
  | `smartape1-w1` | `172.67.151.107` | `ybtoner.com` — the **compromised legitimate site** | 1 | 0 |
  | `smartape1-s1` | `5.78.196.180` | `silverharvestnetwork.com` — attacker payload host | 3 | 2 |
  | `smartape1-s2` | `5.78.196.180` | same | 4 | 1 |

  The 2/3 answer is defensible: attacker-owned delivery infrastructure, absent a real
  C2. The 1/3 answer is a genuine role error — the notes call `ybtoner.com`
  "LEGITIMATE BUT COMPROMISED SITE", and it sits on Cloudflare, which is
  `c2_is_benign_service` failing live. So this case is ungradeable on `c2Correct` *and*
  shows a real instability.

  Suggestive, at n=3: the run that got it wrong consulted the verifier **once** with
  zero refusals; the two that got it right consulted it 3–4 times with 1–2 refusals.
  That is the first hint the verifier is doing work end to end, and it is worth
  designing a proper test around rather than reading as a result.
- **Bind does not assume a single C2.** `smartape1-w1` bound two `role: 'c2'` endpoints
  (`172.67.151.107` and `5.78.196.236`) plus three `infra`, in one `bind_relationship`.
  The handoff's earlier "bind assumes one" was wrong. What *is* single-C2 is the
  **scorecard**: `c2Correct` reads `endpoints.find(e => e.role === 'c2')` — the first
  one only. On `2026-08-21`, a genuine two-C2 case, that will grade half the answer.
  Fix `c2Correct` before reading those records.
- **`c2Correct` is a "found *a* right one" metric, and `2026-08-21` proves it matters.**
  `smartape2-s2` bound one C2, `5.252.177.69` (the follow-up RAT), and never bound
  `144.124.242.171` (the initial RAT) at all — yet scored `c2Correct: true` and
  `iocCoveragePct: 100`. Half the answer, graded as the whole. On a corpus where every
  other case has one C2 this was invisible. The metric needs to be coverage over the
  notes' C2 set, not membership of the first bound endpoint.

  **It is 2/2, not a flake.** Both repeats bound `5.252.177.69` and neither bound
  `144.124.242.171`, despite very different effort — `s1` took 136 tool calls and 79
  LLM calls, `s2` took 67 and 44. A systematic miss of the initial RAT's C2, not
  variance. This is the first reproducible correctness gap the bench has produced.
- **njRAT is the clean result, and it is the one the case was chosen for.**
  `njrat-s1` bound exactly one endpoint as C2 — `104.248.130.195` on port 7492, the
  true C2 — with 100% IOC coverage and 100% groundedness. The capture carries four
  abused-or-legitimate services (`api.telegram.org`, `checkip.dyndns.org`,
  `cphost.qhoster.net:587` SMTP exfil, and Cloudflare-fronted `reallyfreegeoip.org`)
  and none of them was bound as C2, yet all were written up. That is
  `c2_is_benign_service` answered correctly in a live run rather than in isolation.
- **`c2_ips` on that report is over-inclusive** — and njRAT shows it is not universal. It asserts eight addresses on a
  two-C2 case, including three Google (`142.251.186.97`, `142.250.138.95`,
  `172.217.72.101`) and two Akamai (`184.29.91.124`, `23.219.89.143`). Groundedness
  scores 100% because every one of them is in the packets — groundedness asks whether
  an address was *observed*, never whether the role assigned to it is right. Precision
  of the asserted C2 set is unmeasured, and this is the case that shows it needs to be.
- **`c2Correct` ignores hostnames, and Lumma's ground truth has a typo.** `lumma-s2`
  bound `64.89.161.173`, scored `c2Correct: false`, and is **right**: the capture
  contains `64.89.161.173` resolving to `futupath.cyou`, while the MTA notes write
  `64.89.161.73 port 80 - futupath.cyou` — a dropped digit in the published notes. The
  agent got the C2 by IP *and* by name. `c2Correct` tests `truth.ips.has(c2)` only,
  even though `iocMatch` already knows how to match a destination by resolved
  hostname. Two fixes, both cheap: let `c2Correct` accept a name match, and pin the
  known-bad IOC IP with a note so nobody re-derives this.

  Running total: of the `c2Correct: false` results, Lumma's is purely a notes typo.
  `2026-05-27` is subtler — see the next item. The metric is substantially measuring
  the corpus, but not entirely.
- **The enumeration gate narrowed coverage variance but did not close it, and 88%
  would fail the proposed CI floor.** The two Lumma runs bound the same correct C2 but
  split 88% / 100% on coverage. The single miss is `mega.nz` — an abused legitimate
  file-host, not a random omission. Pre-enumeration the same spread was 29–100%, so the
  gate did most of the work; what is left is a category, not noise. Two consequences:
  the **≥ 90% floor in item 3 would have failed `lumma-s1`**, so either the floor
  aggregates across runs or it drops to 85%; and the residual variance lives exactly in
  the abused-service class that `c2_is_benign_service` is supposed to adjudicate.
- **Groundedness is not 100%. It is 93–100%, and 2 of 6 new runs fabricated an
  address.** `lumma-s2` asserted `66.234.159.108` (99%) and `njrat-s2` asserted
  `173.166.146.112` (93%). Both confirmed absent from their captures with `tshark`
  directly, not just by the scorecard's own regex. The headline table's "Groundedness
  100%" was measured on the two easiest captures in the corpus and does not survive
  contact with the other five.

  This is the metric working — it found them with no answer key, which is the whole
  argument for it — but it is also **the number a SOC buyer is told about**, so it has
  to be quoted as a range from now on. Both are plausible-looking public IPv4s, which
  is the dangerous shape: an analyst cannot spot them by eye.

  **A third run fabricated a victim hostname, and it was caught by luck.**
  `smartape1-s1` published `who.hostname = "browser.host"` on the victim row. The
  string `browser` appears nowhere in that capture — not NBNS, not DHCP, not as a raw
  string. It was only checked because `host` happens to be in the scorecard's
  `PUBLIC_SUFFIXES`, so the DOMAIN regex treated it as a network indicator.

  **That exposes a real gap: `assertedAtoms` only checks tokens shaped like a domain
  or an IPv4.** A fabricated NetBIOS-style hostname — `DESKTOP-7XK2`, `WIN-ACCT01` —
  has no dot, is never checked, and would be published on the `who` row unmeasured.
  Hostname is precisely the field that reaches a ticketing system and names a real
  machine. Groundedness should check `who`/`where` identity fields against what the
  capture evidences (NBNS, DHCP option 12, Kerberos, SMB), not only against DNS/SNI/HTTP
  names. Until it does, the 93–100% range understates the true fabrication rate.

  Tally so far: **3 of 8 runs asserted something the packets do not support** — two
  IPv4s and one victim hostname.
- **`workspaceEscapes` fired for the first time.** `lumma-s2` attempted
  `.../hagfish/tools` and `.../bench/typesafe-s2` — both outside the case directory,
  both refused by the sandbox. Reach without escape, which is what the field is for.
- **Cost varies 2.4x on one capture at fixed config.** `smartape2-s1` cost $0.0841
  against `s2`'s $0.0346 — same case, same build, same prompt. The handoff's
  $0.0325/investigation was measured on the two easiest captures in the corpus; treat
  it as a floor, not a mean. Tool calls drove it: 136 against 67.
- **IOC coverage and C2 correctness are independent, and the first run shows it.**
  `smartape1-w1`: coverage 100%, grounded 100%, closed true, `c2Correct` false.
  Coverage is a text match over the report blob; a report can name every IOC and still
  assign the wrong role to the headline one. Do not read 100% coverage as a correct
  verdict.

## The groundedness gate: built, measured, and NOT yet validated

Built 2026-09-17: `requireGroundedReport` refuses a close asserting an indicator the
evidence does not carry, with a jev rung that can release a false positive but never
create a refusal. Measured 8 runs against 8, four cases, both arms re-scored with the
same fixed metric.

| | keyless | grounded |
|---|---|---|
| groundedness clean | 7/8 | 7/8 |
| groundedness range | 92–100% | 93–100% |
| **IOC coverage** | 88–100% | **100% on all 8** |
| cost mean | $0.0491 | $0.0564 (+15%) |
| wall mean | 497s | 527s (+6%) |
| refusals mean | 1.6 | 2.0 |

**The headline purpose was not achieved, and the reason matters more than the number.**

Groundedness is 7/8 in both arms, but the failures are different classes. `keyless`
failed on the real fabrication (`browser.host`). `grounded` failed on four
hosting-provider rDNS names — real data fetched from outside the capture.

So the gate did remove the fabrication class. It was then defeated: told to ground
`browser.host`, `smartape1-g2` published **`hostname: "tshark"`** — a string present in
every tool result, so occurrence passed it, the gate never fired, and groundedness
scored **100%** on a victim row naming the analysis tool. Swapping a plausible
fabrication for evidence-present nonsense is a worse report and a better score. The
7/8-vs-7/8 therefore *understates* the harm.

Fixed after the sweep: a `hostname` must now match a harvested host-naming identity
(NBNS, DHCP option 12, Kerberos, SMB), never a substring of the evidence. Pinned by a
regression test using the literal `tshark` case. **The sweep measured the broken
version, so the fixed gate is unmeasured — re-run before drawing any conclusion.**

What the sweep does establish, and it is the opposite of the predicted regression:
**IOC coverage rose and stopped varying** — 88–100% became 100% on all eight runs,
including Lumma's 50 destinations. The feared "model deletes the uncertain claim"
did not happen. Cost rose 15%, not the doubling that `smartape2` alone suggested.

Also fixed, and it invalidated earlier numbers: `captureAtoms` never scanned packet
**payload**, only IP headers, DNS answers, SNI, HTTP Host and NBNS. Two atoms this
bench called fabrications — `173.166.146.112` and `66.234.159.108` — are the victim's
own public IP returned in an HTTP/JSON body by `ip-api.com`, `checkip.dyndns.org`, and
in Lumma's case by the C2 itself. Both are real, well-evidenced, and among the most
useful indicators in those reports. The true fabrication count across the first sweep
was **1 of 8, not 3**.

## Groundedness measured against the raw capture is structurally wrong

Four atoms this bench reported as fabrications were real, and each exposed a different
blind spot in `captureAtoms`. The pattern is one thing, not four:

| atom | why it was missed | what it really is |
|---|---|---|
| `173.166.146.112` | headers only, no payload scan | victim's public IP from `ip-api.com` |
| `66.234.159.108` | headers only, no payload scan | victim's public IP, returned **by the C2** |
| `arc.msn.com` | `\b` after `com` fails on `arc.msn.com0` — the next ASN.1 byte is a printable digit | Microsoft telemetry in TLS payload |
| `mcnzxz.com` | **gzip-compressed on the wire** | MassLogger SMTP exfil accounts `kingsnake1@`/`kingsnakeresult@`, in a decompressed carve alongside `cphost14.qhoster.net` and three other published IOCs |

The first two are fixed by scanning payload, the third by dropping word boundaries in
payload. **The fourth is not fixable this way at all.** Malware configuration is
routinely compressed or encoded, so a groundedness check that reads raw capture bytes
will keep calling the most valuable indicators in a report hallucinations — exfil
accounts, C2 config, encoded beacons. It is wrong precisely where it matters most.

**The product gate does not have this problem, and that is the design lesson.**
`requireGroundedReport` checks against `evidenceText` — what the investigation actually
extracted, the agent's own decompression included. It passed `mcnzxz.com` correctly
because the agent had decompressed the stream and the name was genuinely in evidence.
The bench metric, reading the pcap, called the same claim a fabrication. **Evidence the
investigation gathered is a better groundedness standard than the capture file**, and
this was chosen for the gate before any of this was known.

Consequence for the numbers: every `groundedPct` in the ledger over-reports fabrication
for compressed or encoded indicators. Across 24 graded investigations the count of
genuine fabrications is **one** — `browser.host`, absent by every method.

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
- **The verifier has never *decided* a live bind.** It is consulted constantly —
  `verifierConsultations` is 1–7 on all 17 scorecard records — but always about
  non-C2 destinations. Both bound C2s so far are plain IPs (`165.22.199.85`,
  `185.14.92.102`), so the case `judgeCdnOrUpdate` exists for — refusing to drop a
  CDN-fronted C2 — is proven only on the real code path in isolation (3/3 refused
  → bound), never end to end. Do not read the original phrasing ("never fired") as
  "never runs".

  Worth holding onto: the CDN axis and the coverage axis are the same axis. Both 29%
  runs (`amos-clean-073553`, `amos-b3`) missed exactly the five Cloudflare-fronted AMOS
  domains — `clean-disk-tools.com`, `kernel-87.com`, `node-slate.com`,
  `frame-facet.com`, `wuess.com`.

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

**The `no-web` control does not cover `bash`, and the agent uses the network.**
Found 2026-09-17 while the groundedness gate was running. `no-web.cordis.yml` disables
the `web`, `web-search-deepseek` and `tool-web` plugins. It does **not** stop the
`bash` tool reaching the network.

**Corrected 2026-09-17.** This first read "**23 of 25 graded runs**, every build". That
was wrong. The count came from a word-boundary regex matching the bare word `host`
inside arguments — `grep -i host`, and tshark's own `http.host` field, which appear
constantly in pcap work. It is the **identical false positive** the policy's own tests
later caught in the deny code, and the audit was never re-run with the corrected
detector.

Measured with command-position detection: **0 of 8 `keyless` runs** made a real network
call, and 2 of 8 in each gated arm. The prevalence was badly overstated. The control
gap itself is real, directly observed once, on `smartape2-g2`.

What actually happens, measured from `smartape2-g2`'s own probe:

| | result | meaning |
|---|---|---|
| `getent hosts 5.252.177.69` | **exit 0**, returned `no-rdns.mivocloud.com` | reverse DNS **works** |
| `curl https://dns.google/resolve?name=x.com` | HTTP `000`, **exit 60** | HTTPS **fails** — TLS cert verification |

Two consequences, and they point opposite ways.

*The reassuring one:* no run ever referenced `malware-traffic-analysis.net`, `abuse.ch`
or `virustotal` from `bash` — audited across all 25. And curl exit 60 means HTTPS to the
open web fails anyway. **The published numbers are not contaminated by web fetches.**

*The alarming one:* that containment is **accidental, not enforced** — rarely exercised
on this corpus, but nothing stops it. Exit 60 is a
certificate failure, not a policy denial — a runner with a working CA bundle fetches the
answer key just fine. CI is exactly such a runner. And `externalSearches: 0` is false
comfort: it counts `web_search` tool calls only, so it read zero on the runs that did
query DNS.

*And it is already affecting reports.* `smartape2-g2` published four hosting-provider
reverse-DNS names — `arc.msn.com`, `v924398.hosted-by-vdsina.com`,
`no-rdns.mivocloud.com`, `clients.your-server.de` — none of which the capture carries.
Groundedness correctly flagged all four at 93%. They are not confabulations; they are
**real data from outside the evidence**, which is arguably worse for grading because it
is correct and unciteable.

Work:

1. **Done.** `denyNetworkReachback` on `investigation` refuses a shell command that runs
   a network-reaching program. Off by default; graded runs set
   `DSH_DENY_NETWORK_REACHBACK=1`. It checks **command position**, not bare words —
   the reachback actually seen was `cd <case> && (timeout 6 getent hosts <ip>)`, whose
   head token is `cd`, while `grep -i host file` names no program at all. Both are
   pinned by tests.

   **It is advisory, not a sandbox.** A program denylist does not stop
   `python3 -c "import socket"`. The real control is running the investigation with no
   route; this makes the common case fail loudly and name the reason.
2. **Done.** `networkCommands` on the scorecard's production block counts reachback from
   any shell tool, using the same command-position test. `externalSearches` stays as it
   was so the existing records keep their meaning — it counts `web_search` only, and
   that is now documented rather than mistaken for coverage.
3. **Still open, and it is a product decision, not a test one.** Live rDNS on a
   customer's own traffic is legitimate tradecraft and forbidding it outright would be
   wrong. The likely shape: an enriched name must be *cited as enrichment* rather than
   asserted as observed — which is what the groundedness gate already demands. Nobody
   has decided this.

Caveat on the records: `networkCommands` landed mid-sweep, so `smartape2-g1` and
`smartape2-g2` predate the field. The reachback in those two runs is documented above
from their session logs directly.

**`workspaceEscapes` is now on every scorecard record.** It lists tool-call paths
outside the run directory. They are attempts, not successes — the sandbox refuses a
path outside the case directory, which `remcos-n2` demonstrated by trying
`cd /home/.../dsal-analyst` and getting `Error: refusing shell: ... is outside the case
directory`. Read containment is enforced, and this metric is what would catch it
regressing. Non-empty is a reason to read the log, not an automatic failure.

**The session workspace must be the run directory, and it is not free.** `pnpm` runs a
workspace script with cwd set to the package root, so `cd <run-dir> && pnpm dsh ...`
silently gives the agent the **repo** as its writable workspace. The first sweep run
did exactly this: it read `bench/typesafe-triage/cases/` with the original MTA
filenames, found the notes files, and reasoned *"The four IPs match the handoff"* before
it was killed. That session was discarded and never reached the ledger. Pass
`DSH_CASE_DIR=<run-dir>`; `sweep.mjs` does, and refuses to score any run whose session
log is not named after its run directory.

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
