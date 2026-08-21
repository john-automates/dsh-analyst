# Agent Note: Auto-run outstanding issued identity hunts

Status: implemented

English | [中文](2026-08-21-auto-run-outstanding-identity-hunts.zh.md)

## Problem

Live First to Last r4 (`a11b092`, Bedrock 30B) scored 0/5. [Sourced MAC harvest](2026-08-21-harvest-eth-src-from-c2-talking-ip.md) did fire: after the LAN IP was harvested, the plugin issued `eth-src` with `(eth.src)` and `ip.src ==` that LAN client. The model never ran that hunt. It queried `eth.src` on the external C2 IP from the task cue, wrote a C2-side MAC, then `who` became the idle LAN workstation. `case_report` was never called (`write` was). The gold client MAC never entered the ledger.

Issuance and notice text were already correct. Execution waited for `pcap_filter`.

## Decision

When `autoHunt` is true, outstanding issued identity hunts — `eth-src`, `name-service`, `kerberos-cname`, and `samr-userinfo` — execute through `pcap_filter` with the scoped `display_filter` and fields from `huntFilterSpec` / `huntNotice`. The plugin does not wait for the model to call `pcap_filter`. Each dump harvests into the identity ledger as usual.

When a C2-talking LAN IP is known, only that subject's hunts auto-run. A hunt whose subject is a non-LAN / C2 IP never auto-runs, except [`other-end`](2026-08-21-other-end-hunt-on-cue-victim.md), which hunts LAN `ip.src` talking to that cue. Hostname and user hunts auto-run only before a C2-talking LAN IP is known.

The capture path is the triggering pcap tool's `path` when that argument has a capture suffix, otherwise the first `*.pcap` / `*.pcapng` / `*.cap` under `evidence/` or the case root. Missing `pcap_filter` or a missing capture skips execution. A failed hunt does not fail the triggering tool. Already-attempted hunts are not retried on the same session.

[Quote-strip](2026-08-21-pcap-filter-quoted-display-filter.md), [string-field coerce](2026-08-20-pcap-filter-string-fields.md), `ip.src` (not `ip.addr`) for `eth-src`, and [two-client fusion](2026-08-20-scope-identity-hunts-to-c2-talking-client.md) stay as they are. Scout, family harvest, leftover-report bans, and new evals stay out of this change.

## Alternatives considered

**Keep waiting for the model to run the issued hunt.** Rejected: r4 issued the correct `eth-src` and the model ran a different filter on the C2 IP.

**Change only the methodology prompt.** Rejected: the notice already named `(eth.src)` and `ip.src ==` the LAN client.

**Auto-run hunts for every issued subject, including the C2 IP.** Rejected: that persists the far-side NIC. Non-LAN identity-hunt subjects do not auto-run. `other-end` is a separate exception ([other-end](2026-08-21-other-end-hunt-on-cue-victim.md)).

**Bake gold identities into prompts or tests.** Rejected: tests use a synthetic LAN client and MAC. Case names, IPs, and MACs are not expected answers.

**Add a `SessionEventMap` member for hunt execution.** Rejected: identities harvested from the dump are already logged. A new event would churn SDK snapshots.

**Invent evals or touch scout.** Rejected: this knob is execution after issuance.

## Testing

`packages/analyst/investigation/tests/investigation.spec.ts` registers a stub `pcap_filter`. After an echo that harvests a LAN client, issued `eth-src` executes with `(eth.src)` and `ip.src ==` that client even though the model never called `pcap_filter`. The synthetic MAC is harvested. A C2 IP subject is not executed. `hunts.spec.ts` pins `huntFilterSpec` and `shouldAutoRunHunt`.

## Consequences

A recorded LAN-client `eth-src` dump enters the ledger without a model `pcap_filter` call. The model can still call `pcap_filter`; already-executed hunts are not re-run on the same session. Hostname and user hunts still depend on those dumps reaching harvest.
