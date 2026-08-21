# Agent Note: Bind case_report who/where to the C2-talking LAN identity

Status: implemented

English | [中文](2026-08-21-case-report-c2-talking-lan-identity.zh.md)

## Problem

Live lumma-r1 (`04f45ee`, mta-2026-01-31-lumma-in-the-room-ah, Bedrock 30B) scored 3/5. hostname, user, and full_name passed. IP and MAC failed: `case_report` wrote the cue C2 IP and a remote MAC as the victim. The investigation ledger already held the C2-talking LAN IP and the sourced client `eth.src`. This is the same victim/C2 inversion as First to Last r4, now at close time rather than harvest.

[Sourced MAC harvest](2026-08-21-harvest-eth-src-from-c2-talking-ip.md) and [auto-run hunts](2026-08-21-auto-run-outstanding-identity-hunts.md) already put the LAN identity on the ledger. `case_report` still persisted whatever the model sent.

## Decision

When a C2-talking LAN IP is known — `c2TalkingLanIps` has a focus IP, or the ledger has exactly one LAN IP and a non-LAN unicast IP — `case_report` rewrites `who` and `where` before `recordReport`. A non-LAN unicast IP in a field that does not already contain the focus LAN IP becomes that LAN IP. A MAC other than the unique ledger MAC, in a field that does not already contain that MAC, becomes that `eth.src`. `what`, `when`, `why`, and `how` are unchanged. Hostname, user, and full_name are not inserted.

No focus IP leaves the packet as submitted. Two ledger LAN IPs without `c2TalkingLanIps` do not pick a victim. Several ledger MACs do not invent a sourced MAC.

[Quote-strip](2026-08-21-pcap-filter-quoted-display-filter.md), [string-field coerce](2026-08-20-pcap-filter-string-fields.md), `ip.src` for `eth-src`, [sourced MAC harvest](2026-08-21-harvest-eth-src-from-c2-talking-ip.md), and [auto-run](2026-08-21-auto-run-outstanding-identity-hunts.md) stay as they are. Scout, family harvest, leftover-report bans, and new evals stay out of this change.

## Alternatives considered

**Reject the tool call.** Rejected: lumma-r1 already closed. A retry is the same inversion that harvest and notices did not stop.

**Change only the methodology prompt or the tool description.** Rejected: the ledger already named the LAN client.

**Rewrite an idle LAN IP in who/where onto the focus IP.** Rejected: that is [two-client fusion](2026-08-20-scope-identity-hunts-to-c2-talking-client.md). This knob is victim/C2 inversion.

**Insert ledger hostname, user, or full_name.** Rejected: names are not invented.

**Bake gold IPs, MACs, or names from Easy as 123, First to Last, or Lumma into prompts or tests.** Rejected: tests use a synthetic LAN client and TEST-NET peer.

**Invent evals or touch scout.** Rejected: this knob is close-packet bind after the ledger is filled.

## Testing

`packages/analyst/investigation/tests/report.spec.ts` binds a synthetic ledger (LAN client + external C2 + one client MAC). A packet that names the C2 as who/where is rewritten to the LAN client. Evidence-only `c2TalkingLanIps` rewrites the IP without inventing a MAC. A field that already names the focus LAN IP is left alone. `packages/analyst/analyst-tools/tests/tools.spec.ts` records that ledger and executes `case_report`; the persisted packet and tool result show the LAN IP and sourced MAC.

## Consequences

A `case_report` that names the C2 as the infected host persists the C2-talking LAN IP and, when unique, its sourced `eth.src`. Correct who/where that already name that client stay as written. Hostname, user, and full_name still come only from the model or from harvest, not from this rewrite.
