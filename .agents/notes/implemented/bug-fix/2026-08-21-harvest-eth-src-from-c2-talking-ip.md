# Agent Note: Persist eth.src sourced from the C2-talking LAN IP

Status: implemented

English | [中文](2026-08-21-harvest-eth-src-from-c2-talking-ip.zh.md)

## Problem

Live First to Last r3 (`365f74e`, Bedrock 30B) scored 4/5. Quote-strip, C2 hunt scoping, and hostname harvest attached `who` and `where` to the C2-talking client. The reported MAC was the far-side NIC: the `eth-src` hunt ran `ip.addr == <client>` (both directions) and the model picked the first MAC in the dump. The gold client MAC was also harvested.

`harvestIdentities` recorded every MAC in tool text. `huntNotice` for `eth-src` used `ip.addr ==` the subject, the same qualifier as name-service, Kerberos, and SAMR.

## Decision

After `c2TalkingLanIps` has a focus IP, `harvestIdentities` records a MAC only when it is sourced from that IP: labeled `ip.src` equal to the focus with `eth.src` (or the first MAC on that line), an outbound `focus → peer` conversation line, or ARP `<focus> is at <mac>`. Inbound `peer → focus` lines and idle LAN workstation lines are not recorded. When the current text has no IPv4 and only labeled `eth.src` columns, a strict majority MAC is recorded; a tie records none, so a bidirectional dump cannot win.

`huntNotice` for `eth-src` uses `display_filter` `(eth.src) and ip.src == <subject>` and field `eth.src`. Other IP-subject hunts keep `ip.addr ==` ([two-client fusion](2026-08-20-scope-identity-hunts-to-c2-talking-client.md)). Detection uses the current tool result plus folded `tool/result` text already on the session log.

[Quote-strip](2026-08-21-pcap-filter-quoted-display-filter.md), [string-field coerce](2026-08-20-pcap-filter-string-fields.md), and [hostname harvest](2026-08-20-harvest-hostname-from-tshark-summaries.md) stay as they are. Scout, family harvest, auto-run hunts, leftover-report bans, and new evals stay out of this change.

## Alternatives considered

**Keep `ip.addr ==` on the eth-src notice and teach the model to pick the client MAC.** Rejected: r3 already harvested both MACs; the model picked the first.

**Record every MAC on a line that mentions the focus IP.** Rejected: that is `ip.addr` semantics. Inbound frames contribute the far-side NIC.

**Auto-run the scoped pcap_filter hunt.** Rejected: this knob is persist and notice text. Execution stays with the model.

**Bake case gold MACs into prompts or tests.** Rejected: tests use a synthetic two-client, two-MAC fixture. Case names, IPs, and MACs are not expected answers.

**Change name-service, Kerberos, and SAMR notices to `ip.src`.** Rejected: those hunts need replies to the client. `ip.addr` stays for them.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` and `hunts.spec.ts` feed a synthetic two-MAC fixture (one LAN IP talks to a TEST-NET peer; the other stays on-LAN). After the C2-talking IP is seen, only the MAC sourced from that IP is recorded. A bidirectional field dump with two `eth.src` values records only the `ip.src ==` focus MAC. `huntNotice` for `eth-src` contains `ip.src ==` and does not contain `ip.addr ==`. `investigation.spec.ts` records the sourced MAC through post-execute.

## Consequences

A bidirectional `eth.src` dump cannot persist the far-side NIC as identity. The model is told to filter `ip.src ==` the C2-talking LAN IP. Hostname, user, and full_name harvest stay unscoped.
