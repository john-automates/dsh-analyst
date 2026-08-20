# Agent Note: Scope identity hunts to the C2-talking LAN client

Status: implemented

English | [中文](2026-08-20-scope-identity-hunts-to-c2-talking-client.zh.md)

## Problem

Live First to Last r1 (`20b7854`, Bedrock 30B, mta-2026-08-09) scored 2/5. Session cwd was the case directory. Hunts issued and ran in volume. The C2-talking LAN IP and its hostname passed. MAC, user, and full name failed because harvest and `case_report` `who` attached to the other LAN workstation. Easy as 123 hid this: it has one client.

`huntsForNewIdentities` issued `eth-src`, `name-service`, `kerberos-cname`, and `samr-userinfo` for every new IP, and Kerberos/SAMR for every new hostname and user. Notices used unscoped `eth.src`, `kerberos.CNameString`, and SAMR filters.

## Decision

After a LAN IP shares a tool-output line with a non-LAN unicast peer, subsequent `eth-src`, `name-service`, `kerberos-cname`, and `samr-userinfo` hunts issue only for that C2-talking IP. Other LAN workstations, the external peer, hostnames, and users do not receive those identity hunts. Dedup remains kind+subject.

`c2TalkingLanIps` reads one conversation per line. RFC1918 is LAN. Loopback, link-local, multicast, reserved, and broadcast are not C2 peers. Idle LAN-to-LAN lines do not focus a client. Detection uses the current tool result plus folded `tool/result` text already on the session log.

`huntNotice` for an IP-subject hunt includes `ip.addr ==` that subject in `display_filter`. Hostname and user notices stay unscoped; they are not issued once a C2-talking IP is known.

The [analyst investigation preset](../feature/2026-08-20-analyst-investigation-preset.md) still owns harvest, SAMR, and the other hunt knobs. `DSH_CASE_DIR`, string-field coerce, XML recovery, hostname harvest, and invalid tshark field rejection stay as they are.

Scout, family harvest, auto-run hunts, and new evals stay out of this change.

## Alternatives considered

**Change only the methodology prompt.** Rejected: r1 already issued and ran identity hunts. The miss was issuance for every LAN workstation, not a missing prompt sentence.

**Auto-run the scoped pcap_filter hunts.** Rejected: this knob is issuance and notice text. Execution stays with the model.

**Bake case gold identities into prompts or tests.** Rejected: tests use a synthetic two-client fixture (one LAN IP talks to an external TEST-NET peer; the other stays on-LAN). Case names, IPs, MACs, and users are not expected answers.

**New `SessionEventMap` member for the C2-talking IP.** Rejected: the conversation is already in `tool/result` text. Folding that text avoids a new event and SDK snapshot churn.

**Drop already-issued idle-workstation hunts from the log.** Rejected: the log is append-only. Suppression applies to subsequent issuance once the C2-talking IP is known.

## Testing

`packages/analyst/investigation/tests/hunts.spec.ts` feeds a synthetic two-client fixture. After the C2-talking LAN IP is seen, `huntsForNewIdentities` issues identity hunts only for that IP. `huntNotice` includes `ip.addr ==` that subject and does not name the idle workstation. Dedup, single-client issuance, and invalid tshark field rejection stay covered by existing tests.

## Consequences

A conversation dump that names two LAN clients focuses identity hunts on the one talking to a non-LAN peer. The model is not told to hunt the idle workstation as `who`. Hostname harvest still records whatever names appear in tool text.
