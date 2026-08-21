# Agent Note: Reject protocol-field harvests and stamp field-only SAMR/CName from the conversation client

Status: implemented

English | [中文](2026-08-21-reject-protocol-field-stamp-field-only-samr.zh.md)

## Problem

Live lumma-r13 (`97a1e42`) bound the cited conversation correctly (victim `10.1.21.58` / c2 `153.92.1.49`). Close bar 3/5 — IP PASS, hostname PASS, full_name PASS (unique-unaffiliated). User FAIL: the workstation account was ledger/print only. MAC FAIL is a separate [talking-IP donate](2026-08-21-stamp-mac-evidence-from-talking-ip.md) regression and is out of this change.

[Conversation-client stamp](2026-08-21-stamp-user-fullname-from-conversation-client.md) did not fire. SAMR/CName dumps were field-only (`kerberos.CNameString` / `samr.samr_UserInfo21.account_name` with no `ip.src` on the line), so `conversationClientIp` returned undefined and harvest wrote no `evidence_id`. After bind, full_name donated via unique-unaffiliated. User did not, because uniqueness was broken by garbage harvests that entered the user ledger as values: a tshark header or empty field (`samr.samr_UserInfo21.account_name:`) and a truncated dump (`account_name: [truncated:`).

## Decision

Protocol field names and truncated dumps are not identities. A captured user or full_name that looks like a tshark/SAMR/Kerberos field (`samr.samr_UserInfo21.account_name`, `kerberos.CNameString`, a `.` protocol prefix, a trailing `:`) or a truncation marker (`[truncated`, `[truncated:`) does not enter the ledger. Empty captures stay rejected.

A real SAMR/CName harvest on a field-only DC-scoped dump stamps `evidence_id` from the conversation client in `evidenceText`: the LAN / non-DC peer talking to that DC (`ip.src` or `LAN → DC`). Hunt-subject DC does not win. A client-stamped `evidence_id` is not passed into `conversationClientIp` as if it were the DC.

After a live bind, a real user stamped or evidenced on the victim client donates even when other real domain accounts exist, as long as those others are not the victim-client. Garbage rows do not exist to break uniqueness. The persisted who/where carry that user. Slots are not invented.

[Conversation-client stamp](2026-08-21-stamp-user-fullname-from-conversation-client.md) still owns on-line Kerberos/SAMR `ip.src`. [Talking-IP MAC stamp](2026-08-21-stamp-mac-evidence-from-talking-ip.md) and [hostname donate](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) stay. Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and idle or DC LAN row.

## Alternatives considered

**Keep harvesting protocol-field and truncated captures and teach `uniqueUnaffiliated` to ignore them.** Rejected: those strings are not identities. They must not enter the user or full_name ledger.

**Stamp hunt-subject `evidence_id` on a field-only SAMR/CName dump.** Rejected: SAMR/CName hunts are typically scoped to the DC. That locks the workstation account to the DC.

**Pass a client-stamped `evidence_id` into `conversationClientIp` as hunt-subject `scopeIp`.** Rejected: after a correct harvest stamp the client IP equals `ip.src`. Treating that stamp as the DC returns the other end and donates to the DC. [Conversation-client stamp](2026-08-21-stamp-user-fullname-from-conversation-client.md) already recorded this.

**Change the MAC talking-IP path so field-only SAMR dumps also restamp MAC.** Rejected: MAC donate stays on talking-IP frames. This knob does not change that path.

**Donate every unaffiliated user when garbage is gone.** Rejected: two real domain accounts with no victim-client conversation must donate neither. Victim-client stamp or evidence is what selects the workstation account.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP, a TEST-NET peer, and an idle or DC LAN row.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` feeds a synthetic LAN client (`10.0.10.2`), TEST-NET peer (`198.51.100.80`), and idle or DC row (`10.0.10.3`). `samr.samr_UserInfo21.account_name:` and `account_name: [truncated:` do not harvest as user. A real `kerberos.CNameString: lan-user` or `samr.samr_UserInfo21.account_name: lan-user` on a field-only DC-scoped dump stamps `evidence_id=10.0.10.2` when evidence text has `10.0.10.2 → 10.0.10.3` or `ip.src` `10.0.10.2` talking to that DC. Passing the client as `scopeIp` does not stamp the DC.

`packages/analyst/investigation/tests/bind.spec.ts` records that client-stamped user plus a second domain account sourced from `10.0.10.3`. After a live bind, the client user donates and persists on who/where. The DC-sourced account does not. MAC talking-IP donate and hostname donate stay.

## Consequences

A field-only DC-scoped first harvest can still stamp the workstation account onto the conversation client. Protocol-field and truncated captures cannot occupy the user ledger or veto unique-unaffiliated donate. Other real domain accounts without a victim-client conversation stay off the victim row. MAC talking-IP donate and hostname donate are unchanged.
