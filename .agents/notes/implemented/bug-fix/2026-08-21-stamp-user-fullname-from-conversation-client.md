# Agent Note: Stamp user and full_name evidence_id from the conversation client, not the hunt subject

Status: implemented

English | [中文](2026-08-21-stamp-user-fullname-from-conversation-client.zh.md)

## Problem

Live lumma-r12 (`1b29190`) bound the cited conversation correctly (victim `10.1.21.58` / c2 `153.92.1.49`). [Talking-IP MAC stamp](2026-08-21-stamp-mac-evidence-from-talking-ip.md) restamped the gold MAC from victim-IP frames and tagged `[victim]`; DC and gateway MACs stayed off. Close bar 3/5 — user FAIL and full_name FAIL. Both were ledger-only and untagged. r11 scored 4/5 (had user+name, missed MAC).

`harvestIdentities` stamps `evidence_id` on MAC (talking IP) and hostname (hunt subject). User and full_name get no stamp. SAMR/CNameString hunts are typically scoped to the DC. `uniqueUnaffiliated` donate then fails when other domain accounts sit on the ledger, or the identities stay unaffiliated and never persist onto who/where.

## Decision

A harvested user (`kerberos.CNameString` / `account_name`) or full_name (`samr.samr_UserInfo21.full_name`) stamps `evidence_id` from the client IPv4 of that conversation: the LAN / non-DC end (`ip.src` talking to a DC, or the peer that is not the hunt-subject `scopeIp`). Hunt-subject `scopeIp` (usually the DC) does not stamp user or full_name.

After a live bind, a user or full_name first seen under a DC or peer hunt still donates to the victim when that conversation's client (`ip.src`) is the bound victim. A client-stamped `evidence_id` is not a hunt-subject DC and does not invert the endpoints. Hunt-subject `evidence_id` does not veto donate. The persisted who/where carry that user and full_name. A domain account that never appears as the client of a conversation whose client is the bound victim does not donate. Slots are not invented.

[Talking-IP MAC stamp](2026-08-21-stamp-mac-evidence-from-talking-ip.md) and [hostname donate](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) stay. Cue-as-victim stays refused and still issues [other-end](2026-08-21-other-end-hunt-on-cue-victim.md). Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and idle or DC LAN row.

## Alternatives considered

**Keep user and full_name untagged and teach `uniqueUnaffiliated` to ignore other domain accounts.** Rejected: other accounts on the ledger are real. Uniqueness cannot tell which account is the conversation client.

**Stamp hunt-subject `evidence_id` on user and full_name.** Rejected: SAMR/CNameString hunts are typically scoped to the DC. That locks the workstation account to the DC, the MAC hole [talking-IP stamp](2026-08-21-stamp-mac-evidence-from-talking-ip.md) already closed.

**Pass a stamped client `evidence_id` into `conversationClientIp` as hunt-subject `scopeIp`.** Rejected: after a correct harvest stamp the client IP equals `ip.src`. Treating that stamp as the DC returns the other end and donates to the DC.

**Restamp `evidence_id` on a later victim-client dump.** Rejected: `recordIdentity` is unique on kind+value. Donate reads the conversation instead of rewriting the ledger row.

**Donate every unaffiliated user or full_name of a kind.** Rejected: two domain accounts with no victim-client conversation must donate neither.

**Donate a domain account that never appears as the client of a conversation whose client is the bound victim.** Rejected: those accounts stay off the victim row.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP, a TEST-NET peer, and an idle or DC LAN row.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` feeds a synthetic LAN client (`10.0.10.2`), TEST-NET peer (`198.51.100.80`), and idle or DC row (`10.0.10.3`). A user or full_name on a Kerberos/SAMR conversation whose client is `10.0.10.2` stamps that IP even when `scopeIp` is `10.0.10.3`. Hostname still stamps the hunt subject. A field-only CNameString dump does not inherit hunt-subject `evidence_id` on user.

`packages/analyst/investigation/tests/bind.spec.ts` records a user+full_name with `evidence_id=10.0.10.3`, untagged from a DC-scoped dump, or already stamped `evidence_id=10.0.10.2`, then evidence text of a Kerberos/SAMR conversation whose client is `10.0.10.2`. After a live bind, those values donate and persist on who/where. A second domain account on `10.0.10.3` does not donate. MAC and hostname donate and cue-as-victim refusal stay.

## Consequences

A DC-scoped first harvest cannot lock a workstation user or full_name to the DC when the conversation names a different client IP. A wrong first stamp, an untagged row, or a correct client stamp still donates if later Kerberos/SAMR text shows `ip.src` as the bound victim. Other domain accounts without that client stay off the victim row. MAC talking-IP donate and hostname donate are unchanged.
