# Agent Note: Auto-issue MAC and name-service hunts after a new IP

Status: implemented

English | [中文](2026-08-20-auto-issue-mac-and-name-service-hunts.zh.md)

## Problem

Live r6 (`b9f2075`, Bedrock 30B, Easy as 123) scored 3/5. User `brolf`, full name `Becka Rolf`, C2, and IP `10.2.28.88` passed. MAC `00:19:d1:b2:4d:ad` failed because `eth.src` was never issued. Hostname `DESKTOP-TEYQ2NR` failed because this run never dumped LLMNR/NBNS/BROWSER, so [hostname-summary harvest](2026-08-20-harvest-hostname-from-tshark-summaries.md) had no name-service lines to read.

`huntsForNewIdentities` issued only `kerberos-cname` and `samr-userinfo` after a new IP. After the infected IP, the model did not hunt L2 or name service. r3 had issued `eth.src` and scored 4/5.

## Decision

A new IP also issues `eth-src` and `name-service` for that subject, then the existing Kerberos and SAMR hunts. `name-service` uses display filter `llmnr or nbns or browser`. SMB is not a `HuntKind` and is not issued. New hostname and user issuance is unchanged. Dedup remains kind+subject against existing hunts and the batch itself.

`huntNotice` names valid tshark 4.4.16 fields: `eth.src` for the MAC hunt (with `ip.src ==` the C2-talking IP when known; [sourced MAC](2026-08-21-harvest-eth-src-from-c2-talking-ip.md)), and `llmnr`, `nbns`, and `browser` for the name-service hunt that produces DESKTOP-* / NBNS Registration / BROWSER Host Announcement lines. After a LAN IP talks to a non-LAN peer, those identity hunts issue only for that C2-talking IP ([two-client fusion](2026-08-20-scope-identity-hunts-to-c2-talking-client.md)). The [analyst investigation preset](../feature/2026-08-20-analyst-investigation-preset.md) still owns harvest, SAMR, and the other hunt knobs.

Scout, family harvest, and new evals stay out of this change. Execution of issued hunts is [auto-run outstanding issued identity hunts](2026-08-21-auto-run-outstanding-identity-hunts.md).

## Alternatives considered

**Change only the methodology prompt.** Rejected: r6 already followed Kerberos then SAMR after the IP. The missing hunts were never issued, so the model had no MAC or name-service notice.

**Auto-run the pcap_filter hunts.** Rejected for this issuance knob: execution is [auto-run outstanding issued identity hunts](2026-08-21-auto-run-outstanding-identity-hunts.md).

**Add an SMB hunt kind.** Rejected: SMB is not already a `HuntKind`. Hostname harvest already reads SMB summaries when those lines appear.

**Issue MAC or name-service after a new hostname.** Rejected: the live miss is a new IP with no L2 or name-service hunt.

**Add family harvest or invent evals in the same change.** Rejected: those are separate knobs.

## Testing

`packages/analyst/investigation/tests/hunts.spec.ts` issues `eth-src` and `name-service` after a new IP, keeps hostname and user issuance unchanged, and dedupes against existing hunts. `huntNotice` must name `eth.src`, `llmnr`, `nbns`, `browser`, DESKTOP-*, NBNS Registration, and BROWSER Host Announcement, and must not name `smb`.

## Consequences

A recorded new IP appends MAC and name-service hunts so the model is told to dump `eth.src` and LLMNR/NBNS/BROWSER. Hostname still depends on those summary lines reaching harvest. Family harvest remains deferred.
