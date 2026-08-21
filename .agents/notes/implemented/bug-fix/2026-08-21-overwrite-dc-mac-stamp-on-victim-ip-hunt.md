# Agent Note: Overwrite a DC/peer MAC stamp when a later victim-IP hunt sources it

Status: implemented

English | [中文](2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.zh.md)

## Problem

Live lumma-r18 (`90eaf1c`) bound the cited conversation correctly. Close bar 4/5. ip/hostname/user/full_name persisted. `mac` did not. Model-submitted DC/gateway MACs stayed off.

The gold MAC was already on the ledger with a DC-scoped `evidence_id` from the first harvest (DC hunt subject). A later victim-IP `eth.src` hunt ran (`(eth.src) and ip.src == <victim>`, field `eth.src`) and harvested the same MAC. [Victim-IP-scoped restamp](2026-08-21-restamp-victim-ip-scoped-eth-src.md) only fills a missing `evidence_id`. `recordIdentity` / `foldIdentities` refused to overwrite the sticky DC stamp. Donate then treated the row as DC-scoped and did not persist `mac` on who/where.

A MAC that only appears on DC/gateway frames must stay off. A later DC/peer harvest must not overwrite an existing victim stamp.

## Decision

After a victim-IP `eth.src` hunt or field-only dump scoped to a talking IP, restamp that MAC onto that IP even when the first-seen row already has a DC/peer `evidence_id`. Persist `mac` on who/where through the existing donate and `completeAcceptedSlot` path. ip/hostname/user/full_name stay.

`recordIdentity` unique-on-kind+value still yields one row. A later MAC event overwrites `evidence_id` when the new id is the bound victim or a C2-talking LAN IP and the existing id is not. A missing first stamp still fills. A later DC/peer stamp does not overwrite a victim or C2-talking stamp. Other kinds keep the first non-empty stamp.

A DC or gateway MAC that never appears as `eth.src` on victim-IP frames or in a victim-IP-scoped dump stays off. "DC-scoped stay off" means those frames, not a MAC first harvested under a DC hunt subject and later seen on victim-IP frames.

[Victim-IP-scoped restamp](2026-08-21-restamp-victim-ip-scoped-eth-src.md) still owns filling a missing stamp. [Talking-IP MAC stamp](2026-08-21-stamp-mac-evidence-from-talking-ip.md) still owns same-line donate. [Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) still owns fill-on-omit. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and idle or DC LAN row.

## Alternatives considered

**Keep restamping only when `evidence_id` is empty.** Rejected: the live gold MAC already carried a DC hunt-subject stamp. Donate requires `evidence_id` of the victim on a field-only dump, so the sticky DC stamp dropped `mac`.

**Teach donate to treat a field-only victim-IP `eth.src` dump as victim-sourced without rewriting the ledger row.** Rejected: auto-run dump text is `eth.src: MAC` only. The scope lives on the hunt / `display_filter`, which harvest already records as `evidence_id`. Folding that later stamp onto the first-seen row is the same restamp rule [victim-IP-scoped restamp](2026-08-21-restamp-victim-ip-scoped-eth-src.md) already uses.

**Overwrite a victim or C2-talking stamp with a later DC/peer stamp.** Rejected: a correct victim stamp must stick.

**Donate a MAC that never appears as `eth.src` on victim-IP frames or in a victim-IP-scoped dump.** Rejected: those NICs stay off the victim row.

**Invent a MAC, drop ip/hostname/user/full_name, bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: persist still copies only donated slots. The fixture is a synthetic LAN client, TEST-NET peer, and idle or DC LAN row.

## Testing

`packages/analyst/investigation/tests/investigation.spec.ts` records `CLIENT_MAC` with `evidence_id=10.0.10.3` after a live bind (victim `10.0.10.2`), then a field-only victim-IP `eth.src` dump. The row restamps to `10.0.10.2`. A later DC-scoped dump of the same MAC does not overwrite. Fold overwrites DC→victim when the log has a live bind or a C2-talking line, and keeps victim→DC. Hostname keeps the first non-empty stamp.

`packages/analyst/investigation/tests/bind.spec.ts` takes `CLIENT_MAC` first stamped `10.0.10.3`, then restamped `10.0.10.2`, plus a DC MAC on a DC-scoped dump. After a live bind, who/where that omit `mac` persist `CLIENT_MAC` and keep ip/hostname/user/full_name. The DC MAC stays off.

## Consequences

A victim-IP-scoped field-only `eth.src` dump affiliates that MAC to the victim after a DC/peer first stamp. A MAC that only appears on DC/gateway frames stays off. A later DC-scoped harvest does not move a victim stamp. Same-line talking-IP donate and omitted-key persist stay.
