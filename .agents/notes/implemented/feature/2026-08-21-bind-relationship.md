# Agent Note: BindRelationship before Who/Where

Status: implemented

English | [中文](2026-08-21-bind-relationship.zh.md)

## Problem

Attacks are relationships. The detector’s IP is a hypothesis about the other end until someone assigns victim versus c2 on a cited conversation. The investigation ledger already held that conversation and the C2-talking LAN identity. The model never saw those roles.

`formatLedger` was a flat unlabeled list. Hunt notices still told the model to run `pcap_filter` after outstanding hunts had already executed. `METHODOLOGY_SECTION` stated DINQ and 5W1H with no victim-versus-c2 rule. `case_report` accepted six free-text strings and had no `tools/pre-execute` check. The keyless pcap-case snapshot closed in one hop from `pcap_filter` to `case_report`.

A silent rewrite of `who`/`where` onto the C2-talking LAN IP hid inversion instead of forcing the bind. That rewrite is archived as [bind case_report who/where to the C2-talking LAN identity](../../archived/bug-fix/2026-08-21-case-report-c2-talking-lan-identity.md).

## Decision

`bind_relationship` is the thinking primitive. It records `investigation/bind` with `{src, dst, dport, t, evidence_id}` and endpoints `{addr, role ∈ victim|c2|infra|distractor|unknown, because}`. Exactly one victim. The cited conversation must include a cue or observation address ([refuse both-LAN bind](../bug-fix/2026-08-21-refuse-both-lan-bind.md)). A cue or observation address (non-LAN unicast) defaults to `c2` and cannot be victim ([refuse cue-as-victim](../bug-fix/2026-08-21-refuse-cue-as-victim.md)); that deny names the [other-end hunt](../bug-fix/2026-08-21-other-end-hunt-on-cue-victim.md) for LAN `ip.src` talking to the cue. Role `c2` cannot be a LAN address. Tokens are not swapped. A both-LAN deny does not issue a hunt. Every other unassigned address defaults to `unknown`.

The live bind publishes a focus/roles card through `investigation:ledger`. That card is not another inbox splice. Hunt notices name the filter that already ran.

`tools/pre-execute` denies `case_report` and any tool arguments that set `who` or `where` unless a live bind exists with exactly one victim. It also denies when an identity slot’s `evidence_id` points at a non-victim, or when `who`/`where`.`entity_id` names a non-victim endpoint or another IPv4. A user, hostname, MAC, or full_name is a victim-row handle, not an entity id; the persisted packet uses the bound victim address ([victim-row entity_id](../bug-fix/2026-08-21-case-report-victim-row-entity-id.md)). The deny text is `unbound: assign victim vs c2 on the cited conversation.` Inverted victim/c2 is refused. Tokens are not swapped.

`case_report` `who`/`where` are projections of the victim entity row (IP, MAC, hostname, user, full_name). They are not free-text fill. An IP donates as itself. An explicit `entity_id` wins. A unique sourced `eth.src` MAC affiliates to the bound victim through `c2TalkingLanVictim`; that helper does not rewrite `who`/`where`. After a live bind, a MAC or hostname evidenced on the bound victim IP donates even when other values of that kind exist on the ledger ([victim-IP-scoped donate](../bug-fix/2026-08-21-donate-victim-ip-scoped-mac-hostname.md)). A MAC first stamped under a DC or peer hunt still donates when later frames source it from the victim IP ([talking-IP MAC stamp](../bug-fix/2026-08-21-stamp-mac-evidence-from-talking-ip.md)). A user or full_name first seen under a DC or peer hunt still donates when that conversation's client is the bound victim ([conversation-client stamp](../bug-fix/2026-08-21-stamp-user-fullname-from-conversation-client.md)). An unaffiliated ledger identity donates when it is the only identity of that kind not affiliated with a different entity ([complete victim-row projection](../bug-fix/2026-08-21-complete-victim-row-projection.md)). Identities whose `entity_id` is already the victim still donate. Two unaffiliated identities of the same kind donate neither. Distractors stay on the ledger and cannot donate identity slots. Names are not invented.

[Quote-strip](../bug-fix/2026-08-21-pcap-filter-quoted-display-filter.md), [string-field coerce](../bug-fix/2026-08-20-pcap-filter-string-fields.md), [stringified bind endpoints and dport](../bug-fix/2026-08-21-bind-relationship-stringified-args.md), `ip.src` for `eth-src`, [sourced MAC harvest](../bug-fix/2026-08-21-harvest-eth-src-from-c2-talking-ip.md), and [auto-run](../bug-fix/2026-08-21-auto-run-outstanding-identity-hunts.md) stay helpers. BindRelationship is the close check. Scout, leftover-report bans, and new evals stay out of this change.

## Alternatives considered

**Silent rewrite of who/where onto the C2-talking LAN IP.** Rejected: that hid inversion. The model must bind the conversation. The earlier rewrite is archived.

**Merge ledger fields into who/where as the product.** Rejected: BindRelationship is a thinking primitive, not another silent projection.

**Change only the methodology prompt or the tool description.** Rejected: the model can still close unbound.

**Token-swap an inverted victim/c2 pair.** Rejected: that is the silent rewrite under another name. Refuse the close.

**Rewrite an idle LAN IP in who/where onto the focus IP.** Rejected: that is [two-client fusion](../bug-fix/2026-08-20-scope-identity-hunts-to-c2-talking-client.md).

**Invent a hostname, user, or full_name that is not on the ledger.** Rejected: names are not invented. A unique unaffiliated ledger identity donates after a live bind ([complete victim-row projection](../bug-fix/2026-08-21-complete-victim-row-projection.md)).

**Bake gold IPs, MACs, or names from Easy as 123, First to Last, or Lumma into prompts or tests.** Rejected: tests use a synthetic LAN client and a TEST-NET peer.

**Invent evals or touch scout.** Rejected: this knob is the bind before close.

**Allow two victims or zero victims.** Rejected: the bind requires exactly one victim.

**Let a distractor donate a MAC, hostname, or user.** Rejected: distractors stay labeled and cannot fill who/where.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET peer (`198.51.100.80`), and idle distractor / LAN DC (`10.0.10.3`). It checks cue-default `c2`, cue-as-victim denied, a both-LAN conversation denied without an `other-end` hunt, LAN `c2` denied, two/zero victims denied, a JSON-string `endpoints` list plus numeric-string `dport` resolving to the same bind as a native array plus integer `dport`, projection from the victim row, distractor non-donation, unique sourced-MAC affiliation, unique unaffiliated mac/hostname/user/full_name donation, victim-IP-scoped mac/hostname donation when another row exists, two unaffiliated users or macs donating neither, unbound/inverted/free-text deny, and a victim-row user handle (`who.entity_id` = username) that closes with the victim address. `packages/analyst/investigation/tests/investigation.spec.ts` records `bind_relationship`, denies `case_report` until a live victim exists, and renders the roles card on the ledger. `packages/analyst/analyst-tools/tests/tools.spec.ts` requires the bind before close and projects who/where from the victim, including a username handle on that row and an unaffiliated harvested row. The keyless `examples/analyst` pcap-case snapshot is `pcap_filter` then `bind_relationship` then `case_report`.

## Consequences

Close requires `bind_relationship` first. An inverted or unbound `case_report` fails with the unbound reason. The model sees victim versus c2 on the ledger card. Auto-run, quote-strip, and field coerce remain helpers and do not assign roles. Hostname, user, and full_name come from harvest donation — an explicit victim `entity_id`, a victim-IP-scoped mac/hostname, a conversation-client user or full_name, or a unique unaffiliated ledger identity — not from a rewrite.
