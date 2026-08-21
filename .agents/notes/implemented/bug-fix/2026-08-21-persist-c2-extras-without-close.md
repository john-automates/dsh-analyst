# Agent Note: Persist leftover C2 extras without a 5W1H close

Status: implemented

English | [中文](2026-08-21-persist-c2-extras-without-close.zh.md)

## Problem

After a live leftover-extras bind, extra-wan and c2-domain harvest remaining C2 IPv4s and the first non-CDN dotted name. Those fields already exist on `projectCaseReport` as `c2_ips` / `c2_domain`. They only land on `investigation/report` when prose `case_report` is accepted. A run that binds C2, hunts extras, then leaves every `case_report` UNBOUND writes zero `investigation/report` events. The extras vanish. Who/where stay victim-only; inventing a close packet to keep the extras would invent 5W1H.

The same chassis must be a victim-identity + C2 investigation. Closed means who/where proven on the victim, C2 is not CDN/DC/update, and extras only if proven. The model must not overwrite that purpose into origin or family hunting. Auto-hunts wait for a ready Plan, not Mission. BindRelationship is an answer artifact, not a substitute for naming the C2 hypothesis.

## Decision

Mission, Plan, Action, and Report wrap DINQ (Observation → Question → Hypothesis → Answer → Bind → Who/Where). The names stay Mission / Plan / Action / Report. They are not renamed to LDSM / ADSM. Thesis-revise is a scenario object (`name` + `claim` + `rule` + `result`), not a fourth IR phase. Harness checks, not `METHODOLOGY_SECTION` text, own the stages.

0. **Mission — purpose.** The plugin stamps Mission at `session/created` (and again before any hunt if the log has none) as a victim-identity + C2 investigation. Purpose and closed-means stay the chassis values. Chassis `cueValidation` `open` is pending (`cue-pending`) until `investigation_mission` names a real cue. That pending cue is not a validated observation. The model may update the cue pointer and slot 0a. Submitted purpose is ignored; `recordMission` always persists `CHASSIS_MISSION_PURPOSE`. Trailing period, whitespace, or case on the submitted string does not deny the cue update. A different investigation wording is also ignored and overwritten with the chassis purpose. Mission scopes the case only. It does not unlock auto-hunts.

1. **Plan — inventory then a named hypothesis set.** Plan persists live and append-only: source inventory and gaps concatenate uniquely; each hypothesis is `I believe X because Y` plus a disconfirm test; candidate labels are `{victim, c2, dc, cdn, update, distractor}`. A later entry adds questions. It does not replace an earlier hypothesis id. After a named live cue (`valid` or explicitly `open`), `investigation_plan` persists the case capture as inventory when the model omits or submits an empty inventory and a capture exists (`capture.pcap`, or the first `*.pcap` / `*.pcapng` / `*.cap` under `evidence/` or the case root). A submitted non-empty inventory is kept. Empty inventory is not a finished Plan: with no case capture, `planReady` and bind stay on `PLAN_INVENTORY_REASON`. After a named live cue, when a C2 hypothesis and attest inventory are already present (this call or folded), `investigation_plan` also persists a default open CDN-or-update alternative (`I believe X because Y` plus disconfirm, label `cdn`) if the model omits every `dc` / `cdn` / `update` hypothesis. A submitted alternative is kept. The alternative check stays; the default is what lets it pass. `planReady` is the only auto-run key: named cue `valid` or explicitly `open` (not cue-pending), ≥1 C2 hypothesis, ≥1 CDN/DC/update alternative, and inventory. `bind_relationship` uses the same check. Deny reasons are explicit (`CUE_PENDING_REASON`, `CUE_INVALID_REASON`, `PLAN_C2_HYPOTHESIS_REASON`, `PLAN_ALTERNATIVE_REASON`, `PLAN_INVENTORY_REASON`). Mission alone is never enough.

2. **Action — targeted hunts.** Every auto-run hunt waits for `planReady`: eth-src, name-service, kerberos-cname, samr-userinfo, other-end, extra-wan, and c2-domain. `huntsToAutoRun` takes that one ready flag. Each auto-run appends `investigation/action` with `hypothesis_id` (identity hunts cite the first victim H when one exists, otherwise the first C2 H). extra-wan / c2-domain stay the Action for WAN dests after a live non-CDN bind. Bind still runs `resolveBind` first (both-LAN, CDN/update C2, cue-as-victim). Only an `ok` bind then requires a ready Plan.

3. **Report — persist-without-close.** `case_report` stays denied until who/where are proven (existing unbound/coerce path). Proven extra-wan / c2-domain leftovers write `investigation/extras` (`c2_ips` omits CDN/update; `c2_domain` is the first non-CDN dotted name; `killed` lists killed hypothesis ids) even when a messy `case_report` stays unbound. That event is not an accepted close and does not invent who/where/what/when/why/how. If a 5W1H packet already exists, the hook also appends a folded `investigation/report` that keeps those slots and sets the extras. A later accepted `case_report` re-merges folded extras. Who/where stay victim-only.

Tests use synthetic fixtures only (LAN `10.0.10.2`, C2 `198.51.100.80`, extra WAN `203.0.113.50` + `payload.example.test`, CDN `203.0.113.80` + `update.microsoft.com`, DC `10.0.10.3`). Live-case gold IPs and domains are not listed.

## Alternatives considered

**Unlock any auto-hunt after a Mission stamp.** Rejected: Mission scopes purpose. Auto-running eth-src / Kerberos after Mission alone is the PCAP-first crutch that made cue-IP-as-victim. Plan-ready is the only auto-run key.

**Treat chassis cue-pending `open` as a validated observation.** Rejected: slot 0a stays pending until `investigation_mission` names a real cue. That pending pointer does not unlock hunts or bind.

**Persist the submitted purpose string on the Mission event.** Rejected: purpose stays a victim-identity + C2 investigation. Origin or family hunting is a different case. `recordMission` overwrites with the chassis purpose.

**Deny investigation_mission when submitted purpose is not an exact chassis-string match.** Rejected: `recordMission` already stamps `CHASSIS_MISSION_PURPOSE`. A trailing period, extra whitespace, or case difference would drop a named cue and leave bind on cue-pending.

**Accept an empty inventory as a finished Plan.** Rejected: empty inventory cannot attest. After a named live cue the case capture is the default attest inventory when one exists. With no capture, bind stays on `PLAN_INVENTORY_REASON`.

**Overwrite a submitted inventory with `capture.pcap`.** Rejected: a non-empty inventory is kept.

**Treat an omitted CDN/DC/update alternative as a finished Plan, or drop the alternative check.** Rejected: bind still requires ≥1 alternative. After a named live cue the omitted alternative defaults to an open CDN-or-update hypothesis so that check can pass. With no named cue, bind stays on `CUE_PENDING_REASON`.

**Overwrite a submitted alternative with the open CDN-or-update default.** Rejected: a submitted alternative is kept.

**Rename the four stages to LDSM / ADSM.** Rejected: Mission / Plan / Action / Report stay the names. Thesis-revise stays a scenario object, not a fourth IR phase.

**Invent a 5W1H close packet so extras have a home.** Rejected: persist-without-close is not an auto-close. Who/where stay victim-only.

**Teach leftover persist and Plan readiness only in the methodology prompt.** Rejected: an unbound `case_report` would still drop extras, and a Mission-only bind would still hunt leftovers.

**Put leftover extras on who/where or as a second bind.** Rejected: extras are ledger rows, not Who. BindRelationship is not a substitute for naming the C2 hypothesis.

**Bake live-case gold IPs or hostnames into harness code or tests.** Rejected: tests use TEST-NET, `payload.example.test`, and `update.microsoft.com`.

**Skip Plan on `resolveBind` failures so both-LAN / CDN denies wait for hypotheses.** Rejected: those denies stay first. Plan readiness applies only after `resolved.ok`.

## Testing

`packages/analyst/investigation/tests/investigation.spec.ts` stamps chassis Mission on `session/created`, harvests LAN `10.0.10.2` from `pcap_filter` after Mission alone without auto-running eth-src or kerberos, denies bind until Plan names a C2 hypothesis (`CUE_PENDING_REASON` then `PLAN_C2_HYPOTHESIS_REASON`), and after `investigation_mission` (cue `open`) plus `investigation_plan` (C2 H + alternative + inventory) auto-runs those hunts with `hypothesis_id` on each Action row. The same file accepts `investigation_mission` when submitted purpose omits the trailing period or adds whitespace, persists cue `198.51.100.80` / `cue_validation` and chassis purpose, keeps bind denied on cue-pending (`CUE_PENDING_REASON`) until a named cue plus a ready Plan, denies a resolved bind that lacks a CDN/DC alternative (`PLAN_ALTERNATIVE_REASON`) or inventory (`PLAN_INVENTORY_REASON`), and after a named live cue defaults omitted or empty `investigation_plan` inventory to case-root `capture.pcap` so `planReady` is true and bind is not denied `PLAN_INVENTORY_REASON`, while empty inventory with no capture stays `PLAN_INVENTORY_REASON`, a submitted inventory is kept, and missing C2 H still denies `PLAN_C2_HYPOTHESIS_REASON`. After a named live cue the same file defaults an omitted CDN/DC/update alternative to the open `cdn` hypothesis so `planReady` is true and bind is not denied `PLAN_ALTERNATIVE_REASON`, while a submitted alternative is kept and cue-pending / missing C2 H still deny `CUE_PENDING_REASON` / `PLAN_C2_HYPOTHESIS_REASON`. A resolved bind that lacks an alternative on a direct `recordPlan` still denies `PLAN_ALTERNATIVE_REASON`. It binds LAN `10.0.10.2` to TEST-NET C2 `198.51.100.80`, auto-runs extra-wan / c2-domain, persists `investigation/extras` with `198.51.100.80` + `203.0.113.50` and `payload.example.test` (CDN dest `203.0.113.80` omitted) without an `investigation/report`, keeps those extras after an unbound `case_report`, and re-merges them onto a later accepted packet. A both-LAN or CDN/update C2 deny still fails `resolveBind` first and persists no extras. `mindset.spec.ts` pins fold, Plan readiness including cue-pending, explicit deny reasons, claim form, and thesis-revise. `hunts.spec.ts` keeps every hunt off `huntsToAutoRun` until Plan is ready. The keyless pcap-case snapshot stamps Mission at create and persists Plan before bind.

## Consequences

The chassis purpose exists before any hunt. A named cue persists even when submitted purpose differs by punctuation or names a different investigation; chassis purpose is always stamped. After a named live cue, omitted Plan inventory defaults to the case capture when one exists; empty inventory is not a finished Plan. After a named live cue, an omitted CDN/DC/update alternative defaults to an open CDN-or-update hypothesis; a submitted alternative is kept. Auto-hunts wait for a ready Plan, including a named cue. A successful bind names a C2 hypothesis and has checked a CDN/DC/update alternative. Leftover C2 IPs and a non-CDN dotted name persist after proven hunts even when prose `case_report` stays unbound. Who/where stay the victim row.
