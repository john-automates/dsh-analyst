# Agent Note: Persist leftover C2 extras without a 5W1H close

Status: implemented

English | [中文](2026-08-21-persist-c2-extras-without-close.zh.md)

## Problem

After a live leftover-extras bind, extra-wan and c2-domain harvest remaining C2 IPv4s and the first non-CDN dotted name. Those fields already exist on `projectCaseReport` as `c2_ips` / `c2_domain`. They only land on `investigation/report` when prose `case_report` is accepted. A run that binds C2, hunts extras, then leaves every `case_report` UNBOUND writes zero `investigation/report` events. The extras vanish. Who/where stay victim-only; inventing a close packet to keep the extras would invent 5W1H.

The same chassis must be a victim-identity + C2 investigation. Closed means who/where proven on the victim, C2 is not CDN/DC/update, and extras only if proven. A model essay must not block Easy-as-123 identity hunts, and the model must not overwrite that purpose into origin or family hunting. BindRelationship is an answer artifact, not a substitute for naming the C2 hypothesis.

## Decision

Mission, Plan, Action, and Report wrap DINQ (Observation → Question → Hypothesis → Answer → Bind → Who/Where). The names stay Mission / Plan / Action / Report. They are not renamed to LDSM / ADSM. Thesis-revise is a scenario object (`name` + `claim` + `rule` + `result`), not a fourth IR phase. Harness checks, not `METHODOLOGY_SECTION` text, own the stages.

0. **Mission — purpose.** The plugin stamps Mission at `session/created` (and again before any hunt if the log has none) as a victim-identity + C2 investigation. Purpose and closed-means stay the chassis values. The model may update the cue pointer and slot 0a; a different purpose is denied (`MISSION_PURPOSE_REASON`). Identity hunts may run after that Mission exists.

1. **Plan — inventory then a named hypothesis set.** Plan persists live and append-only: source inventory and gaps concatenate uniquely; each hypothesis is `I believe X because Y` plus a disconfirm test; candidate labels are `{victim, c2, dc, cdn, update, distractor}`. A later entry adds questions. It does not replace an earlier hypothesis id. `bind_relationship` is denied until a C2 hypothesis is named and a CDN/DC/update alternative is on the Plan, and the Plan inventories what can attest. Deny reasons are explicit (`PLAN_C2_HYPOTHESIS_REASON`, `PLAN_ALTERNATIVE_REASON`, `PLAN_INVENTORY_REASON`). Cue `invalid` is `CUE_INVALID_REASON`. Mission alone is never enough for bind.

2. **Action — targeted hunts.** Identity hunts (eth-src / name-service / kerberos / samr) run after Mission exists. extra-wan / c2-domain stay the Action for WAN dests after a live non-CDN bind. Those Action rows carry `hypothesis_id`. Bind still runs `resolveBind` first (both-LAN, CDN/update C2, cue-as-victim). Only an `ok` bind then requires a ready Plan. `other-end` on cue-as-victim deny stays ungated.

3. **Report — persist-without-close.** `case_report` stays denied until who/where are proven (existing unbound/coerce path). Proven extra-wan / c2-domain leftovers write `investigation/extras` (`c2_ips` omits CDN/update; `c2_domain` is the first non-CDN dotted name; `killed` lists killed hypothesis ids) even when a messy `case_report` stays unbound. That event is not an accepted close and does not invent who/where/what/when/why/how. If a 5W1H packet already exists, the hook also appends a folded `investigation/report` that keeps those slots and sets the extras. A later accepted `case_report` re-merges folded extras. Who/where stay victim-only.

Tests use synthetic fixtures only (LAN `10.0.10.2`, C2 `198.51.100.80`, extra WAN `203.0.113.50` + `payload.example.test`, CDN `203.0.113.80` + `update.microsoft.com`, DC `10.0.10.3`). Live-case gold IPs and domains are not listed.

## Alternatives considered

**Unlock leftover auto-hunts after a Mission stamp.** Rejected: Mission scopes purpose so identity hunts can run. Leftover WAN hunts wait for a live bind whose Plan named a C2 hypothesis. Auto-hunt leftovers after Mission alone is the PCAP-first crutch that made cue-IP-as-victim.

**Wait for a model Mission essay before identity hunts.** Rejected: chassis stamps Mission at session start so Easy-as-123 auto-hunts are not blocked on that essay. Bind is the check that needs a named C2 hypothesis.

**Let the model overwrite Mission purpose.** Rejected: purpose is a victim-identity + C2 investigation. Origin or family hunting is a different case.

**Rename the four stages to LDSM / ADSM.** Rejected: Mission / Plan / Action / Report stay the names. Thesis-revise stays a scenario object, not a fourth IR phase.

**Invent a 5W1H close packet so extras have a home.** Rejected: persist-without-close is not an auto-close. Who/where stay victim-only.

**Teach leftover persist and Plan readiness only in the methodology prompt.** Rejected: an unbound `case_report` would still drop extras, and a Mission-only bind would still hunt leftovers.

**Put leftover extras on who/where or as a second bind.** Rejected: extras are ledger rows, not Who. BindRelationship is not a substitute for naming the C2 hypothesis.

**Bake live-case gold IPs or hostnames into harness code or tests.** Rejected: tests use TEST-NET, `payload.example.test`, and `update.microsoft.com`.

**Skip Plan on `resolveBind` failures so both-LAN / CDN denies wait for hypotheses.** Rejected: those denies stay first. Plan readiness applies only after `resolved.ok`.

## Testing

`packages/analyst/investigation/tests/investigation.spec.ts` stamps chassis Mission on `session/created`, issues identity hunts after that Mission without a Plan, and denies bind with `PLAN_C2_HYPOTHESIS_REASON` until a C2 hypothesis is named. The same file denies a different Mission purpose (`MISSION_PURPOSE_REASON`), denies a resolved bind that lacks a CDN/DC alternative (`PLAN_ALTERNATIVE_REASON`) or inventory (`PLAN_INVENTORY_REASON`), binds LAN `10.0.10.2` to TEST-NET C2 `198.51.100.80`, auto-runs extra-wan / c2-domain, persists `investigation/extras` with `198.51.100.80` + `203.0.113.50` and `payload.example.test` (CDN dest `203.0.113.80` omitted) without an `investigation/report`, keeps those extras after an unbound `case_report`, and re-merges them onto a later accepted packet. A both-LAN or CDN/update C2 deny still fails `resolveBind` first and persists no extras. `mindset.spec.ts` pins fold, Plan readiness, explicit deny reasons, claim form, and thesis-revise. `hunts.spec.ts` keeps extra-wan / c2-domain off `huntsToAutoRun` until Plan is ready. The keyless pcap-case snapshot stamps Mission at create and persists Plan before bind.

## Consequences

The chassis purpose exists before any hunt. Identity hunts run after that Mission. A successful bind names a C2 hypothesis and has checked a CDN/DC/update alternative. Leftover C2 IPs and a non-CDN dotted name persist after proven hunts even when prose `case_report` stays unbound. Who/where stay the victim row.
