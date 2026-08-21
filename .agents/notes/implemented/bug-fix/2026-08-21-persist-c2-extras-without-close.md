# Agent Note: Persist leftover C2 extras without a 5W1H close

Status: implemented

English | [中文](2026-08-21-persist-c2-extras-without-close.zh.md)

## Problem

After a live leftover-extras bind, extra-wan and c2-domain harvest remaining C2 IPv4s and the first non-CDN dotted name. Those fields already exist on `projectCaseReport` as `c2_ips` / `c2_domain`. They only land on `investigation/report` when prose `case_report` is accepted. A run that binds gold C2, hunts extras, then leaves every `case_report` UNBOUND writes zero `investigation/report` events. The extras vanish. Who/where stay victim-only; inventing a close packet to keep the extras would invent 5W1H.

A tempting chassis shortcut is to unlock leftover auto-hunts after a Mission stamp. That is the PCAP-first crutch that treated a cue IP as victim: Mission scopes the case and validates the cue, but it is not Observation → Question → Hypothesis. BindRelationship is an answer artifact, not a substitute for naming the C2 hypothesis.

## Decision

Mission, Plan, Action, and Report wrap DINQ (Observation → Question → Hypothesis → Answer → Bind → Who/Where). The names stay Mission / Plan / Action / Report. They are not renamed to LDSM / ADSM. Thesis-revise is a scenario object (`name` + `claim` + `rule` + `result`), not a fourth IR phase. Mission and Action do not skip Observation → Question → Hypothesis.

Mission persists purpose, scored slots (including slot 0a `cueValidation`: `valid` | `open` | `invalid`), `closedMeans`, and a cue pointer. Chassis may stamp Mission to scope the case (no origin or family hunt on an identity+C2 closed-means case). Mission does not unlock auto-hunts.

Plan persists live and append-only: source inventory and gaps concatenate uniquely; each hypothesis is `I believe X because Y` plus a disconfirm test; candidate labels are `{victim, c2, dc, cdn, update, distractor}`. A later entry adds questions. It does not replace an earlier hypothesis id.

Action persists one hunt outcome: `hypothesis_id` + optional evidence pointer + thesis confirm | kill | gap. BindRelationship remains the answer artifact after a C2 hypothesis is named.

Report remains the 5W1H victim-entity projection. Persist-without-close is the Report hook only: proven extra-wan / c2-domain leftovers write `investigation/extras` (`c2_ips` omits CDN/update; `c2_domain` is the first non-CDN dotted name; `killed` lists killed hypothesis ids). That event is not an accepted close and does not invent who/where/what/when/why/how. If a 5W1H packet already exists, the hook also appends a folded `investigation/report` that keeps those slots and sets the extras. A later accepted `case_report` re-merges folded extras. An unbound prose `case_report` does not wipe extras. Who/where stay victim-only.

Harness checks, not prompt text, own leftover auto-hunts and successful bind:

1. extra-wan / c2-domain auto-run only after Plan has (a) cue `valid` or explicitly `open`, (b) at least one C2 hypothesis and at least one CDN/DC/update alternative, and (c) an inventory of what can attest. Those Action rows carry `hypothesis_id`.
2. `bind_relationship` still runs `resolveBind` first (both-LAN, CDN/update C2, cue-as-victim). Only an `ok` bind then requires a ready Plan. Bind-before-who/where stays. Identity hunts and `other-end` on cue-as-victim deny stay ungated.

Tests use synthetic fixtures only (LAN `10.0.10.2`, C2 `198.51.100.80`, extra WAN `203.0.113.50` + `payload.example.test`, CDN `203.0.113.80` + `update.microsoft.com`). Live-case gold IPs and domains are not listed.

## Alternatives considered

**Unlock leftover auto-hunts after a Mission stamp.** Rejected: Mission scopes and validates the cue. Auto-hunt after Mission alone is the PCAP-first crutch that made cue-IP-as-victim.

**Rename the four stages to LDSM / ADSM.** Rejected: Mission / Plan / Action / Report stay the names. Thesis-revise stays a scenario object, not a fourth IR phase.

**Invent a 5W1H close packet so extras have a home.** Rejected: persist-without-close is not an auto-close. Who/where stay victim-only.

**Teach leftover persist and Plan readiness only in the methodology prompt.** Rejected: an unbound `case_report` would still drop extras, and a Mission-only bind would still hunt.

**Put leftover extras on who/where or as a second bind.** Rejected: extras are ledger rows, not Who. BindRelationship is not a substitute for naming the C2 hypothesis.

**Bake live-case gold IPs or hostnames into harness code or tests.** Rejected: tests use TEST-NET, `payload.example.test`, and `update.microsoft.com`.

**Skip Plan on `resolveBind` failures so both-LAN / CDN denies wait for hypotheses.** Rejected: those denies stay first. Plan readiness applies only after `resolved.ok`.

## Testing

`packages/analyst/investigation/tests/investigation.spec.ts` binds LAN `10.0.10.2` to TEST-NET C2 `198.51.100.80`, auto-runs extra-wan / c2-domain, persists `investigation/extras` with `198.51.100.80` + `203.0.113.50` and `payload.example.test` (CDN dest `203.0.113.80` omitted) without an `investigation/report`, keeps those extras after an unbound `case_report`, and re-merges them onto a later accepted packet. Mission alone does not record a bind or auto-run leftover hunts. A both-LAN or CDN/update C2 deny still fails `resolveBind` first and persists no extras. `mindset.spec.ts` pins fold, Plan readiness, claim form, and thesis-revise. `hunts.spec.ts` keeps extra-wan / c2-domain off `huntsToAutoRun` until Plan is ready. The keyless pcap-case snapshot stamps Mission and Plan before bind.

## Consequences

Leftover C2 IPs and a non-CDN dotted name persist after proven hunts even when prose `case_report` stays unbound. Mission cannot unlock those hunts. A successful bind names a C2 hypothesis and has checked a CDN/DC/update alternative. Who/where stay the victim row.
