# Agent Note: Refuse complete while cue-pending or Plan not ready

Status: implemented

English | [中文](2026-08-21-refuse-complete-while-cue-pending.zh.md)

## Problem

Headless can treat a text-only model stop (`finish` kind=`stop`) as `turn/end` reason `completed` and exit 0. After `pcap_info` with chassis Mission still cue-pending and no Plan, that close is a finished investigation. Cue-pending still blocks hunts and bind ([persist leftover C2 extras without a 5W1H close](2026-08-21-persist-c2-extras-without-close.md)). Those checks do not run when the model never calls those tools.

## Decision

`dsh-investigation` listens on `agent/turn-stopping`. When Mission is still cue-pending (`cueValidation` pending / open without a named cue) or `planReady` is false, it `steer()`s a plugin notice that names cue-pending and/or Plan not ready. The loop runs another step. `turn/end` `completed` is not appended. Headless does not exit 0 from that text-only stop.

After a named live cue is persisted and `planReady` is true, the listener does not steer. Complete is allowed again. Bind, report, identity leftover, and extra-wan unique-collapse stay on their own checks.

`planReady` still requires a named live cue, a C2 hypothesis, a CDN/DC/update alternative, and attest inventory. This check does not invent a cue or Plan. Hunt, bind, and extras persist are unchanged.

## Alternatives considered

**Teach only `METHODOLOGY_SECTION`.** Rejected: a text-only stop after `pcap_info` still closes as completed.

**Throw on `turn/end` append or rewrite the reason to `error`.** Rejected: that fails the run instead of continuing. `agent/turn-stopping` plus `steer()` is the stop-boundary extension point.

**Change agent-loop so `finish` kind=`stop` is not `completed`.** Rejected: new behavior belongs on the investigation plugin.

**Invent a cue or Plan, or stamp identity close.** Rejected: the model names the cue and writes Plan. Who/where stay victim-only.

**Also refuse complete until bind or `case_report`.** Rejected: this check is Mission/Plan complete only.

**Retune unique-collapse extra-wan (`maxOutputChars`, clip, `uniqueCollapsePcapFields`).** Rejected: that leftover is untested and separate.

## Testing

`packages/analyst/investigation/tests/mindset.spec.ts` pins `completeDenyReason` for chassis cue-pending (names cue-pending and Plan not ready), named cue with Plan not ready, invalid cue, and allow after named live cue plus ready Plan. `packages/analyst/investigation/tests/investigation.spec.ts` fires `agent/turn-stopping`: chassis cue-pending steers `COMPLETE_CUE_PENDING_REASON`; named cue `open` without Plan steers `COMPLETE_PLAN_NOT_READY_REASON`; `stampReadyMindset` does not steer.

## Consequences

A text-only stop after `pcap_info` cannot close a headless investigation as completed while Mission is cue-pending or Plan is not ready. The model sees why. After a named live cue and ready Plan, complete is allowed; later bind or report failure is unchanged.
