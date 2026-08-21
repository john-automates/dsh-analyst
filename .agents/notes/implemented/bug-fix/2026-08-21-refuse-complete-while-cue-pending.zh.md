# Agent Note: 在 cue-pending 或 Plan 未就绪时拒绝 complete

Status: implemented

[English](2026-08-21-refuse-complete-while-cue-pending.md) | 中文

## 问题

Headless 可以把仅有文本的模型停止（`finish` kind=`stop`）当成 `turn/end` 原因为 `completed` 并以 0 退出。在 `pcap_info` 之后，若底盘 Mission 仍为 cue-pending 且没有 Plan，那次关闭就是一次已完成的调查。cue-pending 仍会挡住 hunt 和绑定（[在没有 5W1H 结案时持久化遗留 C2 附加项](2026-08-21-persist-c2-extras-without-close.md)）。模型不调用那些工具时，那些检查不会运行。

## 决策

`dsh-investigation` 监听 `agent/turn-stopping`。当 Mission 仍为 cue-pending（`cueValidation` 待定／open 且未点名线索）或 `planReady` 为 false 时，它 `steer()` 一条插件通知，点名 cue-pending 和／或 Plan 未就绪。循环再执行一步。不会追加 `turn/end` `completed`。Headless 不会因那次仅有文本的停止以 0 退出。

已点名现场线索已持久化且 `planReady` 为 true 之后，此监听器不再因 cue-pending 或 Plan 未就绪做 steering（中途引导）。在那些理由上 complete 被允许。当前绑定之后，[仍未绑定的已收割 LAN 工作站](2026-08-21-refuse-complete-while-unbound-workstation.md) 是另一条 complete 拒绝。绑定、结案、身份遗留持久化，以及 extra-wan 去重仍由各自检查负责。

`planReady` 仍要求已点名现场线索、C2 假设、CDN／DC／更新替代，以及作证清单。此检查不编造线索或 Plan。hunt、绑定和附加项持久化不变。

## 备选方案

**只改 `METHODOLOGY_SECTION`。** 否决：`pcap_info` 之后的仅有文本停止仍会以 completed 关闭。

**在追加 `turn/end` 时抛错，或把原因改写成 `error`。** 否决：那会让本次运行失败，而不是继续。停止边界的扩展点是 `agent/turn-stopping` 加上 `steer()`。

**改 agent-loop，使 `finish` kind=`stop` 不再是 `completed`。** 否决：新行为属于调查插件。

**编造线索或 Plan，或盖上身份结案戳。** 否决：由模型点名线索并写 Plan。who/where 仍只属于受害端。

**直到绑定或 `case_report` 才允许 complete。** 否决：此检查只针对 Mission／Plan 的 complete。

**改调 unique-collapse extra-wan（`maxOutputChars`、裁切、`uniqueCollapsePcapFields`）。** 否决：那项遗留未经测试，且是分开的。

## 测试

`packages/analyst/investigation/tests/mindset.spec.ts` 钉住 `completeDenyReason`：底盘 cue-pending（点名 cue-pending 与 Plan 未就绪）、已点名线索但 Plan 未就绪、无效线索，以及已点名现场线索加上就绪 Plan 后允许。`packages/analyst/investigation/tests/investigation.spec.ts` 触发 `agent/turn-stopping`：底盘 cue-pending 会 steering `COMPLETE_CUE_PENDING_REASON`；已点名线索 `open` 且无 Plan 会 steering `COMPLETE_PLAN_NOT_READY_REASON`；`stampReadyMindset` 不做 steering。

## 后果

`pcap_info` 之后的仅有文本停止，在 Mission 仍为 cue-pending 或 Plan 未就绪时，不能把 headless 调查关闭为已完成。模型会看到原因。已点名现场线索且 Plan 就绪之后，此检查允许 complete；之后的绑定或结案失败不变。当前绑定之后仍未绑定的已收割 LAN 工作站由另一条检查负责。
