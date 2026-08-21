# Agent Note: 在已收割 LAN 工作站仍未绑定时拒绝 complete

Status: implemented

[English](2026-08-21-refuse-complete-while-unbound-workstation.md) | 中文

## 问题

Headless 可以把仅有文本的模型停止（`finish` kind=`stop`）当成 `turn/end` 原因为 `completed` 并以 0 退出。当前绑定了一个 LAN victim 之后，另一台已收割的 LAN 工作站（IP 加上主机名和／或人类用户和／或非基础设施 MAC）可以仍未绑定。模型把该主机当成连通性检查噪声打发掉。它从未被 `bind_relationship`，也从未作为 who/where 提交。

[在 cue-pending 或 Plan 未就绪时拒绝 complete](2026-08-21-refuse-complete-while-cue-pending.md) 已在 Mission 仍为 cue-pending 或 `planReady` 为 false 时于 `agent/turn-stopping` 上做 steering（中途引导）。已点名线索且 Plan 就绪之后，该检查允许 complete。[持久化每一个已绑定受害端行](2026-08-21-persist-every-bound-victim-row.md) 只在第二次当前绑定之后才写入第二个 victim，因此剩余主机从未被绑定时它保持空闲。

## 决策

`completeDenyReason` 仍先点名 cue-pending 或 Plan 未就绪。在 `planReady` 且至少有一次当前绑定之后，若另一台已收割的 LAN 工作站仍未绑定，它也拒绝仅有文本的停止。拒绝文本点名该剩余项。`agent/turn-stopping` 把该文本做 steering（中途引导）。不会追加 `turn/end` `completed`。Headless 不会因那次仅有文本的停止以 0 退出。

已收割的 LAN 工作站是账本上已有工作站身份的非基础设施 LAN IPv4：非 AD SRV 主机名、人类 user／`full_name`，和／或通信 IP 帧或戳记并非只从已知基础设施来源的 MAC。所有已记录绑定上的 victim IPv4 都被排除。绑定角色 `infra`，以及该 IP 上的 AD SRV／DC 定位器主机名，属于基础设施／域控／网关／文件服务器剩余项，不是工作站。每一个这样的剩余项都已绑定为 victim，或不存在这样的剩余项时，此检查再次允许 complete。

此检查不编造绑定，不编造 5W1H，也不把未绑定主机持久化到 who/where／`victims`。Who/Where 之前先绑定保持不变。[cue-pending／Plan 未就绪](2026-08-21-refuse-complete-while-cue-pending.md) 仍优先。多 victim 持久化、LAN／DC 剩余项强制转换、AD SRV 主机名省略、`acceptedC2Ips`／`c2_domain`／extra-wan／CDN 前缀，以及家族持久化保持不变。

测试使用合成 RFC1918／TEST-NET 替身。

## 备选方案

**只改 methodology 或账本文案。** 否决：一次绑定之后的仅有文本停止仍会以 completed 关闭。

**自动绑定剩余项或编造 who/where。** 否决：Who/Where 之前先绑定保持不变。由模型绑定剩余项；只有该绑定之后，持久化才写入受害端行。

**把每一个未绑定 LAN IPv4 都当成剩余工作站。** 否决：仅有 IP 的收割，以及域控／网关／文件服务器剩余项（绑定角色 `infra` 或 AD SRV 定位器）不得挡住单 victim 结案。

**重调持久化每一个已绑定受害端行、LAN／DC 强制转换或 AD SRV 主机名省略。** 否决：那些旋钮此处未经测试，且在第二个 victim 被绑定之前保持空闲。

**直到 `case_report` 才允许 complete。** 否决：此检查只针对剩余绑定的 complete。

**改 agent-loop，使 `finish` kind=`stop` 不再是 `completed`。** 否决：新行为属于调查插件已有的 `agent/turn-stopping` 监听器。

**把线上案件的黄金 IP、MAC、主机名、用户或真实 AD 域写进 fixture 或注记。** 否决：测试使用已绑定 victim `10.0.10.2`、剩余工作站 `10.0.10.8`（主机名 `lan-host-b`）、域控／基础设施 `10.0.10.3`，以及 TEST-NET C2 `198.51.100.80`。

## 测试

`packages/analyst/investigation/tests/mindset.spec.ts` 钉住 `completeDenyReason`：一次绑定之后剩余的 `10.0.10.8`（`lan-host-b`）会点名该未绑定工作站；cue-pending 与 Plan 未就绪在那些项仍开放时仍然优先；绑定该剩余项，或只留下域控／基础设施 `10.0.10.3`，则允许 complete。`packages/analyst/investigation/tests/bind.spec.ts` 钉住 `unboundHarvestedLanWorkstations`：主机名、人类 user 和非基础设施 MAC 剩余项，AD SRV／绑定角色 infra／网关／文件服务器的空剩余项，以及 `requireCaseReport` 的 who/where 仍落在已绑定 victim `10.0.10.2` 上、不发布 `10.0.10.8`。`packages/analyst/investigation/tests/investigation.spec.ts` 触发 `agent/turn-stopping`：一次绑定加上剩余 `lan-host-b` 会 steering 点名拒绝且不写结案；绑定该剩余项，或一次绑定且只剩域控／基础设施剩余项，则不做 steering。

## 后果

一次当前绑定之后的仅有文本停止，在另一台已收割的 LAN 工作站仍未绑定时，不能把 headless 调查关闭为已完成。模型会看到该剩余项。绑定该剩余项，或只剩域控／网关／文件服务器剩余项时，complete 再次被允许。who/where／`victims` 仍只属于已绑定的受害端行。
