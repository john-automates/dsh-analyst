# Agent Note: 在没有 5W1H 结案时持久化遗留 C2 附加项

Status: implemented

[English](2026-08-21-persist-c2-extras-without-close.md) | 中文

## 问题

在一次现场遗留附加项绑定之后，extra-wan 与 c2-domain 会收割剩余 C2 IPv4 以及第一个非 CDN 带点名。这些字段已经作为 `c2_ips`／`c2_domain` 存在于 `projectCaseReport`。它们只有在散文 `case_report` 被接受时才落到 `investigation/report`。一次绑定了 C2、猎完附加项、然后让每次 `case_report` 都保持 UNBOUND 的运行，会写出零条 `investigation/report`。附加项消失。who/where 仍只属于受害端；为了保住附加项而编造结案包会编造 5W1H。

同一套底盘必须是受害端身份 + C2 调查。结案意味着 who/where 在受害端上得到证明、C2 不是 CDN／DC／更新、附加项仅在得到证明时才有。模型不能把该目的覆盖成溯源或家族狩猎。自动 hunt 等待就绪的 Plan，而不是 Mission。BindRelationship 是答案产物，不能替代点名 C2 假设。

## 决策

Mission、Plan、Action 和 Report 包裹 DINQ（Observation → Question → Hypothesis → Answer → Bind → Who/Where）。名称保持 Mission／Plan／Action／Report。不改名为 LDSM／ADSM。Thesis-revise 是情景对象（`name` + `claim` + `rule` + `result`），不是第四个 IR 阶段。由 harness 检查（而不是 `METHODOLOGY_SECTION` 文本）拥有这些阶段。

0. **Mission — 目的。** 插件在 `session/created` 盖上 Mission 戳（若日志里还没有，也会在任何 hunt 之前再盖一次），目的是受害端身份 + C2 调查。目的与已关闭手段保持底盘值。底盘的 `cueValidation` `open` 是待定（`cue-pending`），直到 `investigation_mission` 点名真实线索。那个待定线索不是已校验的观测。模型可以更新线索指针和槽位 0a。提交的目的会被忽略；`recordMission` 始终持久化 `CHASSIS_MISSION_PURPOSE`。提交字符串上的句号、空白或大小写不会拒绝线索更新。不同调查措辞也会被忽略，并被底盘目的覆盖。Mission 只给案件定范围。它不解锁自动 hunt。

1. **Plan — 先清单，再点名假设集。** Plan 现场追加、只追加：来源清单与缺口按唯一值拼接；每条假设是 `I believe X because Y` 加上一条证伪测试；候选标签是 `{victim, c2, dc, cdn, update, distractor}`。后一条目增加问题。它不替换更早的假设 id。在已点名现场线索（`valid` 或显式 `open`）之后，若模型省略清单或提交空清单，且案件捕获存在（`capture.pcap`，或 `evidence/` 或案件根目录下第一个 `*.pcap`／`*.pcapng`／`*.cap`），`investigation_plan` 会把该捕获持久化为清单。已提交的非空清单会保留。空清单不是完成的 Plan：没有案件捕获时，`planReady` 与绑定仍停在 `PLAN_INVENTORY_REASON`。`planReady` 是唯一的自动运行钥匙：已点名线索为 `valid` 或显式 `open`（不是 cue-pending）、至少一条 C2 假设、至少一条 CDN／DC／更新替代，以及清单。`bind_relationship` 使用同一套检查。拒绝原因是显式的（`CUE_PENDING_REASON`、`CUE_INVALID_REASON`、`PLAN_C2_HYPOTHESIS_REASON`、`PLAN_ALTERNATIVE_REASON`、`PLAN_INVENTORY_REASON`）。仅有 Mission 永远不够。

2. **Action — 针对性 hunt。** 每一次自动运行 hunt 都等待 `planReady`：eth-src、name-service、kerberos-cname、samr-userinfo、other-end、extra-wan 和 c2-domain。`huntsToAutoRun` 只接收那一个就绪标志。每次自动运行都追加带 `hypothesis_id` 的 `investigation/action`（身份 hunt 在有受害端假设时引用第一条受害端 H，否则引用第一条 C2 H）。extra-wan／c2-domain 仍是成功的非 CDN 绑定之后针对 WAN 目的地址的 Action。绑定仍先跑 `resolveBind`（两端都在 LAN、CDN／更新 C2、线索当 victim）。只有 `ok` 的绑定随后才要求就绪的 Plan。

3. **Report — 无结案持久化。** 在 who/where 得到证明之前，`case_report` 仍被拒绝（现有的未绑定／强制转换路径）。已证明的 extra-wan／c2-domain 遗留项写入 `investigation/extras`（`c2_ips` 省略 CDN／更新；`c2_domain` 是第一个非 CDN 带点名；`killed` 列出被杀死的假设 id），即使一份凌乱的 `case_report` 保持未绑定。该事件不是已接受的结案，也不编造 who/where/what/when/why/how。若已有 5W1H 包，钩子还会追加一份折叠后的 `investigation/report`，保留那些槽位并写入附加项。后来被接受的 `case_report` 会重新合并已折叠的附加项。who/where 仍只属于受害端。

测试只使用合成夹具（LAN `10.0.10.2`、C2 `198.51.100.80`、额外 WAN `203.0.113.50` + `payload.example.test`、CDN `203.0.113.80` + `update.microsoft.com`、DC `10.0.10.3`）。不列出线上案件的黄金 IP 与域名。

## 考虑过的替代方案

**在盖上 Mission 戳之后解锁任何自动 hunt。** 否决：Mission 框定目的。仅凭 Mission 就自动跑 eth-src／Kerberos，就是把线索 IP 当成 victim 的 PCAP 优先拐杖。Plan 就绪是唯一的自动运行钥匙。

**把底盘 cue-pending 的 `open` 当成已校验观测。** 否决：槽位 0a 保持待定，直到 `investigation_mission` 点名真实线索。那个待定指针不解锁 hunt 或绑定。

**把提交的目的字符串持久化到 Mission 事件上。** 否决：目的保持受害端身份 + C2 调查。溯源或家族狩猎是另一类案件。`recordMission` 用底盘目的覆盖。

**在提交目的不是精确底盘字符串匹配时拒绝 investigation_mission。** 否决：`recordMission` 已经盖上 `CHASSIS_MISSION_PURPOSE`。句号、多余空白或大小写差异会丢掉已点名线索，并让绑定停在 cue-pending。

**把空清单当成完成的 Plan。** 否决：空清单不能作证。已点名现场线索之后，若存在案件捕获，它就是默认的作证清单。没有捕获时，绑定仍停在 `PLAN_INVENTORY_REASON`。

**用 `capture.pcap` 覆盖已提交的清单。** 否决：非空清单会保留。

**把四个阶段改名为 LDSM／ADSM。** 否决：名称保持 Mission／Plan／Action／Report。Thesis-revise 仍是情景对象，不是第四个 IR 阶段。

**编造一份 5W1H 结案包好让附加项有家。** 否决：无结案持久化不是自动结案。who/where 仍只属于受害端。

**只在方法论提示词里讲授遗留持久化与 Plan 就绪。** 否决：未绑定的 `case_report` 仍会丢掉附加项，仅有 Mission 的绑定仍会猎附加项。

**把遗留附加项放到 who/where 上，或当作第二次绑定。** 否决：附加项是账本行，不是 Who。BindRelationship 不能替代点名 C2 假设。

**把线上案件的黄金 IP 或主机名写进 harness 代码或测试。** 否决：测试使用 TEST-NET、`payload.example.test` 和 `update.microsoft.com`。

**在 `resolveBind` 失败时跳过 Plan，好让两端都在 LAN／CDN 拒绝等待假设。** 否决：那些拒绝仍排在前面。Plan 就绪只在 `resolved.ok` 之后适用。

## 测试

`packages/analyst/investigation/tests/investigation.spec.ts` 在 `session/created` 盖上底盘 Mission，在仅有 Mission 时从 `pcap_filter` 收割 LAN `10.0.10.2` 且不自动运行 eth-src 或 kerberos，在 Plan 点名 C2 假设之前拒绝绑定（先是 `CUE_PENDING_REASON`，然后是 `PLAN_C2_HYPOTHESIS_REASON`），并在 `investigation_mission`（线索 `open`）加上 `investigation_plan`（C2 H + 替代 + 清单）之后自动运行那些 hunt，且每条 Action 行都带 `hypothesis_id`。同一文件在提交目的缺少句号或带有多余空白时接受 `investigation_mission`，持久化线索 `198.51.100.80`／`cue_validation` 与底盘目的，在点名线索加上就绪 Plan 之前对 cue-pending 保持拒绝（`CUE_PENDING_REASON`），拒绝缺少 CDN／DC 替代（`PLAN_ALTERNATIVE_REASON`）或清单（`PLAN_INVENTORY_REASON`）的已解析绑定，并在已点名现场线索之后把省略或空的 `investigation_plan` 清单默认成案件根目录 `capture.pcap`，使 `planReady` 为真且绑定不被 `PLAN_INVENTORY_REASON` 拒绝，而没有捕获的空清单仍是 `PLAN_INVENTORY_REASON`，已提交清单会保留，缺少 C2 H／CDN 替代仍拒绝 `PLAN_C2_HYPOTHESIS_REASON`／`PLAN_ALTERNATIVE_REASON`。它把 LAN `10.0.10.2` 绑定到 TEST-NET C2 `198.51.100.80`，自动运行 extra-wan／c2-domain，在没有 `investigation/report` 的情况下把 `investigation/extras` 持久化为 `198.51.100.80` + `203.0.113.50` 与 `payload.example.test`（省略 CDN 目的地址 `203.0.113.80`），在未绑定的 `case_report` 之后仍保留这些附加项，并在后来被接受的结案包上重新合并它们。两端都在 LAN 或 CDN／更新 C2 的拒绝仍先失败于 `resolveBind`，且不持久化附加项。`mindset.spec.ts` 钉住折叠、含 cue-pending 的 Plan 就绪、显式拒绝原因、主张形式和 thesis-revise。`hunts.spec.ts` 在 Plan 就绪之前让每一次 hunt 离开 `huntsToAutoRun`。无密钥 pcap-case 快照在创建时盖上 Mission，并在绑定之前持久化 Plan。

## 后果

任何 hunt 之前就已存在底盘目的。即使提交目的因标点不同或点名另一类调查，已点名线索仍会持久化；底盘目的始终被盖上。已点名现场线索之后，省略的 Plan 清单在存在案件捕获时默认成该捕获；空清单不是完成的 Plan。自动 hunt 等待就绪的 Plan，包括已点名线索。一次成功绑定会点名 C2 假设，并已检查 CDN／DC／更新替代。即使散文 `case_report` 保持未绑定，已证明 hunt 之后的遗留 C2 IP 与非 CDN 带点名仍会持久化。who/where 仍是受害端行。
