# Agent Note: 在没有 5W1H 结案时持久化遗留 C2 附加项

Status: implemented

[English](2026-08-21-persist-c2-extras-without-close.md) | 中文

## 问题

在一次现场遗留附加项绑定之后，extra-wan 与 c2-domain 会收割剩余 C2 IPv4 以及第一个非 CDN 带点名。这些字段已经作为 `c2_ips`／`c2_domain` 存在于 `projectCaseReport`。它们只有在散文 `case_report` 被接受时才落到 `investigation/report`。一次绑定了 C2、猎完附加项、然后让每次 `case_report` 都保持 UNBOUND 的运行，会写出零条 `investigation/report`。附加项消失。who/where 仍只属于受害端；为了保住附加项而编造结案包会编造 5W1H。

同一套底盘必须是受害端身份 + C2 调查。结案意味着 who/where 在受害端上得到证明、C2 不是 CDN／DC／更新、附加项仅在得到证明时才有。模型作文不能挡住 Easy-as-123 身份 hunt，模型也不能把该目的覆盖成溯源或家族狩猎。BindRelationship 是答案产物，不能替代点名 C2 假设。

## 决策

Mission、Plan、Action 和 Report 包裹 DINQ（Observation → Question → Hypothesis → Answer → Bind → Who/Where）。名称保持 Mission／Plan／Action／Report。不改名为 LDSM／ADSM。Thesis-revise 是情景对象（`name` + `claim` + `rule` + `result`），不是第四个 IR 阶段。由 harness 检查（而不是 `METHODOLOGY_SECTION` 文本）拥有这些阶段。

0. **Mission — 目的。** 插件在 `session/created` 盖上 Mission 戳（若日志里还没有，也会在任何 hunt 之前再盖一次），目的是受害端身份 + C2 调查。目的与已关闭手段保持底盘值。模型可以更新线索指针和槽位 0a；不同目的会被拒绝（`MISSION_PURPOSE_REASON`）。身份 hunt 可以在该 Mission 存在之后运行。

1. **Plan — 先清单，再点名假设集。** Plan 现场追加、只追加：来源清单与缺口按唯一值拼接；每条假设是 `I believe X because Y` 加上一条证伪测试；候选标签是 `{victim, c2, dc, cdn, update, distractor}`。后一条目增加问题。它不替换更早的假设 id。在点名 C2 假设、Plan 上有 CDN／DC／更新替代、并且清单写明能作证的来源之前，`bind_relationship` 会被拒绝。拒绝原因是显式的（`PLAN_C2_HYPOTHESIS_REASON`、`PLAN_ALTERNATIVE_REASON`、`PLAN_INVENTORY_REASON`）。线索为 `invalid` 时是 `CUE_INVALID_REASON`。仅有 Mission 永远不够绑定。

2. **Action — 针对性 hunt。** 身份 hunt（eth-src／name-service／kerberos／samr）在 Mission 存在之后运行。extra-wan／c2-domain 仍是成功的非 CDN 绑定之后针对 WAN 目的地址的 Action。那些 Action 行携带 `hypothesis_id`。绑定仍先跑 `resolveBind`（两端都在 LAN、CDN／更新 C2、线索当 victim）。只有 `ok` 的绑定随后才要求就绪的 Plan。拒绝把线索指定为 victim 时的 `other-end` 仍不受该检查约束。

3. **Report — 无结案持久化。** 在 who/where 得到证明之前，`case_report` 仍被拒绝（现有的未绑定／强制转换路径）。已证明的 extra-wan／c2-domain 遗留项写入 `investigation/extras`（`c2_ips` 省略 CDN／更新；`c2_domain` 是第一个非 CDN 带点名；`killed` 列出被杀死的假设 id），即使一份凌乱的 `case_report` 保持未绑定。该事件不是已接受的结案，也不编造 who/where/what/when/why/how。若已有 5W1H 包，钩子还会追加一份折叠后的 `investigation/report`，保留那些槽位并写入附加项。后来被接受的 `case_report` 会重新合并已折叠的附加项。who/where 仍只属于受害端。

测试只使用合成夹具（LAN `10.0.10.2`、C2 `198.51.100.80`、额外 WAN `203.0.113.50` + `payload.example.test`、CDN `203.0.113.80` + `update.microsoft.com`、DC `10.0.10.3`）。不列出线上案件的黄金 IP 与域名。

## 考虑过的替代方案

**在盖上 Mission 戳之后解锁遗留自动 hunt。** 否决：Mission 框定目的，好让身份 hunt 能跑。遗留 WAN hunt 等待一次 Plan 已点名 C2 假设的现场绑定。仅凭 Mission 就自动猎附加项，就是把线索 IP 当成 victim 的 PCAP 优先拐杖。

**等模型写完 Mission 作文再跑身份 hunt。** 否决：底盘在会话开始时盖上 Mission 戳，这样 Easy-as-123 自动 hunt 不会被那篇作文挡住。绑定才是需要点名 C2 假设的检查。

**让模型覆盖 Mission 目的。** 否决：目的是受害端身份 + C2 调查。溯源或家族狩猎是另一类案件。

**把四个阶段改名为 LDSM／ADSM。** 否决：名称保持 Mission／Plan／Action／Report。Thesis-revise 仍是情景对象，不是第四个 IR 阶段。

**编造一份 5W1H 结案包好让附加项有家。** 否决：无结案持久化不是自动结案。who/where 仍只属于受害端。

**只在方法论提示词里讲授遗留持久化与 Plan 就绪。** 否决：未绑定的 `case_report` 仍会丢掉附加项，仅有 Mission 的绑定仍会猎附加项。

**把遗留附加项放到 who/where 上，或当作第二次绑定。** 否决：附加项是账本行，不是 Who。BindRelationship 不能替代点名 C2 假设。

**把线上案件的黄金 IP 或主机名写进 harness 代码或测试。** 否决：测试使用 TEST-NET、`payload.example.test` 和 `update.microsoft.com`。

**在 `resolveBind` 失败时跳过 Plan，好让两端都在 LAN／CDN 拒绝等待假设。** 否决：那些拒绝仍排在前面。Plan 就绪只在 `resolved.ok` 之后适用。

## 测试

`packages/analyst/investigation/tests/investigation.spec.ts` 在 `session/created` 盖上底盘 Mission，在没有 Plan 的情况下于该 Mission 之后下发身份 hunt，并在点名 C2 假设之前以 `PLAN_C2_HYPOTHESIS_REASON` 拒绝绑定。同一文件拒绝不同的 Mission 目的（`MISSION_PURPOSE_REASON`），拒绝缺少 CDN／DC 替代（`PLAN_ALTERNATIVE_REASON`）或清单（`PLAN_INVENTORY_REASON`）的已解析绑定，把 LAN `10.0.10.2` 绑定到 TEST-NET C2 `198.51.100.80`，自动运行 extra-wan／c2-domain，在没有 `investigation/report` 的情况下把 `investigation/extras` 持久化为 `198.51.100.80` + `203.0.113.50` 与 `payload.example.test`（省略 CDN 目的地址 `203.0.113.80`），在未绑定的 `case_report` 之后仍保留这些附加项，并在后来被接受的结案包上重新合并它们。两端都在 LAN 或 CDN／更新 C2 的拒绝仍先失败于 `resolveBind`，且不持久化附加项。`mindset.spec.ts` 钉住折叠、Plan 就绪、显式拒绝原因、主张形式和 thesis-revise。`hunts.spec.ts` 在 Plan 就绪之前让 extra-wan／c2-domain 离开 `huntsToAutoRun`。无密钥 pcap-case 快照在创建时盖上 Mission，并在绑定之前持久化 Plan。

## 后果

任何 hunt 之前就已存在底盘目的。身份 hunt 在该 Mission 之后运行。一次成功绑定会点名 C2 假设，并已检查 CDN／DC／更新替代。即使散文 `case_report` 保持未绑定，已证明 hunt 之后的遗留 C2 IP 与非 CDN 带点名仍会持久化。who/where 仍是受害端行。
