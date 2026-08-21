# Agent Note: 在没有 5W1H 结案时持久化遗留 C2 附加项

Status: implemented

[English](2026-08-21-persist-c2-extras-without-close.md) | 中文

## 问题

在一次现场遗留附加项绑定之后，extra-wan 与 c2-domain 会收割剩余 C2 IPv4 以及第一个非 CDN 带点名。这些字段已经作为 `c2_ips`／`c2_domain` 存在于 `projectCaseReport`。它们只有在散文 `case_report` 被接受时才落到 `investigation/report`。一次绑定了黄金 C2、猎完附加项、然后让每次 `case_report` 都保持 UNBOUND 的运行，会写出零条 `investigation/report`。附加项消失。who/where 仍只属于受害端；为了保住附加项而编造结案包会编造 5W1H。

一个诱人的底盘捷径是在盖上 Mission 戳之后解锁遗留自动 hunt。那就是把线索 IP 当成 victim 的 PCAP 优先拐杖：Mission 给案件定范围并校验线索，但它不是 Observation → Question → Hypothesis。BindRelationship 是答案产物，不能替代点名 C2 假设。

## 决策

Mission、Plan、Action 和 Report 包裹 DINQ（Observation → Question → Hypothesis → Answer → Bind → Who/Where）。名称保持 Mission／Plan／Action／Report。不改名为 LDSM／ADSM。Thesis-revise 是情景对象（`name` + `claim` + `rule` + `result`），不是第四个 IR 阶段。Mission 与 Action 不跳过 Observation → Question → Hypothesis。

Mission 持久化目的、计分槽位（包括槽位 0a `cueValidation`：`valid`｜`open`｜`invalid`）、`closedMeans` 以及线索指针。底盘可以盖 Mission 戳来给案件定范围（identity+C2 已关闭手段的案件不上 origin 或 family hunt）。Mission 不解锁自动 hunt。

Plan 现场追加、只追加：来源清单与缺口按唯一值拼接；每条假设是 `I believe X because Y` 加上一条证伪测试；候选标签是 `{victim, c2, dc, cdn, update, distractor}`。后一条目增加问题。它不替换更早的假设 id。

Action 持久化一次 hunt 结果：`hypothesis_id` + 可选证据指针 + thesis 的 confirm｜kill｜gap。在点名 C2 假设之后，BindRelationship 仍是答案产物。

Report 仍是 5W1H 受害端实体投影。无结案持久化只走 Report 钩子：已证明的 extra-wan／c2-domain 遗留项写入 `investigation/extras`（`c2_ips` 省略 CDN／更新；`c2_domain` 是第一个非 CDN 带点名；`killed` 列出被杀死的假设 id）。该事件不是已接受的结案，也不编造 who/where/what/when/why/how。若已有 5W1H 包，钩子还会追加一份折叠后的 `investigation/report`，保留那些槽位并写入附加项。后来被接受的 `case_report` 会重新合并已折叠的附加项。未绑定的散文 `case_report` 不会擦掉附加项。who/where 仍只属于受害端。

由 harness 检查（而不是提示词文本）拥有遗留自动 hunt 与成功绑定：

1. extra-wan／c2-domain 自动运行仅在 Plan 具备 (a) 线索为 `valid` 或显式 `open`、(b) 至少一条 C2 假设与至少一条 CDN／DC／更新替代假设、以及 (c) 一份能作证的来源清单之后。那些 Action 行携带 `hypothesis_id`。
2. `bind_relationship` 仍先跑 `resolveBind`（两端都在 LAN、CDN／更新 C2、线索当 victim）。只有 `ok` 的绑定随后才要求就绪的 Plan。结案前先绑定保持不变。身份 hunt，以及拒绝把线索指定为 victim 时的 `other-end`，仍不受该检查约束。

测试只使用合成夹具（LAN `10.0.10.2`、C2 `198.51.100.80`、额外 WAN `203.0.113.50` + `payload.example.test`、CDN `203.0.113.80` + `update.microsoft.com`）。不列出线上案件的黄金 IP 与域名。

## 考虑过的替代方案

**在盖上 Mission 戳之后解锁遗留自动 hunt。** 否决：Mission 定范围并校验线索。仅凭 Mission 就自动 hunt，就是把线索 IP 当成 victim 的 PCAP 优先拐杖。

**把四个阶段改名为 LDSM／ADSM。** 否决：名称保持 Mission／Plan／Action／Report。Thesis-revise 仍是情景对象，不是第四个 IR 阶段。

**编造一份 5W1H 结案包好让附加项有家。** 否决：无结案持久化不是自动结案。who/where 仍只属于受害端。

**只在方法论提示词里讲授遗留持久化与 Plan 就绪。** 否决：未绑定的 `case_report` 仍会丢掉附加项，仅有 Mission 的绑定仍会 hunt。

**把遗留附加项放到 who/where 上，或当作第二次绑定。** 否决：附加项是账本行，不是 Who。BindRelationship 不能替代点名 C2 假设。

**把线上案件的黄金 IP 或主机名写进 harness 代码或测试。** 否决：测试使用 TEST-NET、`payload.example.test` 和 `update.microsoft.com`。

**在 `resolveBind` 失败时跳过 Plan，好让两端都在 LAN／CDN 拒绝等待假设。** 否决：那些拒绝仍排在前面。Plan 就绪只在 `resolved.ok` 之后适用。

## 测试

`packages/analyst/investigation/tests/investigation.spec.ts` 把 LAN `10.0.10.2` 绑定到 TEST-NET C2 `198.51.100.80`，自动运行 extra-wan／c2-domain，在没有 `investigation/report` 的情况下把 `investigation/extras` 持久化为 `198.51.100.80` + `203.0.113.50` 与 `payload.example.test`（省略 CDN 目的地址 `203.0.113.80`），在未绑定的 `case_report` 之后仍保留这些附加项，并在后来被接受的结案包上重新合并它们。仅有 Mission 不会记录绑定，也不会自动运行遗留 hunt。两端都在 LAN 或 CDN／更新 C2 的拒绝仍先失败于 `resolveBind`，且不持久化附加项。`mindset.spec.ts` 钉住折叠、Plan 就绪、主张形式和 thesis-revise。`hunts.spec.ts` 在 Plan 就绪之前让 extra-wan／c2-domain 离开 `huntsToAutoRun`。无密钥 pcap-case 快照在绑定之前盖上 Mission 与 Plan。

## 后果

即使散文 `case_report` 保持未绑定，已证明 hunt 之后的遗留 C2 IP 与非 CDN 带点名仍会持久化。Mission 不能解锁那些 hunt。一次成功绑定会点名 C2 假设，并已检查 CDN／DC／更新替代。who/where 仍是受害端行。
