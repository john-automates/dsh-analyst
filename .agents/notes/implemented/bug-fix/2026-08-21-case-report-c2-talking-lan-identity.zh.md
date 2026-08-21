# Agent Note: 将 case_report 的 who/where 绑定到正在与 C2 通信的 LAN 身份

Status: implemented

[English](2026-08-21-case-report-c2-talking-lan-identity.md) | 中文

## 问题

现场 lumma-r1（`04f45ee`，mta-2026-01-31-lumma-in-the-room-ah，Bedrock 30B）得 3/5。hostname、user 和 full_name 通过。IP 和 MAC 失败：`case_report` 把线索里的 C2 IP 和对端 MAC 写成了受害者。调查账本里已经有正在与 C2 通信的 LAN IP 和来源客户端 `eth.src`。这与 First to Last r4 的受害者／C2 对调相同，只是发生在结案时而不是收割时。

[来源 MAC 收割](2026-08-21-harvest-eth-src-from-c2-talking-ip.md) 和[自动运行 hunt](2026-08-21-auto-run-outstanding-identity-hunts.md) 已经把 LAN 身份写入账本。`case_report` 仍持久化模型送来的原文。

## 决策

已知正在与 C2 通信的 LAN IP 时——`c2TalkingLanIps` 已有焦点 IP，或账本恰好有一个 LAN IP 和一个非 LAN 单播 IP——`case_report` 在 `recordReport` 之前改写 `who` 和 `where`。字段里尚未包含焦点 LAN IP 的非 LAN 单播 IP 会改成该 LAN IP。字段里尚未包含账本唯一 MAC 的其他 MAC 会改成该 `eth.src`。`what`、`when`、`why` 和 `how` 不变。不会插入主机名、用户或全名。

没有焦点 IP 时，结案包按提交原文保留。账本有两个 LAN IP 且没有 `c2TalkingLanIps` 时，不挑选受害者。账本有多条 MAC 时，不编造来源 MAC。

[去引号](2026-08-21-pcap-filter-quoted-display-filter.md)、[字符串字段强制转换](2026-08-20-pcap-filter-string-fields.md)、`eth-src` 使用 `ip.src`、[来源 MAC 收割](2026-08-21-harvest-eth-src-from-c2-talking-ip.md) 和[自动运行](2026-08-21-auto-run-outstanding-identity-hunts.md) 保持不变。scout、家族收割、遗留报告禁令和新评测不在本次变更内。

## 备选方案

**拒绝该工具调用。** 否决：lumma-r1 已经结案。重试仍是收割和通知没能挡住的同一种对调。

**只改方法论提示词或工具描述。** 否决：账本已经点名 LAN 客户端。

**把 who/where 里的空闲 LAN IP 改写成焦点 IP。** 否决：那是[双客户端融合](2026-08-20-scope-identity-hunts-to-c2-talking-client.md)。本旋钮是受害者／C2 对调。

**插入账本上的主机名、用户或全名。** 否决：不编造姓名。

**把 Easy as 123、First to Last 或 Lumma 的黄金 IP、MAC 或姓名写进提示词或测试。** 否决：测试使用合成 LAN 客户端和 TEST-NET 对等体。

**发明评测或改动 scout。** 否决：本旋钮是账本填好之后的结案包绑定。

## 测试

`packages/analyst/investigation/tests/report.spec.ts` 绑定合成账本（LAN 客户端 + 外部 C2 + 一条客户端 MAC）。把 C2 写成 who/where 的结案包会被改写到 LAN 客户端。仅有证据的 `c2TalkingLanIps` 会改写 IP，不编造 MAC。已经点名焦点 LAN IP 的字段保持不动。`packages/analyst/analyst-tools/tests/tools.spec.ts` 记录该账本并执行 `case_report`；持久化的结案包和工具结果给出 LAN IP 与来源 MAC。

## 后果

把 C2 写成受感染主机的 `case_report` 会持久化正在与 C2 通信的 LAN IP，并在唯一时持久化其来源 `eth.src`。已经点名该客户端的正确 who/where 保持原文。主机名、用户和全名仍只来自模型或收割，不来自这次改写。
