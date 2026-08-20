# analyst/ — 调查分析能力系列

[English](README.md) | 中文

案件范围内的调查状态以及写入该状态的 SOC/NSM 工具。这是产品能力系列，不是编码 Agent 换皮：标准、极简、Code 与创造模式仍然随部署提供。

| 包 | 职责 | ctx 键 |
|---|---|---|
| [`investigation/`](investigation/README.md) | 案件目录、证据策略、身份收割、自动下发的 hunt、5W1H 结案包 | `ctx.investigation` |
| [`analyst-tools/`](analyst-tools/README.md) | `pcap_info`、`pcap_filter`、`logs` 和 `case_report` |（注册到 `ctx.tools`） |

选择 `analyst` 预设。设计见[调查分析预设](../../.agents/notes/implemented/feature/2026-08-20-analyst-investigation-preset.md)。
