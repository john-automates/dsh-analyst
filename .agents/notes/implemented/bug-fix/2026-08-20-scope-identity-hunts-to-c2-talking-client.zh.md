# Agent Note: 将身份 hunt 限定到正在与 C2 通信的 LAN 客户端

Status: implemented

[English](2026-08-20-scope-identity-hunts-to-c2-talking-client.md) | 中文

## 问题

现场 First to Last r1（`20b7854`，Bedrock 30B，mta-2026-08-09）得 2/5。会话 cwd 是案件目录。hunt 已大量下发并执行。正在与 C2 通信的 LAN IP 及其主机名通过。MAC、用户和全名失败，因为收割和 `case_report` 的 `who` 挂到了另一台 LAN 工作站。Easy as 123 掩盖了这一点：它只有一个客户端。

`huntsForNewIdentities` 对每个新 IP 下发 `eth-src`、`name-service`、`kerberos-cname` 与 `samr-userinfo`，并对每个新主机名和用户下发 Kerberos/SAMR。通知使用未限定范围的 `eth.src`、`kerberos.CNameString` 和 SAMR 过滤器。

## 决策

当一个 LAN IP 与非 LAN 单播对等体出现在同一行工具输出中时，随后的 `eth-src`、`name-service`、`kerberos-cname` 与 `samr-userinfo` hunt 只对该 C2 通信 IP 下发。其他 LAN 工作站、外部对等体、主机名和用户不会收到这些身份 hunt。去重仍按 kind+subject。

`c2TalkingLanIps` 按行读取一次会话。RFC1918 是 LAN。回环、链路本地、组播、保留和广播都不是 C2 对等体。空闲的 LAN 到 LAN 行不会聚焦客户端。检测使用当前工具结果，加上会话日志中已折叠的 `tool/result` 文本。

以 IP 为主体的 `huntNotice` 在 `display_filter` 中包含 `ip.addr ==` 该主体，但 `eth-src` 使用 `ip.src ==`，这样双向转储就不能持久化对端网卡（[来源 MAC](2026-08-21-harvest-eth-src-from-c2-talking-ip.md)）。主机名和用户通知保持不限定范围；一旦已知 C2 通信 IP，它们就不会下发。

[调查分析预设](../feature/2026-08-20-analyst-investigation-preset.md) 仍拥有收割、SAMR 和其他 hunt 旋钮。`DSH_CASE_DIR`、字符串字段强制转换、XML 恢复、主机名收割以及无效 tshark 字段拒绝保持不变。

scout、家族收割以及新评测不在本次变更内。已下发 hunt 的执行见[自动运行已下发的身份 hunt](2026-08-21-auto-run-outstanding-identity-hunts.md)。

## 备选方案

**只改方法论提示词。** 否决：r1 已经下发并执行了身份 hunt。失误是对每台 LAN 工作站都下发，而不是缺少一句提示词。

**自动运行已限定范围的 pcap_filter hunt。** 对本下发旋钮否决：执行见[自动运行已下发的身份 hunt](2026-08-21-auto-run-outstanding-identity-hunts.md)。

**把案件黄金身份写进提示词或测试。** 否决：测试使用合成的双客户端 fixture（一个 LAN IP 与外部 TEST-NET 对等体通信；另一个留在 LAN 内）。案件名称、IP、MAC 和用户不是期望答案。

**为 C2 通信 IP 新增 `SessionEventMap` 成员。** 否决：会话已在 `tool/result` 文本中。折叠该文本可避免新事件和 SDK 快照动荡。

**从日志中删除已下发的空闲工作站 hunt。** 否决：日志只追加。一旦已知 C2 通信 IP，抑制适用于随后的下发。

## 测试

`packages/analyst/investigation/tests/hunts.spec.ts` 喂入合成的双客户端 fixture。见到正在与 C2 通信的 LAN IP 之后，`huntsForNewIdentities` 只为该 IP 下发身份 hunt。`huntNotice` 对名称服务、Kerberos 和 SAMR 包含 `ip.addr ==` 该主体，对 `eth-src` 包含 `ip.src ==`，并且不点名空闲工作站。去重、单客户端下发和无效 tshark 字段拒绝仍由既有测试覆盖。

## 后果

点名两台 LAN 客户端的会话转储会把身份 hunt 聚焦到正在与非 LAN 对等体通信的那一台。模型不会被要求把空闲工作站当作 `who` 去猎。主机名收割仍记录工具文本中出现的名称。
