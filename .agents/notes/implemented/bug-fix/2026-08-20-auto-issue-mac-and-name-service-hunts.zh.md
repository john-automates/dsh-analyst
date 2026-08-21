# Agent Note: 新 IP 后自动下发 MAC 与名称服务 hunt

Status: implemented

[English](2026-08-20-auto-issue-mac-and-name-service-hunts.md) | 中文

## 问题

现场 r6（`b9f2075`，Bedrock 30B，Easy as 123）得 3/5。用户 `brolf`、全名 `Becka Rolf`、C2 和 IP `10.2.28.88` 通过。MAC `00:19:d1:b2:4d:ad` 失败，因为从未下发 `eth.src`。主机名 `DESKTOP-TEYQ2NR` 失败，因为这次运行没有转储 LLMNR/NBNS/BROWSER，所以[主机名摘要收割](2026-08-20-harvest-hostname-from-tshark-summaries.md)没有名称服务行可读。

`huntsForNewIdentities` 在新 IP 后只下发 `kerberos-cname` 与 `samr-userinfo`。感染 IP 出现后，模型没有猎 L2 或名称服务。r3 下发过 `eth.src`，得 4/5。

## 决策

新 IP 还会对该主体下发 `eth-src` 与 `name-service`，然后再下发既有的 Kerberos 与 SAMR hunt。`name-service` 使用显示过滤器 `llmnr or nbns or browser`。SMB 不是 `HuntKind`，不会下发。新主机名与新用户的下发不变。去重仍按 kind+subject 对照已有 hunt 和本批次自身。

`huntNotice` 点名有效的 tshark 4.4.16 字段：MAC hunt 用 `eth.src`（已知 C2 通信 IP 时带 `ip.src ==` 该 IP；[来源 MAC](2026-08-21-harvest-eth-src-from-c2-talking-ip.md)）；名称服务 hunt 用 `llmnr`、`nbns` 和 `browser`，以产生 DESKTOP-* / NBNS Registration / BROWSER Host Announcement 行。当一个 LAN IP 与非 LAN 对等体通信后，这些身份 hunt 只对该 C2 通信 IP 下发（[双客户端融合](2026-08-20-scope-identity-hunts-to-c2-talking-client.md)）。[调查分析预设](../feature/2026-08-20-analyst-investigation-preset.md) 仍拥有收割、SAMR 和其他 hunt 旋钮。

scout、家族收割以及新评测不在本次变更内。已下发 hunt 的执行见[自动运行已下发的身份 hunt](2026-08-21-auto-run-outstanding-identity-hunts.md)。

## 备选方案

**只改方法论提示词。** 否决：r6 在 IP 之后已经按 Kerberos 再 SAMR 做了。缺失的 hunt 从未下发，因此模型没有 MAC 或名称服务通知。

**自动运行 pcap_filter hunt。** 对本下发旋钮否决：执行见[自动运行已下发的身份 hunt](2026-08-21-auto-run-outstanding-identity-hunts.md)。

**新增 SMB hunt 种类。** 否决：SMB 本来就不是 `HuntKind`。那些行出现时，主机名收割已经会读 SMB 摘要。

**在新主机名后下发 MAC 或名称服务。** 否决：现场缺口是新 IP 没有 L2 或名称服务 hunt。

**在同一变更中加入家族收割或发明评测。** 否决：那些是分开的旋钮。

## 测试

`packages/analyst/investigation/tests/hunts.spec.ts` 在新 IP 后下发 `eth-src` 与 `name-service`，保持主机名与用户下发不变，并对照已有 hunt 去重。`huntNotice` 必须点名 `eth.src`、`llmnr`、`nbns`、`browser`、DESKTOP-*、NBNS Registration 和 BROWSER Host Announcement，且不得点名 `smb`。

## 后果

记录到新 IP 后会追加 MAC 与名称服务 hunt，因此模型会被要求转储 `eth.src` 以及 LLMNR/NBNS/BROWSER。主机名仍取决于这些摘要行到达收割。家族收割仍推迟。
