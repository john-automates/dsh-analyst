# Agent Note: Persist eth.src sourced from the C2-talking LAN IP

Status: implemented

[English](2026-08-21-harvest-eth-src-from-c2-talking-ip.md) | 中文

## 问题

现场 First to Last r3（`365f74e`，Bedrock 30B）得 4/5。去引号、C2 hunt 限定范围和主机名收割已经把 `who` 与 `where` 挂到正在与 C2 通信的客户端。报告中的 MAC 是对端网卡：`eth-src` hunt 跑了 `ip.addr == <client>`（双向），模型取了转储里的第一个 MAC。黄金客户端 MAC 也被收割到了。

`harvestIdentities` 记录工具文本中的每一个 MAC。`eth-src` 的 `huntNotice` 使用 `ip.addr ==` 该主体，与名称服务、Kerberos 和 SAMR 的限定词相同。

## 决策

当 `c2TalkingLanIps` 已有焦点 IP 时，`harvestIdentities` 只在 MAC 来自该 IP 时记录：带标签的 `ip.src` 等于焦点且带 `eth.src`（或该行第一个 MAC）、出站的 `focus → peer` 会话行，或 ARP `<focus> is at <mac>`。入站的 `peer → focus` 行和空闲 LAN 工作站行不会被记录。当前文本没有 IPv4、只有带标签的 `eth.src` 列时，记录严格多数的 MAC；平局则一个都不记，因此双向转储无法取胜。

`eth-src` 的 `huntNotice` 使用 `display_filter` `(eth.src) and ip.src == <subject>` 以及字段 `eth.src`。其他以 IP 为主体的 hunt 仍使用 `ip.addr ==`（[双客户端融合](2026-08-20-scope-identity-hunts-to-c2-talking-client.md)）。检测使用当前工具结果，加上会话日志中已折叠的 `tool/result` 文本。

[去引号](2026-08-21-pcap-filter-quoted-display-filter.md)、[字符串字段强制转换](2026-08-20-pcap-filter-string-fields.md) 和[主机名收割](2026-08-20-harvest-hostname-from-tshark-summaries.md)保持不变。scout、家族收割、遗留报告禁令和新评测不在本次变更内。已下发 hunt 的执行见[自动运行已下发的身份 hunt](2026-08-21-auto-run-outstanding-identity-hunts.md)。

## 备选方案

**eth-src 通知继续使用 `ip.addr ==`，并教模型挑选客户端 MAC。** 否决：r3 已经收割了两个 MAC；模型取了第一个。

**记录提到焦点 IP 的那一行上的每一个 MAC。** 否决：那是 `ip.addr` 语义。入站帧会带上对端网卡。

**自动运行已限定范围的 pcap_filter hunt。** 对本持久化旋钮否决：执行见[自动运行已下发的身份 hunt](2026-08-21-auto-run-outstanding-identity-hunts.md)。

**把案件黄金 MAC 写进提示词或测试。** 否决：测试使用合成的双客户端、双 MAC fixture。案件名称、IP 和 MAC 不是期望答案。

**把名称服务、Kerberos 和 SAMR 通知改成 `ip.src`。** 否决：这些 hunt 需要发给客户端的回复。它们仍使用 `ip.addr`。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 与 `hunts.spec.ts` 喂入合成的双 MAC fixture（一个 LAN IP 与 TEST-NET 对等体通信；另一个留在 LAN 内）。见到正在与 C2 通信的 IP 之后，只记录来自该 IP 的 MAC。带两个 `eth.src` 值的双向字段转储只记录 `ip.src ==` 焦点的 MAC。`eth-src` 的 `huntNotice` 包含 `ip.src ==`，且不包含 `ip.addr ==`。`investigation.spec.ts` 通过 post-execute 记录该来源 MAC。

## 后果

双向 `eth.src` 转储不能把对端网卡持久化为身份。模型被要求用 `ip.src ==` 正在与 C2 通信的 LAN IP 做过滤。主机名、用户和全名收割保持不限定范围。
