# Agent Note: 从 tshark 名称服务摘要收割主机名

Status: implemented

[English](2026-08-20-harvest-hostname-from-tshark-summaries.md) | 中文

## 问题

`harvestIdentities` 只从带标签的键（`hostname|host|nbns.name|dns.qry.name := value`）记录主机名。默认的 `pcap_filter` 转储已经在 tshark Info 文本中点名工作站，而不是那些标签：`LLMNR Standard query ANY DESKTOP-TEYQ2NR`、`NBNS Registration NB DESKTOP-TEYQ2NR<00>` / `<20>`、`BROWSER Request Announcement DESKTOP-TEYQ2NR`，以及 `BROWSER Host Announcement DESKTOP-TEYQ2NR`。因此身份账本漏掉主机名，`case_report` 的 `where` 只能写 IP 和 MAC。[调查分析预设](../feature/2026-08-20-analyst-investigation-preset.md) 已经持久化收割到的身份；这个缺口是主机名解析器，不是账本。

## 决策

`harvestIdentities` 也会从 NBNS、BROWSER、SMB 和 LLMNR 的 tshark 摘要形式持久化 `kind: hostname`。DESKTOP-* NetBIOS 名称和 Host Announcement 名称会落地。能区分出的工作组和域 token（`Domain/Workgroup Announcement`、`Local Master Announcement`，或 NBNS 后缀 `<1b>`–`<1e>`）不会记为主机名，因此像 `EASYAS123` 这样的 token 会被省略，即使同一转储还带有 `EASYAS123<00>` 或对该名称的 Request Announcement。IP、MAC、用户和全名收割不变。带标签的主机名键仍按先见顺序胜出。

## 备选方案

**要求每次 `pcap_filter` 都带 `-e nbns.name` 或 `dns.qry.name`。** 否决，因为现场转储已经在默认摘要里包含主机名。只解析字段的解析器会让这些运行没有主机名身份。

**收割每一个像 NetBIOS 的 token。** 否决，因为 `EASYAS123` 这类工作组和域名会被记为主机名。

**克隆 scout 或 Beldum 的收割。** 否决：那些树不在范围内，且本仓库禁止泄露或复制该源码。

**在同一变更中加入恶意软件家族收割或新的 eval。** 否决：那些是与主机名持久化分开的旋钮。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 喂入 Easy as 123 的 tshark 摘要行以及工作组形式。`harvestIdentities` 必须得到归一化主机名 `desktop-teyq2nr`，且不得得到 `easyas123`。相邻的 IP `10.2.28.88`、MAC `00:19:d1:b2:4d:ad`、用户 `brolf` 和全名 `Becka Rolf` 仍被收割。

## 后果

在只有摘要的 `pcap_filter` 转储之后，身份账本可以包含主机名，因此 `where` 可以点名工作站。点名的 NBNS、BROWSER、SMB 和 LLMNR 主机形式之外的异常 tshark 措辞仍会被省略。既是工作组 token 又是 Host Announcement 的名称按工作组处理并丢弃。
