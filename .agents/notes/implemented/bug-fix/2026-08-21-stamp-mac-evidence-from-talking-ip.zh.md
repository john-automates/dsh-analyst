# Agent Note: 把 MAC 的 evidence_id 戳成通信 IP，而不是 hunt 主体

Status: implemented

[English](2026-08-21-stamp-mac-evidence-from-talking-ip.md) | 中文

## 问题

线上 lumma-r11（`a448b28`）正确绑定了被引用的会话。[受害端 IP 范围捐出](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) 的主机名捐出已生效（账本上还有其他主机名；受害端主机名仍落地）。结案栏 4/5 — MAC 失败。黄金 MAC 在第一次收割时被账本标成域控的 `evidence_id`，从未改戳到受害端。模型后来在 tshark 里在受害端 IP 上看到了同一 MAC。域控 MAC 和网关 MAC 没有进入受害端行。会话捐出通知计数为 0。

`harvestIdentities` 把每一个收割到的 MAC 的 `evidence_id` 写成 `scopeIp`（hunt 主体）。第一次转储限定在域控，工作站 MAC 因此锁到域控。`recordIdentity` 按 kind+value 唯一，因此后来的受害端 IP 转储不会改戳。`scopedIpForIdentity` 把 hunt 主体 `evidence_id` 当成归属，捐给域控而不是受害端。`identityDonatesToVictim` 在该 `evidence_id` 点名非 victim 端点时也会拒绝。

## 决策

收割到的 MAC 把 `evidence_id` 写成该行上来源该 `eth.src` 的通信 IPv4：带标签的 `ip.src`、出站 `ip → peer`，或 ARP `is at`。这两个 IP 不一致时，通信 IP 胜出。没有通信 IP 的仅字段 `eth.src` 转储戳 hunt 主体 `scopeIp`（[受害端 IP 范围改戳](2026-08-21-restamp-victim-ip-scoped-eth-src.md)）。主机名仍从 `name-service` 转储戳 hunt 主体 `evidence_id`。

当前绑定之后，即使 MAC 第一次出现在域控或对等体 hunt 下，只要任一工具结果帧把该 MAC 从来自被绑定 victim IP 的方向送出，就仍捐给 victim。hunt 主体 `evidence_id` 不能否决。持久化的 who/where 携带该 mac。从未作为来自 victim IP 的 `eth.src` 出现的域控或网关 MAC 不捐出。不会编造槽位。

[受害端 IP 范围捐出](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) 仍从 hunt 主体 `evidence_id` 或名称服务行捐出主机名。线索作为 victim 仍被拒绝，并仍下发 [other-end](2026-08-21-other-end-hunt-on-cue-victim.md)。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体和空闲或域控 LAN 行。

## 备选方案

**继续把 hunt 主体 `evidence_id` 戳在 MAC 上，只让捐出忽略它。** 对收割否决：第一次写入是持久的。戳通信 IP 记录的是谁送出了该帧。捐出仍会在后来的帧把该 MAC 从来自 victim 的方向送出时，忽略错误的第一次戳记。

**在已经有通信 IP 或其他 IPv4 戳记的后来受害端 IP 转储上改戳 `evidence_id`。** 此处否决：行上仍是通信 IP 胜出，捐出已经读取后来的受害端 IP 帧。给第一次收割缺少的 `evidence_id` 补上限定在受害端 IP 的仅字段转储，见[受害端 IP 范围改戳](2026-08-21-restamp-victim-ip-scoped-eth-src.md)。

**捐出与 victim IP 出现在同一行的每一个 MAC（`ip.addr`）。** 否决：入站帧会带上对端或域控网卡。来源是指 `ip.src`、出站 `ip → peer` 或 ARP `is at`。

**捐出从未作为 victim IP 上 eth.src 出现的域控或网关 MAC。** 否决：那些网卡不进入受害端行。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture（测试前置数据）是合成 LAN IP、TEST-NET 对等体和空闲或域控 LAN 行。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET 对等体（`198.51.100.80`）和空闲或域控行（`10.0.10.3`）。通信 IP 为 `10.0.10.2` 的行上的 MAC 即使 `scopeIp` 是 `10.0.10.3` 也戳成该 IP。主机名仍戳 hunt 主体。没有通信 IP 的仅字段 `eth.src` 转储戳 hunt 主体 `evidence_id`（[受害端 IP 范围改戳](2026-08-21-restamp-victim-ip-scoped-eth-src.md)）。

`packages/analyst/investigation/tests/bind.spec.ts` 先把客户端 MAC 记成 `evidence_id=10.0.10.3`，再给出 `ip.src=10.0.10.2` 上的 `eth.src` 证据文本。当前绑定之后，该 MAC 捐出并持久化到 who/where。从未出现在 `10.0.10.2` 上的域控 MAC 不捐出。主机名捐出和拒绝将线索指定为 victim 保持不变。

## 后果

当帧点名了不同的通信 IP 时，限定在域控的第一次收割不能把工作站 MAC 锁到域控。即使第一次戳记错误，后来的帧把该 MAC 从来自被绑定 victim 的方向送出时仍会捐出。主机名捐出不变。用户和全名戳会话客户端（[会话客户端戳记](2026-08-21-stamp-user-fullname-from-conversation-client.md)）。
