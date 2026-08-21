# Agent Note: 成功绑定后的 C2-domain hunt

Status: implemented

[English](2026-08-21-c2-domain-hunt-after-live-bind.md) | 中文

## 问题

身份结案可以在正确的 LAN victim／非 LAN C2 方向下达到 5/5，而 C2 域名附加项仍然失败。模型从未对已绑定 C2 IP 查询 TLS SNI 或 DNS，因此该名称从未进入会话或已接受的结案包。

`huntsToAutoRun` 不会运行主体为非 LAN／C2 IP 的 hunt，但 [`other-end`](2026-08-21-other-end-hunt-on-cue-victim.md) 除外。没有针对已绑定 C2 的 TLS SNI／DNS hunt 种类。`CaseReport` 只有 who／what／when／where／why／how；没有东西把 C2 域名持久化到已接受的结案包。改写 who/where 的 hostname 会把 C2 名捐到受害端行。

## 决策

成功的 `bind_relationship` 在唯一非 LAN 的 `c2` IPv4 上，下发主体为该 C2 的 `c2-domain` hunt，然后 [extra-WAN](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) 对每个收割到的额外 WAN IPv4 下发同样的 hunt。过滤器是 `tls.handshake.extensions_server_name or dns.qry.name or dns.resp.name`，并用 `ip.addr ==` 该 C2 限定范围。这三个名字是有效的 tshark 4.4.16 字段。两端都在 LAN 的拒绝到不了当前绑定，因此不会对 LAN C2 下发该 hunt（[拒绝两端都在 LAN 的绑定](2026-08-21-refuse-both-lan-bind.md)）。

当 `autoHunt` 为 true 时，`c2-domain` 像 `other-end` 一样通过 `pcap_filter` 自动运行，即使其主体是 C2。[身份 hunt 自动运行](2026-08-21-auto-run-outstanding-identity-hunts.md) 仍对 `eth-src`、`name-service`、Kerberos 和 SAMR 跳过非 LAN 主体。

收割把 SNI 或 DNS 名记为主机名，`evidence_id` 为该 C2 IP。工作组和 NBNS token 仍按今天的规则拒绝。在非 LAN C2 的 `scopeIp` 下，单标签的 LAN／域控／NetBIOS 名不会被记录。该主机名不捐出 who/where（[BindRelationship](../feature/2026-08-21-bind-relationship.md)）。已接受的 `case_report` 把证据落在那些 C2 IPv4（已绑定加上额外地址）上的第一个带点 DNS 名复制到可选的 `c2_domain`。没有收割到时省略该字段。不会编造域名。

scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲／域控 LAN 对等体和 `c2.example.test`。

## 备选方案

**等模型去查 TLS SNI 或 DNS。** 否决：正确绑定之后，C2 域名附加项仍因零次会话命中失败。

**把 C2 名放到 who/where 的 hostname。** 否决：那会把 C2 域名捐到受害端行。

**对主体为 C2 IP 的每一个 hunt 都自动运行。** 否决：那会持久化对端网卡和 LAN 名称服务行。例外只有 `c2-domain`，与 `other-end` 并列。

**编造域名，或把黄金 C2 名写进 harness 代码或测试。** 否决：只持久化收割到的带点 DNS 名。测试使用 `c2.example.test`，不用线上案件值。

**在收割到 C2 IP 时由 `huntsForNewIdentities` 下发 `c2-domain`。** 否决：该 hunt 限定在当前绑定的 C2 角色，而不是每一个非 LAN IP。

**发明评测或改动 scout。** 否决：这个旋钮是当前绑定之后的 C2 域名收割。

## 测试

`packages/analyst/investigation/tests/hunts.spec.ts` 钉住 TEST-NET `198.51.100.80` 上 `c2-domain` 的过滤器、字段、通知和自动运行。`harvest.spec.ts` 把 `tls.handshake.extensions_server_name`／`dns.qry.name` 收割为主机名且 `evidence_id` 为该 C2，并让 `lan-host`／`dc01`／工作组离开该范围。`bind.spec.ts` 把 `c2.example.test` 持久化为 `c2_domain`，who/where 的 hostname 仍是 `lan-host`，并且对构造出的 LAN C2 不下发 hunt。`investigation.spec.ts` 在 `bind_relationship` 之后下发并自动运行该 hunt；两端都在 LAN 或 LAN c2 的拒绝不下发。`analyst-tools/tests/tools.spec.ts` 经 `case_report` 结案，并保持身份槽不变。

## 后果

LAN victim／非 LAN C2 的当前绑定可以在没有模型 SNI 或 DNS 调用的情况下持久化已证实的 C2 域名。who/where 仍是受害端行。没有收割则省略 `c2_domain`。两端都在 LAN 的拒绝仍不下发 C2 hunt。
