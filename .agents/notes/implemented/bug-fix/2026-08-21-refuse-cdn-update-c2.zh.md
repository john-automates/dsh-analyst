# Agent Note: 拒绝 CDN／更新目的地址作为 BindRelationship C2

Status: implemented

[English](2026-08-21-refuse-cdn-update-c2.md) | 中文

## 问题

在 [extra-WAN](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) 之后，遗留附加项绑定可能从被裁切的 80／443 转储里取第一个 `:443` 目的地址。该目的地址可能是知名 CDN 或软件更新对等体（Akamai／Microsoft SNI），而不是恶意软件 C2。extra-wan 随后持久化每个盖上受害端戳的 WAN 目的地址，包括那些 CDN／更新噪声。`acceptedC2Domain` 先到先得可能持久化 Microsoft 更新 SNI，并跳过另一个额外 IP 上后来的非 CDN 带点名。who/where 仍只属于受害端；C2 附加项是错的。

`resolveBind` 已经拒绝[两端都在 LAN 的会话](2026-08-21-refuse-both-lan-bind.md)和 LAN `c2`。它接受任何唯一的非 LAN C2。`isC2DomainName` 只要求带点且不是 IPv4 的名字。

## 决策

`isCdnOrUpdateName` 是对知名公共 CDN 与软件更新域的后缀检查：`microsoft.com`、`windows.com`、`windowsupdate.com`、`office.com`、`live.com`、`akamai.net`、`akamaiedge.net`、`akamaihd.net`、`akadns.net`、`edgesuite.net`、`edgekey.net`、`cloudflare.com`、`cloudfront.net`、`fastly.net`。可注册后缀及其子域匹配（`update.microsoft.com`、`a1.akamai.net`）。不以 IPv4 段为键。不列出线上案件的黄金名。`isC2DomainName` 保持不变；这项检查是额外的。

`resolveBind` 接受可选的已折叠身份和工具结果文本。在现有请求检查之后，唯一非 LAN C2 若有证据落在其上的 CDN／更新主机名，则保持未绑定。证据是 `evidence_id` 为该 C2 IPv4 的已收割主机名，或点名该 IP 的行上被引用会话的 TLS SNI、HTTP host 或 DNS 名。拒绝文本是 `unbound: role c2 cannot be a well-known CDN or update destination.` 不编造替代 C2。不记录绑定。与两端都在 LAN 一样，不下发 extra-wan 和 c2-domain。

`acceptedC2Ips` 省略证据主机名为 CDN／更新的 IP，包括已绑定 C2。不是 CDN／更新的、盖上受害端戳的额外地址仍持久化。`acceptedC2Domain`／`projectCaseReport` 把证据落在任何剩余 C2 IP 上、且不是 CDN／更新的第一个带点 `isC2DomainName` 持久化。CDN／更新名永远不会赢。who/where 仍是受害端行。

[BindRelationship](../feature/2026-08-21-bind-relationship.md) 仍拥有结案前绑定。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、带 `update.microsoft.com` 或 `a1.akamai.net` 的 CDN 目的地址 `203.0.113.80`、带 `payload.example.test` 的额外 WAN `203.0.113.50`，以及 LAN 域控。

## 备选方案

**接受第一个非 LAN `:443` 目的地址，并让 extra-wan 给每个 victim→WAN 对等体打戳。** 否决：CDN／更新对等体会成为已绑定 C2，其 SNI 可能赢下 `c2_domain`。

**当唯一目的地址是 CDN／更新时编造替代 C2。** 否决：不会对调 token，也不编造 C2。拒绝绑定。

**按 IPv4 段做分类。** 否决：CDN 与更新任播段会变。主机名后缀才是证据。

**把线上案件的黄金 IP 或主机名写进 harness 代码或测试。** 否决：测试使用 TEST-NET、`update.microsoft.com`、`a1.akamai.net` 和 `payload.example.test`。

**把 CDN／更新折进 `isC2DomainName`，从而不收割那些名字。** 否决：收割仍须记录该名字，绑定和持久化才能拒绝它。

**只改方法论提示词或工具描述。** 否决：遗留附加项绑定仍会接受 CDN 目的地址。

**发明评测或改动 scout。** 否决：这个旋钮是绑定上的 CDN／更新拒绝以及遗留附加项。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 钉住所列后缀与子域上的 `isCdnOrUpdateName`，并让 `payload.example.test`／`evilmicrosoft.com` 不匹配。`bind.spec.ts` 在 `update.microsoft.com` 或 `a1.akamai.net` 证据落在该目的地址上时（身份或被引用会话的 SNI／HTTP host）拒绝 `10.0.10.2` ↔ `203.0.113.80` 且不下发 hunt；带 `payload.example.test` 的 `10.0.10.2` ↔ `198.51.100.80` 仍接受。`acceptedC2Ips` 丢掉主机名为 `update.microsoft.com`、盖上受害端戳的 `203.0.113.80`，并保留额外 WAN `203.0.113.50`。`acceptedC2Domain` 跳过该 Microsoft 名，并从另一个 C2 IP 持久化 `payload.example.test`。who/where 的 hostname 仍是 `lan-host`。两端都在 LAN 和 LAN-C2 的拒绝保持不变。`investigation.spec.ts` 通过 `tools.execute` 拒绝 CDN 绑定且不记录 extra-wan 或 c2-domain，接受 payload C2，并在没有 CDN 目的地址的情况下持久化遗留附加项。

## 后果

证据名为知名 CDN 或更新目的地址的唯一 C2 保持未绑定，且不下发 C2 hunt。当前绑定之后，遗留附加项从 `c2_ips` 省略那些目的地址，也绝不让那些名字赢下 `c2_domain`。who/where 仍是受害端行。没有收割则省略 `c2_domain`。
