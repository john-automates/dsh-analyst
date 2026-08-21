# Agent Note: 从已接受 C2 持久化中省略 Fastly IPv4 目的地址

Status: implemented

[English](2026-08-21-omit-fastly-ipv4-c2-dests.md) | 中文

## 问题

在[主机名后缀 CDN／更新省略](2026-08-21-refuse-cdn-update-c2.md)和 [Cloudflare IPv4 省略](2026-08-21-omit-cloudflare-ipv4-c2-dests.md)之后，落在已公布 Fastly IPv4 前缀上的遗留额外目的地址仍可能持久化。会话上常常没有 `fastly.net` 主机名——目的地址是为客户域服务的 Fastly 任播，或绑定时尚无主机名证据——因此 `isCdnOrUpdateName` 为假。`acceptedC2Ips` 保留该目的地址。`acceptedC2Domain` 先到先得会持久化那个客户名，并跳过证据落在剩余非 CDN 目的地址上的后来带点名。who/where 仍只属于受害端；C2 附加项是错的。

再加一个一次性主机名后缀，修不了没有 SNI 的 Fastly 目的地址。单个 Fastly IPv4 一次性条目，修不了同一已公布前缀上的下一条遗留。

## 决策

`isFastlyIpv4` 匹配已公布的 Fastly IPv4 任播前缀（[Fastly 公网 IP 列表](https://api.fastly.com/public-ip-list)），包括 `151.101.0.0/16` 和 `199.232.0.0/16`。落在这些段上的目的地址即使证据主机名是客户域或缺失也按 CDN 处理。通用 VPS／托管段不在此检查内。不列出线上案件的黄金 IP。`isCdnOrUpdateName` 仍只做后缀检查；`fastly.net` 仍在主机名列表上。`isCloudflareIpv4` 仍是 Cloudflare 前缀匹配器。

`acceptedC2Ips` 省略已公布的 Fastly 目的地址（包括已绑定 C2），方式与省略证据主机名为 CDN／更新或 IPv4 为 Cloudflare 的目的地址相同。持久化是已证明 extra-wan 集合，包括躲过那些省略的未点名目的地址（[持久化未点名 extra-wan 目的地址](2026-08-21-persist-unnamed-extra-wan-c2-dests.md)）。`acceptedC2Domain`／`projectCaseReport` 把证据落在已证明目的地址上、且不是 CDN／更新的第一个带点 `isC2DomainName` 持久化。只在被丢掉的 Fastly 目的地址上有证据的主机名不会赢。who/where 仍是受害端行。

`resolveBind` 把落在已公布 Fastly 前缀上的唯一非 LAN C2 视为未绑定，拒绝文本与 CDN／更新主机名相同。不编造替代 C2。不下发 extra-wan 和 c2-domain。

[拒绝 CDN／更新 C2](2026-08-21-refuse-cdn-update-c2.md) 仍拥有主机名后缀列表。[省略 Cloudflare IPv4 C2 目的地址](2026-08-21-omit-cloudflare-ipv4-c2-dests.md) 仍拥有 Cloudflare 前缀。scout、遗留报告禁令、身份剩余项、authenticatoor.org 选择、Mission／Plan 门槛、persist-unnamed 宽度和 45.125 裁切不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、带 `cdn-customer.example.test` 的 Fastly 段夹具 `151.101.1.1`／`199.232.0.1`、带 `payload.example.test` 的额外 WAN `203.0.113.50`，以及 LAN 域控。

## 备选方案

**再为客户域或 `fastly.net` 加一个一次性主机名后缀。** 否决：绑定时尚无 Fastly 主机名的遗留仍是 Fastly 任播目的地址。

**把单个 Fastly IPv4 写进 harness 代码或测试。** 否决：同一已公布前缀上的下一条遗留会漏掉。测试使用已记录的段成员 `151.101.1.1` 和 `199.232.0.1`，而不是线上案件的黄金 IP。

**把每个 VPS／通用托管目的地址都当作 CDN。** 否决：非 Fastly 的额外 WAN 目的地址仍须持久化其带点名。

**按 IPv4 段做所有 CDN 省略。** 否决用于 Microsoft、Akamai 和软件更新目的地址：那些任播段会变，主机名后缀才是证据。已公布的 Fastly 前缀与 Cloudflare 是同一类例外：那些目的地址上的客户主机名不是 `fastly.net`。

**重调 Cloudflare 前缀、akamaized.net、persist-unnamed、dest-wins-when-second-c2、unique-collapse、refuse-complete、身份剩余项或 authenticatoor.org 选择。** 否决：那些旋钮已经命中，或是分开的剩余项。

**只改方法论提示词。** 否决：遗留附加项仍会持久化 Fastly 目的地址。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 钉住 `isFastlyIpv4` 在 `151.101.1.1`／`151.101.0.0`／`151.101.255.255`／`23.235.32.0`／`23.235.47.255`／`199.232.0.1` 上为真，并让 TEST-NET、`203.0.113.50`、`151.100.255.255`、`199.231.255.255`、Cloudflare 夹具 `104.16.1.1` 和 `cdn-customer.example.test` 为假。`isCloudflareIpv4('151.101.1.1')` 仍为假。`isCdnOrUpdateName('a.fastly.net')` 仍为真，`isCdnOrUpdateName('cdn-customer.example.test')` 仍为假。`bind.spec.ts` 在有无 `cdn-customer.example.test` 证据落在该目的地址上时都拒绝 `10.0.10.2` ↔ `151.101.1.1`，在没有主机名时拒绝 `10.0.10.2` ↔ `199.232.0.1`，从 `acceptedC2Ips` 丢掉那些目的地址，并从剩余 C2 `198.51.100.80` 或额外 WAN `203.0.113.50` 持久化后来的 `payload.example.test`。who/where 的 hostname 仍是 `lan-host`。现有的 microsoft／msn／bing／sfx／akamai／akamaized／Cloudflare 省略保持不变。

## 后果

落在已公布 Fastly IPv4 前缀上的目的地址即使主机名是客户域或缺失也会从 `c2_ips` 丢掉。只在该目的地址上有证据的主机名不会赢下 `c2_domain`。证据落在剩余非 CDN 目的地址上的后来（或更早）带点名会持久化。没有 CDN 名、也不是 Cloudflare 或 Fastly IP 的已绑定 C2 会留下。who/where 仍是受害端行。
