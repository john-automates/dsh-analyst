# Agent Note: 从已接受 C2 持久化中省略 Cloudflare IPv4 目的地址

Status: implemented

[English](2026-08-21-omit-cloudflare-ipv4-c2-dests.md) | 中文

## 问题

在[主机名后缀 CDN／更新省略](2026-08-21-refuse-cdn-update-c2.md)之后，落在已公布 Cloudflare IPv4 前缀上的遗留额外目的地址仍可能持久化。该目的地址上的证据主机名常常是客户域，而不是 `cloudflare.com`，因此 `isCdnOrUpdateName` 为假。`acceptedC2Ips` 保留该目的地址。`acceptedC2Domain` 先到先得会持久化那个客户名，并跳过证据落在剩余非 CDN 目的地址上的后来带点名。who/where 仍只属于受害端；C2 附加项是错的。

再加一个一次性主机名后缀，修不了同一任播目的地址上的下一个客户名。

## 决策

`isCloudflareIpv4` 匹配已公布的 Cloudflare IPv4 任播前缀（[Cloudflare IP 段](https://www.cloudflare.com/ips/)），包括 `104.16.0.0/13`。落在这些段上的目的地址即使证据主机名是客户域也按 CDN 处理。通用 VPS／托管段不在此检查内。不列出线上案件的黄金 IP。`isCdnOrUpdateName` 仍只做后缀检查；`evilcloudflare.com` 仍为假。

`acceptedC2Ips` 省略已公布的 Cloudflare 目的地址（包括已绑定 C2），方式与省略证据主机名为 CDN／更新的目的地址相同。持久化是已绑定 C2（当它不是 CDN／CF 时）加上证据落在已接受非 CDN `c2_domain` 上的目的地址；未点名的遗留附加项不持久化（[只持久化已证明 C2 目的地址](2026-08-21-persist-attested-c2-dests.md)）。`acceptedC2Domain`／`projectCaseReport` 把证据落在已证明目的地址上、且不是 CDN／更新的第一个带点 `isC2DomainName` 持久化。只在被丢掉的 Cloudflare 目的地址上有证据的主机名不会赢。who/where 仍是受害端行。

`resolveBind` 把落在已公布 Cloudflare 前缀上的唯一非 LAN C2 视为未绑定，拒绝文本与 CDN／更新主机名相同。不编造替代 C2。不下发 extra-wan 和 c2-domain。

[拒绝 CDN／更新 C2](2026-08-21-refuse-cdn-update-c2.md) 仍拥有主机名后缀列表。scout、遗留报告禁令、身份剩余项、Mission／Plan 门槛和 45.125 裁切不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、带 `cdn-customer.example.test` 的 Cloudflare 段夹具 `104.16.1.1`、带 `payload.example.test` 的额外 WAN `203.0.113.50`，以及 LAN 域控。

## 备选方案

**再为客户域加一个一次性主机名后缀。** 否决：同一 Cloudflare 目的地址上的下一条遗留会换一个客户名。

**把每个 VPS／通用托管目的地址都当作 CDN。** 否决：非 Cloudflare 的额外 WAN 目的地址仍须持久化其带点名。

**按 IPv4 段做所有 CDN 省略。** 否决用于 Microsoft、Akamai 和软件更新目的地址：那些任播段会变，主机名后缀才是证据。已公布的 Cloudflare 前缀是例外，因为那些目的地址上的客户主机名不是 `cloudflare.com`。

**把线上案件的黄金 IP 或主机名写进 harness 代码或测试。** 否决：测试使用 TEST-NET、`104.16.1.1`、`cdn-customer.example.test` 和 `payload.example.test`。

**把身份剩余项、自动结案、Mission／Plan 门槛或 45.125 裁切折进这个持久化旋钮。** 否决：那些剩余项是分开的。

**只改方法论提示词。** 否决：遗留附加项仍会持久化 Cloudflare 目的地址。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 钉住 `isCloudflareIpv4` 在 `104.16.1.1`／`104.16.0.0`／`104.23.255.255`／`172.64.0.1` 上为真，并让 TEST-NET、`203.0.113.50`、`104.15.255.255` 和 `cdn-customer.example.test` 为假。`isCdnOrUpdateName('evilcloudflare.com')` 与 `isCdnOrUpdateName('cdn-customer.example.test')` 仍为假。`bind.spec.ts` 在有无 `cdn-customer.example.test` 证据落在该目的地址上时都拒绝 `10.0.10.2` ↔ `104.16.1.1`，从 `acceptedC2Ips` 丢掉该目的地址，并从剩余 C2 `198.51.100.80` 或额外 WAN `203.0.113.50` 持久化后来的 `payload.example.test`。who/where 的 hostname 仍是 `lan-host`。现有的 microsoft／msn／bing／sfx／akamai 名称省略保持不变。

## 后果

落在已公布 Cloudflare IPv4 前缀上的目的地址即使主机名是客户域也会从 `c2_ips` 丢掉。只在该目的地址上有证据的主机名不会赢下 `c2_domain`。证据落在剩余非 CDN 目的地址上的后来（或更早）带点名会持久化。没有 CDN 名、也不是 Cloudflare IP 的已绑定 C2 会留下。who/where 仍是受害端行。
