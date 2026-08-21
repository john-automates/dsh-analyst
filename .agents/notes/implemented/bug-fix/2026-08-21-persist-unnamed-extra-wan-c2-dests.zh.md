# Agent Note: 把未点名 extra-wan 目的地址持久化到 c2_ips

Status: implemented

[English](2026-08-21-persist-unnamed-extra-wan-c2-dests.md) | 中文

## 问题

在[对 extra-wan 按首次出现去重](2026-08-21-unique-collapse-extra-wan-before-clip.md)之后，extra-wan 可以收割未点名、盖上受害端戳的 WAN 目的地址。[只持久化已证明 C2 目的地址](2026-08-21-persist-attested-c2-dests.md)只保留已绑定 C2（当它不是 CDN／CF 时），以及证据落在已接受非 CDN `c2_domain` 上的目的地址。躲过 CDN／更新主机名省略和 Cloudflare IPv4 省略的未点名 extra-wan 目的地址仍会从 `c2_ips` 丢掉。who/where 仍只属于受害端；收割到的附加项缺失。

若先把持久化缩成只含已绑定 C2，那些目的地址仍会丢掉。重调 `acceptedC2Domain` 也不会把未点名目的地址放进 `c2_ips`。

## 决策

`acceptedC2Ips` 就是已证明 extra-wan 集合：已绑定 C2（当它不是 CDN／CF 时），加上躲过 `ipIsCdnOrUpdate`（证据主机名为 CDN／更新，或已公布 Cloudflare IPv4）的、盖上受害端戳的 extra-wan 目的地址。躲过那些省略的未点名目的地址会持久化。`isCdnOrUpdateName` 或 `isCloudflareIpv4` 会省略的目的地址仍丢掉。

`acceptedC2Domain` 仍选择证据落在该已证明集合上、且不是 CDN／更新的第一个带点 `isC2DomainName`。who/where 仍是受害端行。不会发明第二次绑定。

[只持久化已证明 C2 目的地址](2026-08-21-persist-attested-c2-dests.md)仍拥有从已证明附加项选择域名、以及不先把持久化缩成只含已绑定 C2 的决策。unique-collapse 裁切、refuse-complete、身份遗留、authenticatoor.org 选择、CDN／CF 后缀与前缀列表、Mission／Plan 门和线上案件黄金 IP 不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2 `198.51.100.80`、未点名附加项 `203.0.113.50`／`203.0.113.60`、带 `update.microsoft.com` 的 CDN 目的地址 `203.0.113.80`，以及 Cloudflare 段夹具 `104.16.1.1`。

## 备选方案

**把持久化保持为已绑定 C2 加上证据落在已接受域名上的目的地址。** 否决：躲过 CDN／CF 省略的未点名 extra-wan 目的地址仍会丢掉。

**持久化每一个收割到的 WAN 目的地址，包括 CDN／CF。** 否决：CDN／更新主机名省略和 Cloudflare IPv4 省略保持不变。

**重调 `acceptedC2Domain`，或加入 akamaized.net／authenticatoor.org 选择。** 否决：域名选择是另一项遗留。

**把 45.125 目的地址写进 harness 代码或测试。** 否决：测试使用 TEST-NET 附加项。

**重调 unique-collapse 裁切、`maxOutputChars` 或 refuse-complete。** 否决：那些旋钮已经命中。

**改动身份遗留或 who/where。** 否决：who/where 仍只属于受害端。

**只改 methodology 提示。** 否决：遗留附加项仍会丢掉未点名目的地址。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 在有无已接受域名时都持久化未点名附加项 `203.0.113.50` 和 `203.0.113.60`，仍省略带 `update.microsoft.com` 的目的地址 `203.0.113.80` 和 Cloudflare 目的地址 `104.16.1.1`，并在 `payload.example.test` 证据落在剩余目的地址上时把 `acceptedC2Domain` 留在该名。who/where 的 hostname 仍是 `lan-host`。`investigation.spec.ts` 的遗留附加项包含未点名目的地址，并仍省略 CDN 目的地址。现有的 microsoft／msn／bing／sfx／akamai／Cloudflare 省略保持不变。

## 后果

未点名的非 CDN extra-wan 目的地址会进入 `c2_ips`。证据主机名为 CDN／更新的目的地址，或 Cloudflare IPv4，仍丢掉。域名选择不变。who/where 仍是受害端行。
