# Agent Note: 只把已证明的 C2 目的地址持久化到 c2_ips

Status: implemented

[English](2026-08-21-persist-attested-c2-dests.md) | 中文

## 问题

在 [extra-WAN](2026-08-21-extra-wan-c2-hunt-after-live-bind.md)、[CDN／更新省略](2026-08-21-refuse-cdn-update-c2.md) 和 [Cloudflare IPv4 省略](2026-08-21-omit-cloudflare-ipv4-c2-dests.md) 之后，遗留附加项会持久化每个盖上受害端戳、且不是 CDN／CF 的非 LAN 目的地址。没有主机名的 extra-wan 收割 IP 会躲过那些省略。`c2_ips` 于是在已绑定 C2 和证据落在已接受域名上的目的地址旁边，列出未点名的遗留 WAN 目的地址。who/where 仍只属于受害端；C2 附加项是错的。

若先把持久化缩成只含已绑定 C2，证据落在已接受非 CDN 带点名上的目的地址会消失，`c2_domain` 会回退。

## 决策

`acceptedC2Domain` 仍选择证据落在已证明附加项上、且不是 CDN／更新的第一个带点 `isC2DomainName`。已证明附加项是已绑定 C2，加上盖上受害端戳、不是已公布 Cloudflare 目的地址、也没有知名 CDN 或更新主机名的 WAN 目的地址。extra-wan 和 `c2-domain` 仍在该已证明集合上 hunt。

持久化 `acceptedC2Ips` 是已绑定 C2（当它不是 CDN／CF 时），加上证据落在该已接受域名上的目的地址。没有这种证明的遗留、盖上受害端戳的 WAN 目的地址不持久化。who/where 仍是受害端行。不会发明第二次绑定。

身份遗留、已接受 C2 域名目的地址的选择方式、Cloudflare 前缀、CDN／更新后缀列表、Mission／Plan 门、自动结案和 extra-wan 裁切不在本次变更内（[在裁切之前对 extra-wan 目的地址按首次出现去重](2026-08-21-unique-collapse-extra-wan-before-clip.md)）。测试使用合成 LAN 客户端、TEST-NET C2 `198.51.100.80`、带 `payload.example.test` 或 `c2.example.test` 的额外 WAN `203.0.113.50`、未点名额外地址 `203.0.113.60`、CDN 目的地址 `203.0.113.80`，以及 Cloudflare 段夹具 `104.16.1.1`。不列出线上案件的黄金名和 IP。

## 备选方案

**先把持久化缩成只含已绑定 C2，再从该集合选择 `c2_domain`。** 否决：证据落在已接受带点名上的目的地址会消失，`c2_domain` 会回退。

**把每个盖上受害端戳的非 CDN 附加项都留在 `c2_ips` 上。** 否决：未点名的遗留附加项会持久化。

**把线上案件的黄金名或 IP 写进 harness 代码或测试。** 否决：测试使用 TEST-NET、`payload.example.test` 和 `c2.example.test`。

**重调 Cloudflare 前缀或 CDN／更新后缀列表。** 否决：未点名附加项没有主机名，也不在那些前缀里。

**自动结案身份、改动遗留身份持久化，或改 Mission／Plan 门。** 否决：那些遗留是分开的。

**在同一次持久化里修 extra-wan 遗留裁切。** 否决：那次未命中是另一项遗留（[在裁切之前对 extra-wan 目的地址按首次出现去重](2026-08-21-unique-collapse-extra-wan-before-clip.md)）。

**只改 methodology 提示。** 否决：遗留附加项仍会持久化未点名目的地址。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 在额外 WAN `203.0.113.50` 上有 `payload.example.test` 或 `c2.example.test` 证据时，持久化已绑定 C2 `198.51.100.80` 加上该额外地址，丢掉未点名额外地址 `203.0.113.60`，并仍省略 microsoft／msn／bing／sfx／akamai／Cloudflare 目的地址。`acceptedC2Domain` 仍优先选择 `payload.example.test` 而不是 CDN 名。who/where 的 hostname 仍是 `lan-host`。extra-wan 和 `c2-domain` hunt 仍对已证明附加项下发，包括一个不持久化的未点名目的地址。

## 后果

`c2_ips` 持有已绑定 C2 和证据落在已接受非 CDN 域名上的目的地址。未点名的遗留附加项被丢掉。证据落在已证明目的地址上的带点名仍会赢下 `c2_domain`。who/where 仍是受害端行。
