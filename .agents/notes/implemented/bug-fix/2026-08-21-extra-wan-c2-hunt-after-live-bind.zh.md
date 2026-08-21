# Agent Note: 成功绑定后的 extra-WAN C2 hunt

Status: implemented

[English](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) | 中文

## 问题

成功绑定之后，底盘只把唯一已绑定的 C2 当作 C2。受害端 IP 上的其他 WAN 会话不会被猎取或持久化。现有 [`c2-domain`](2026-08-21-c2-domain-hunt-after-live-bind.md) hunt（TLS SNI + DNS）只对那一个已绑定 C2 运行；当带点域名的证据落在另一个 WAN 对等体上，或绑定之后收割到但 `evidence_id` 不是已绑定 C2 时，`CaseReport.c2_domain` 保持为空。

`acceptedC2Domain` 只按 `boundC2Ipv4` 取键。没有东西下发 `ip.src ==` 该 victim 去找其他非 LAN 单播目的地址。额外 C2 IP 从不出现在已接受的结案包上。把那些 IP 或名字捐到 who/where 会反转受害端行。

## 决策

成功的 `bind_relationship` 在唯一 LAN victim 与唯一非 LAN C2 上，下发主体为该 victim IPv4 的 `extra-wan` hunt。过滤器是 `ip.src ==` 该 victim，对非 LAN 单播目的地址讲话，且不是已经绑定的 C2（RFC1918、回环、链路本地、组播、保留地址和 `0.0.0.0` 排除在外）。字段是 `ip.dst`。两端都在 LAN 或 CDN／更新 C2 的拒绝到不了当前绑定，因此不下发该 hunt（[拒绝两端都在 LAN 的绑定](2026-08-21-refuse-both-lan-bind.md)，[拒绝 CDN／更新 C2](2026-08-21-refuse-cdn-update-c2.md)）。

当 `autoHunt` 为 true 时，即使主体是 LAN victim，且即使已有 C2 通信焦点 IP，`extra-wan` 仍通过 `pcap_filter` 自动运行，但仅在一次 Plan 已点名 C2 假设、CDN／DC／更新替代假设以及清单的现场绑定之后。线索为 `invalid` 时仍会挡住。底盘 Mission 不解锁遗留自动运行（[在没有 5W1H 结案时持久化遗留 C2 附加项](2026-08-21-persist-c2-extras-without-close.md)）。`scopeIpFromHunt` 返回该 victim，因此收割把目的 `kind=ip` 的 `evidence_id` 戳成该 victim。插件随后对每个 C2 IPv4（已绑定加上额外地址）下发 [`c2-domain`](2026-08-21-c2-domain-hunt-after-live-bind.md)。`shouldAutoRunHunt` 仍允许非 LAN 主体上的 `c2-domain`。

`acceptedC2Ips` 先放唯一已绑定 C2，再放 `evidence_id` 为该 victim 的非 LAN 单播 IP。先前转储收割到、没有戳记或戳在非 victim 上的 CDN／DNS／更新 IP 不进入。证据主机名为知名 CDN 或更新名的 IP 也被省略，包括已绑定 C2（[拒绝 CDN／更新 C2](2026-08-21-refuse-cdn-update-c2.md)）。Report 钩子把那些剩余 IPv4 复制到 `investigation/extras`，即使散文 `case_report` 保持未绑定，并复制到已接受结案包上可选的 `c2_ips`。`acceptedC2Domain`／`projectCaseReport` 查看证据落在那些剩余 IP 上的主机名身份，仍受 `isC2DomainName` 约束，跳过 CDN／更新名，并把第一个剩余带点名持久化为 `c2_domain`。who/where 仍是受害端行。额外 C2 不捐到 who/where 的 hostname 或 ip。不会发明第二次绑定。LAN／域控／网关／组播／未绑定 WAN／`DESKTOP-*` 保持不在其上。

scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、额外 WAN `203.0.113.50`、干扰 WAN `203.0.113.99`、空闲／域控 LAN 对等体和 `c2.example.test`。

## 备选方案

**等模型在绑定之后自己猎取其他 WAN 对等体。** 否决：绑定之后没有 victim→其他 WAN 的 hunt，所以额外 C2 从不出现。

**把额外 WAN 目的地址当作第二次绑定。** 否决：who/where 只属于受害端。额外 C2 持久化在 `c2_ips` 上，不是绑定端点。

**把额外 C2 IP 或 C2 域名放到 who/where。** 否决：那会把 C2 捐到受害端行。

**只对 `boundC2Ipv4` 下发 `c2-domain`。** 否决：带点名戳在额外 C2 上时，`c2_domain` 仍为空。

**已有 C2 通信焦点 IP 时阻止 `extra-wan`。** 否决：主体是 LAN victim；焦点限定会跳过用来发现额外地址的 hunt。

**把账本上每个非 LAN IP 都当作 `c2_ips`。** 否决：`harvestIdentities` 已经记录工具结果文本中的每个 IPv4。先前转储留下的 CDN／DNS／更新 IP 没有戳记或戳在非 victim 上；那些地址不得持久化，也不得下发 `c2-domain` hunt。

**把线上案件的黄金 C2 IP 或域名写进 harness 代码或测试。** 否决：测试使用 TEST-NET 和 `c2.example.test`。

**发明评测或改动 scout。** 否决：这个旋钮是当前绑定之后的 extra-WAN 收割。

## 测试

`packages/analyst/investigation/tests/hunts.spec.ts` 钉住 LAN `10.0.10.2` 与 TEST-NET C2 `198.51.100.80` 上 `extra-wan` 的过滤器、字段、通知和自动运行。`bind.spec.ts` 把额外 WAN `203.0.113.50`（`evidence_id` 为 victim）持久化到 `c2_ips` 且已绑定 C2 在前，排除没有戳记或戳在非 victim 上的干扰 WAN `203.0.113.99` 以及 LAN／域控／网关，对每个已接受 C2 IP 下发 `c2-domain`，在额外 C2 上戳记时把 `c2.example.test` 持久化为 `c2_domain`，who/where 的 hostname 仍是 `lan-host`、ip 仍是 victim，并且对构造出的 LAN C2 两种 hunt 都不下发。`harvest.spec.ts` 给限定范围的目的 IP 打戳。`investigation.spec.ts` 在 `bind_relationship` 之后下发并自动运行 `extra-wan` 然后按 C2 的 `c2-domain`，且 `203.0.113.99` 不进入 `c2_ips`；两端都在 LAN 或 LAN c2 的拒绝两种都不下发。`analyst-tools/tests/tools.spec.ts` 经 `case_report` 结案，并保持身份槽不变。

## 后果

LAN victim／非 LAN C2 的当前绑定可以在没有模型 SNI、DNS 或额外对等体调用的情况下，持久化额外 WAN C2 IP，以及证据落在那些 IP 上的带点 C2 域名。who/where 仍是受害端行。没有收割则省略 `c2_domain`。两端都在 LAN 的拒绝仍不下发 C2 hunt。
