# Agent Note: 拒绝将线索指定为 victim 时下发 other-end hunt

Status: implemented

[English](2026-08-21-other-end-hunt-on-cue-victim.md) | 中文

## 问题

线上 lumma-r9（`5400341`）从未武装受害端行捐出，因为绑定从未成功。绑定触发两次，两次都因未绑定被拒绝（[拒绝将线索指定为 victim](2026-08-21-refuse-cue-as-victim.md) 生效）：victim 是线索／C2 且 c2 是 LAN 域控，然后 victim 与 c2 都是同一线索地址。随后 `case_report` 因未绑定被拒绝。没有 `investigation/bind` 或 `investigation/report`。黄金 LAN IP 和主机名从未出现在会话中。黄金 MAC 只在账本上。用户和全名只在账本加上被拒绝的结案中。模型对调了线索，然后退出，而不是去猎取 LAN 对端。运行 70 秒，退出码 0。

检测器 IP 是关于另一端的假设。停在 `UNBOUND_REASON` 只点名了规则，没有点名 hunt。

## 决策

当 `bind_relationship` 因为被指定的 victim 是线索／观测地址（`isCueObservationAddr`／非 LAN 单播）而被拒绝时，插件下发主体为该线索 IP 的 `other-end` hunt。过滤器是 `ip.dst == <cue>`，字段是 `ip.src`。不会对调 token。不会编造 LAN 对端。

拒绝文本点名该 hunt 和过滤器：`unbound: hunt LAN ip.src talking to <cue> (ip.dst == <cue>).` 之后仍把该线索或任何线索指定为 victim 的绑定保持拒绝，并重复 hunt 名称。把线索指定为 victim 永远不会成为当前绑定。两端都在 LAN 的会话拒绝不下发 `other-end`，也不编造 C2（[拒绝两端都在 LAN 的绑定](2026-08-21-refuse-both-lan-bind.md)）。

当 `autoHunt` 为 true 时，`other-end` 像其他已下发 hunt 一样通过 `pcap_filter` 自动运行，即使其主体是线索。[身份 hunt 自动运行](2026-08-21-auto-run-outstanding-identity-hunts.md) 仍对 `eth-src`、`name-service`、Kerberos 和 SAMR 跳过非 LAN 主体。

在存在带非线索 victim 的当前绑定之前，`case_report` 保持未绑定（`UNBOUND_REASON`）。当模型已经有 LAN 对端时，正确的 LAN victim／线索 c2 绑定无需该 hunt 即可被接受。受害端行捐出仍要求该当前绑定。

[拒绝将线索指定为 victim](2026-08-21-refuse-cue-as-victim.md) 仍拥有拒绝。[BindRelationship](../feature/2026-08-21-bind-relationship.md) 仍拥有结案前绑定。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端和 TEST-NET 对等体。

## 备选方案

**正确拒绝后停在 `UNBOUND_REASON`。** 否决：lumma-r9 拒绝两次后退出。拒绝必须点名 other-end hunt。

**把线索静默指定为 `c2`，或对调已颠倒的一对。** 否决：不会对调 token。[拒绝将线索指定为 victim](2026-08-21-refuse-cue-as-victim.md) 保持不变。

**在拒绝文本、提示词或测试中编造 LAN IP。** 否决：hunt 查找 LAN `ip.src`；黄金地址不是期望答案。

**第二次把线索指定为 victim 时接受对调。** 否决：把线索指定为 victim 永远不会成为当前绑定。

**只改方法论提示词或工具描述。** 否决：拒绝已经存在，模型仍退出。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN IP 和 TEST-NET 线索。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 与 `hunts.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）和 TEST-NET 对等体（`198.51.100.80`）。把 `victim` 指定给 TEST-NET 地址会被拒绝，点名为该地址的 `other-end`，并且不编造 LAN IP。`packages/analyst/investigation/tests/investigation.spec.ts` 通过 `tools.execute` 记录该 hunt，用同一 hunt 名称拒绝第二次把线索指定为 victim 的绑定，在挂载替身 `pcap_filter` 时自动运行 `ip.dst == 198.51.100.80`／`ip.src`，从该转储收割 `10.0.10.2`，然后接受 LAN victim／TEST-NET c2 绑定并让 `case_report` 结案。把线索指定为 victim 从不写入 `investigation/bind`。

## 后果

把线索指定为 victim 的拒绝会把模型指向与该线索通信的 LAN `ip.src`。账本随后可以在没有模型调用 `pcap_filter` 的情况下持有收割到的 LAN 对端。对调的绑定仍失败。结案仍要求带非线索 victim 的当前绑定。
