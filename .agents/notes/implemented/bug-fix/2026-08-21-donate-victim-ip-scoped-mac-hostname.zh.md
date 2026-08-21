# Agent Note: 当前绑定之后捐出受害端 IP 范围内的 MAC 和主机名

Status: implemented

[English](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) | 中文

## 问题

线上 lumma-r10（`34b5b26`）正确绑定了被引用的会话（LAN victim / 外部 c2）。`case_report` 被接受。结案栏 3/5：IP、用户和全名通过。MAC 和主机名只留在账本上。

[补全受害端行投影](2026-08-21-complete-victim-row-projection.md) 捐出某一种类中唯一未归属的身份。绑定之后用户和全名是唯一的，因此捐出。账本上还有其他 MAC 和主机名（DC／其他行），全账本唯一性因此两个黄金值都不捐出。

`entityIdForIdentity` 只通过 `c2TalkingLanVictim`（证据文本里唯一的来源 `eth.src` 模式，且全账本只有一个 MAC）或该唯一性路径归属 MAC。主机名没有受害端 IP 路径，只靠唯一性。账本上任何地方再有第二个 MAC 或主机名就会否决捐出，即使其中一个值是从限定在被绑定 victim IP 的 `eth-src`／`name-service` 收割来的。

## 决策

当前绑定之后，捐出证据落在被绑定 victim IP 上的 MAC 和主机名。

持久化为 `evidence_id` 的 hunt 主体，或限定在该 IP 的工具结果行（`eth.src` 且 `ip.src ==` victim，`name-service` 且 `ip.addr ==` victim），把该 mac／hostname 归属到 victim。从 `name-service` 转储记录主机名时，收割把 hunt 主体写入 `evidence_id`。MAC 戳的是该行上的通信 IP，不是 hunt 主体；后来的帧把该 MAC 从来自 victim 的方向送出时，hunt 主体 `evidence_id` 不能否决捐出（[通信 IP 戳 MAC](2026-08-21-stamp-mac-evidence-from-talking-ip.md)）。全账本唯一性不会挡住受害端 IP 范围内的身份。持久化的 who/where 携带该 mac 和 hostname。

证据落在另一 IP 上、或带有另一 `entity_id` 的 distractor 不进入。不会编造槽位。唯一未归属的用户和全名仍捐出。线索作为 victim 仍被拒绝，并仍下发 [other-end](2026-08-21-other-end-hunt-on-cue-victim.md)。[BindRelationship](../feature/2026-08-21-bind-relationship.md) 仍拥有结案前绑定。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体和空闲 LAN 行。

## 备选方案

**继续只靠全账本唯一性和 `c2TalkingLanVictim` 捐出。** 否决：账本上的 DC 或空闲 MAC／主机名会丢掉收割已经写下的、限定在受害端 IP 的值。

**捐出某一种类的每一个未归属 MAC 或主机名。** 否决：没有受害端 IP 证据的两个未归属 MAC 必须都不捐出。

**捐出证据落在另一 IP 上、或带有另一 `entity_id` 的 MAC 或主机名。** 否决：distractor 保持标签，不能填写 who/where。

**编造账本上没有的主机名或 MAC 槽。** 否决：不会编造槽位。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture（测试前置数据）是合成 LAN IP、TEST-NET 对等体和空闲 LAN 行。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET 对等体（`198.51.100.80`）和空闲行（`10.0.10.3`）。当前绑定之后，账本上有从限定在 `10.0.10.2` 的 eth-src／name-service 收割的未归属 mac+hostname，外加一个归属到 `10.0.10.3` 的 mac+hostname 时，会持久化受害端 mac+hostname 并省略空闲行。没有受害端 IP 证据的两个未归属 MAC 都不捐出。线索作为 victim 仍被拒绝。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一限定范围账本先跑 `bind_relationship` 再跑 `case_report`。

## 后果

当前绑定会在 MAC 和主机名的证据落在被绑定 victim IP 上时写出这些值，即使账本上还有其他 MAC 或主机名行。用户和全名的唯一性不变。同一种类的两个未限定 MAC 仍会让该槽留空。线索作为 victim 和对调结案仍以未绑定失败。
