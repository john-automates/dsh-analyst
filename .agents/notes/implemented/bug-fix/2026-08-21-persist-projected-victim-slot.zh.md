# Agent Note: case_report 省略槽位键时持久化投影受害端行

Status: implemented

[English](2026-08-21-persist-projected-victim-slot.md) | 中文

## 问题

线上 lumma-r16（`e2da3b4`）正确绑定了被引用的会话（LAN victim / 外部 c2）。身份 4/5。C2 方向和家族附加项通过。`whitepepper.su` 失败。MAC 失败：黄金 MAC 只在账本上。已接受的 who/where 有 ip／hostname／user／full_name，没有 `mac` 键。模型打印了域控 MAC；该值从未持久化。

[补全受害端行投影](2026-08-21-complete-victim-row-projection.md) 和 [受害端 IP 范围捐出](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) 已经把已捐出的 MAC 复制到 `projectVictimSlot`。结案路径仍持久化模型的 who/where 对象。模型省略 `mac` 时，即使被绑定受害端行已有来自受害端 IP 的 MAC，已接受的结案包也没有 mac。

## 决策

当前绑定之后，持久化投影受害端行，而不是模型的部分键。

模型提交的 who/where 仍先走现有的拒绝／强制转换路径。当前绑定之后，省略的 who/where 还会把同一 `case_report` 参数上的同级顶层身份键（`ip`、`mac`、`hostname`、`user`、`full_name`）折入该提交槽位（[折入同级身份键](2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md)）。已接受的 who/where 是该投影行的 `completeAcceptedSlot`：`entity_id`、`ip`、已捐出的 mac／hostname／user／full_name，该行未捐出、且不捐给其他实体时模型提交的 user／hostname／full_name（[保留提交的受害端行身份](2026-08-21-keep-submitted-victim-row-identities.md)），以及不是仅域控／网关时模型提交的 mac（[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md)）。提交的人类 user 无需会话客户端戳记即可保留。以 `$` 结尾的机器 SAM 不作为 user 持久化。模型省略的键从该行补全。粘滞的域控捐出或唯一性让该行为空时，省略的 mac 和 user 也从受害端 IP 证据持久化（[补全省略的受害端行 mac 与 user](2026-08-21-complete-omitted-victim-mac-user.md)）。机器 SAM 挡住唯一性捐出时，唯一已收割的人类 user 也持久化到省略的 who/where（[在省略的 who 上持久化已收割的人类 user](2026-08-21-persist-harvested-human-on-omitted-who.md)）。MAC 在证据落在被绑定 victim IP 上时捐出（[通信 IP 戳记](2026-08-21-stamp-mac-evidence-from-talking-ip.md)），或从限定在受害端 IP 的仅字段 `eth.src` 转储改戳后捐出（[受害端 IP 范围改戳](2026-08-21-restamp-victim-ip-scoped-eth-src.md)，包括[覆盖域控／对等体第一次戳记](2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md)）。从未作为受害端 IP 上 `eth.src` 出现、也不在限定于该 IP 的转储里的域控或网关 MAC 保持不在。补全 mac 时，其他已捐出的槽位保留。不会编造槽位。

[拒绝两端都在 LAN 的绑定](2026-08-21-refuse-both-lan-bind.md) 和 [绑定强制转换](2026-08-21-bind-relationship-stringified-args.md) 保持不变。[拒绝将线索指定为 victim](2026-08-21-refuse-cue-as-victim.md) 仍被拒绝。没有新槽位。

[BindRelationship](../feature/2026-08-21-bind-relationship.md) 仍拥有结案前绑定。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体和 LAN 域控。

## 备选方案

**拒绝之后继续持久化模型的 who/where 对象。** 否决：省略的 `mac` 丢掉了 `projectVictimSlot` 已有的、来自受害端 IP 的 MAC。

**只补全 mac，补全该行时丢掉 ip／hostname／user／full_name。** 否决：这些 r15 槽位在捐出时保留。

**捐出从未作为受害端 IP 上 eth.src 出现的域控或网关 MAC。** 否决：那些网卡不进入受害端行。

**编造账本上没有或不是受害端来源的 MAC。** 否决：不会编造槽位。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET 对等体和 LAN 域控。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET 对等体（`198.51.100.80`）和 LAN 域控（`10.0.10.3`）。当前绑定之后，账本上有受害端来源的 `CLIENT_MAC` 外加一个域控 MAC，然后 `case_report` 的 who/where 没有 `mac` 键时，会在 who 和 where 上持久化 `CLIENT_MAC`，并保留 ip／hostname／user／full_name。域控 MAC 保持不在。没有受害端来源 MAC 的账本让 `who.mac` 缺席。线索作为 victim 仍被拒绝。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一省略 mac 的结案走 `bind_relationship` 再走 `case_report`。

## 后果

当前绑定加上来自受害端 IP 的 MAC 会写出该 mac，即使模型省略该键。不是从受害端 IP 来源的域控 MAC 不会持久化。其他已捐出的槽位保留。线索作为 victim、两端都在 LAN，以及对调结案仍以未绑定失败。
