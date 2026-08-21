# Agent Note: 除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC

Status: implemented

[English](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) | 中文

## 问题

线上 fake-software r2（`mta-2025-01-22`）正确绑定了被引用的会话（LAN victim / 非 LAN C2）。[保留提交的受害端行身份](2026-08-21-keep-submitted-victim-row-identities.md) 已持久化提交的 user。模型还在 `case_report` 上提交了受害端 MAC。已接受的 who/where 丢掉了 `mac`。

身份账本已把该 MAC 捐给域控（粘滞的域控 `evidence_id`），因此投影受害端行没有已捐出的 mac。`completeAcceptedSlot` 随后跳过每一个模型提供的 `ip`／`mac`。模型之后可能提供的域控 MAC 保持不在。

域控范围保持不在，指只出现在域控／网关帧上的 MAC，而不是先在域控 hunt 主体下收割（或先捐给域控）、模型随后提交到受害端实体上的 MAC。粘滞的域控捐出不得覆盖已提交的受害端 MAC。

## 决策

把 who/where 投影或重映射到被绑定受害端实体时，若模型提供了 `mac`、投影行没有已捐出的值、且该 MAC 不是仅域控／网关，则保留该提交值。在已接受的 who/where 上持久化该 mac。不编造模型从未提交的 MAC。

仅域控／网关指该 MAC 从未作为被绑定 victim IP 上的 `eth.src` 出现，也不出现在限定于该 IP 的 `eth.src` 转储里。由通信 IP ／ `ipsEvidencingMac` ／ `evidencedOnVictimIp` ／受害端 IP 范围转储辅助函数判定。当受害端 IP 帧也来源于该 MAC，或模型在受害端结案上提交了它且这些辅助函数表明它不是仅域控时，粘滞的域控 `evidence_id` 不是仅域控。

模型提供的 IP 不会替换被绑定的 victim ip。提交的 user／hostname／`full_name` 仍按[保留提交的受害端行身份](2026-08-21-keep-submitted-victim-row-identities.md) 持久化。行上已有的已捐出 ip／hostname／user／`full_name` 保留。

漏洞在 `completeAcceptedSlot` 中 `projected[key]` 为空的分支——`ip`／`mac` 的 continue。IP 保持不变：不要把模型提供的非 victim IP 复制到被绑定的 victim ip 上。

[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 仍从该行补全省略的键。[补全省略的受害端行 mac 与 user](2026-08-21-complete-omitted-victim-mac-user.md) 仍在粘滞的域控捐出让该行为空时，从受害端 IP 证据持久化省略的 mac。[覆盖域控／对等体第一次戳记](2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md) 仍拥有改戳。线索作为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行，以及合成 `CLIENT_MAC` 与域控／网关 `DISTRACTOR_MAC`。

## 备选方案

**继续跳过每一个模型提供的 `mac`。** 否决：重映射到受害端实体会在粘滞的域控捐出之后擦掉已提交的受害端 MAC。

**复制每一个模型提供的 MAC。** 否决：从未作为受害端 IP 上 `eth.src` 出现、也不在限定于该 IP 的转储里的域控或网关 MAC 必须保持不在。

**即使受害端 IP 帧来源于该 MAC，仍把粘滞的域控 `evidence_id` 当作仅域控。** 否决：域控范围保持不在由帧范围决定，而不是第一次 hunt 主体或第一次捐出。

**模型省略该键且该行和帧都无法证明时编造 MAC。** 否决：不会编造槽位。从受害端 IP 证据补全省略的 mac 见[补全省略的受害端行 mac 与 user](2026-08-21-complete-omitted-victim-mac-user.md)。

**把模型提供的非 victim IP 复制到被绑定的 victim ip 上。** 否决：IP 保持使用被绑定的 victim 地址。

**保留提交的 mac 时丢掉提交的 user／hostname／`full_name` 或已捐出的 ip／hostname／user／`full_name`。** 否决：那些槽位已经持久化。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行，以及合成 `CLIENT_MAC`／`DISTRACTOR_MAC`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、`CLIENT_MAC` 和 `DISTRACTOR_MAC`。当前绑定之后，提交 `CLIENT_MAC` 的 who/where（账本先把它捐给域控；受害端 IP 帧也来源于它）会持久化 `CLIENT_MAC`。提交的仅域控 `DISTRACTOR_MAC` 保持不在。提交的 user／hostname／`full_name` 仍持久化。省略的 mac 不会被编造。模型提供的其他 IP 不会替换被绑定的 victim ip。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一提交 mac 的结案走 `bind_relationship` 再走 `case_report`。

## 后果

当前绑定加上提交的受害端 MAC 会写出该 mac，即使粘滞的域控捐出让投影行为空。仅域控／网关 MAC 仍保持不在。没有受害端 IP 证据时，省略的 mac 仍不会被编造。被绑定的 victim ip 保持不变。提交的 user／hostname／`full_name` 和已捐出的槽位保留。
