# Agent Note: 当前绑定之后补全省略的受害端行 mac 与 user

Status: implemented

[English](2026-08-21-complete-omitted-victim-mac-user.md) | 中文

## 问题

线上 fake-software r3（`mta-2025-01-22`）正确绑定了被引用的会话（LAN victim / 非 LAN C2）。[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) 未经测试：模型只提交了 `{ entity_id: victim }`。投影填了 ip、hostname 和 `full_name`。已接受的 who/where 没有 mac，也没有 user。

黄金 MAC 先被戳记并捐给域控。受害端 IP 帧来源于同一 MAC（`ip.src`／出站／ARP `is at`）。`entityIdForIdentity` 让显式域控 `entity_id`／粘滞的域控捐出获胜，因此 `projectVictimSlot` 省略了 mac。该 user 不是唯一未归属，因此也未捐出。`completeAcceptedSlot` 只从该投影行补全省略的键，因此只含 `entity_id` 的结案保持单薄。

仅域控／网关 MAC 保持不在。提交的受害端 MAC 仍必须持久化。

## 决策

当前绑定之后，即使模型只提交 `entity_id`，也把省略的 `mac` 和 `user` 从受害端 IP 证据持久化到已接受的 who/where。

先捐给域控的 MAC，只要受害端 IP 帧来源于它，或限定在受害端 IP 的 `eth.src` 转储证明它，仍填入省略的 mac 槽。粘滞的域控 `entity_id` 或 `evidence_id` 不得否决该省略持久化。证据落在被绑定 victim 上的 user（会话客户端戳记，或客户端为该 IP 的 Kerberos／SAMR 会话）即使唯一性会阻止捐出，也填入省略的 user。不编造 user。不持久化捐给非 victim、且证据不在 victim 上的 user。

不丢掉 ip／hostname／`full_name`。不编造该行或帧无法证明的 MAC。仅域控／网关 MAC 保持不在。

[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) 保持：提交的受害端 MAC 仍持久化；提交的仅域控 MAC 仍保持不在。[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 仍复制已捐出的投影键。捐出和 `entityIdForIdentity` 保持：显式域控 `entity_id` 仍赢得归属。漏洞在 `completeAcceptedSlot` 中模型省略 mac／user 时 `projected[key]` 为空的分支。

线索作为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC` 与 `DISTRACTOR_MAC`，以及 `lan-user` 与干扰用户。

## 备选方案

**继续只从已捐出的投影键补全省略的键。** 否决：只含 `entity_id` 的结案会在粘滞的域控捐出之后丢掉受害端 IP 来源的 MAC 和会话客户端 user。

**改 `entityIdForIdentity`／`identityDonatesToVictim`，让受害端 IP 帧压过显式域控 `entity_id`。** 否决：此旋钮是已接受 who/where 上的省略持久化。归属和角色标签保持不变。

**把账本上每一个省略的 MAC 或 user 复制到受害端行。** 否决：仅域控／网关 MAC 和捐给非 victim 的 user 必须保持不在。

**该行和帧都无法证明时编造 MAC 或 user。** 否决：不会编造槽位。

**补全省略的 mac／user 时丢掉 ip／hostname／`full_name`。** 否决：那些槽位已经持久化。

**补全省略的受害端 MAC 时取消保留提交的 mac。** 否决：提交的受害端 MAC 仍持久化；提交的仅域控 MAC 仍保持不在。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC`／`DISTRACTOR_MAC`，以及 `lan-user` 与干扰用户。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、`CLIENT_MAC`、`DISTRACTOR_MAC`、`lan-user` 和干扰用户。当前绑定之后，只提交 `{ entity_id: victim }` 的 who/where 在受害端 IP 帧来源于 `CLIENT_MAC` 时持久化该 MAC，即使账本先把它捐给域控。证据落在受害端会话客户端上的省略 user 即使唯一性会阻止也持久化。仅域控 `DISTRACTOR_MAC` 保持不在。捐给非 victim 的 user 不持久化。ip／hostname／`full_name` 保留。没有受害端 IP 证据时不编造省略的 mac。提交的受害端 MAC 仍持久化。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一只含 `entity_id` 的结案走 `bind_relationship` 再走 `case_report`。

## 后果

当前绑定加上只含 `entity_id` 的结案会在存在受害端 IP 证据时写出省略的 mac 和 user，即使粘滞的域控捐出让投影行为空。仅域控／网关 MAC 仍保持不在。捐给非 victim 的 user 仍保持不在。没有证据时仍不编造省略的槽位。提交的受害端 MAC 保留仍然有效。已捐出的 ip／hostname／`full_name` 保留。
