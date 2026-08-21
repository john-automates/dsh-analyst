# Agent Note: 把同级身份键折入省略的 case_report who/where

Status: implemented

[English](2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md) | 中文

## 问题

线上 fake-software r8（`mta-2025-01-22`，master `4b2caad`，在[定位／CIDR 剩余项](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md)之后）正确绑定了被引用的会话（LAN victim／非 LAN C2）。`case_report` 被接受。已发布的 IP／MAC／hostname 通过。`user` 失败。`full_name` 保持未发布。

[定位／CIDR 剩余项](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md) 没有触发：已接受的结案省略了 who/where，也没有 Client／IP／located／at／on／network 剩余词。该调用发送了同级顶层键 `ip`／`mac`／`hostname`／`user`／`full_name`，不是散文或 JSON who/where。[保留提交的受害端行身份](2026-08-21-keep-submitted-victim-row-identities.md) 已在投影行没有已捐出 user 时保留提交的 user，但 `projectCaseReport`／`requireCaseReport`／`case_report` execute 只把 `args.who` 和 `args.where` 传进 `completeAcceptedSlot`。同一调用上的同级 `SLOT_KEYS` 从未进入该提交槽位。

[补全省略的受害端行 mac 与 user](2026-08-21-complete-omitted-victim-mac-user.md) 没有补上 user：`omittedUserEvidencedOnVictim` 需要会话客户端戳记，而唯一性捐出因为账本上有一个人类 SAM 外加以 `$` 结尾的机器账户而保持为空。

## 决策

当前绑定之后，当 who 和／或 where 被省略时，`projectCaseReport` 把同一 `case_report` 参数上的同级顶层身份键（`ip`、`mac`、`hostname`、`user`、`full_name`）折入该提交槽位，让 `completeAcceptedSlot` 把它们看成提交键。`case_report` execute 把这些同级键与 who/where 一起传入。

即使账本上也有机器账户、唯一性捐出让投影行为空，仍保留提交的人类 user（不是以 `$` 结尾的机器 SAM）。模型已经点名该人类 SAM 时，不要求会话客户端戳记。机器 SAM 挡住唯一性捐出时，省略的 who/where 也持久化该唯一已收割的人类 user（[在省略的 who 上持久化已收割的人类 user](2026-08-21-persist-harvested-human-on-omitted-who.md)）。机器 SAM 不作为 who/where user 持久化。模型提供的 IP 不替换被绑定的 victim ip。已捐出的 ip／hostname／mac／`full_name` 保留。域控／网关网卡保持不在。

漏洞在 `packages/analyst/investigation/src/bind.ts` 中省略的 who/where 加上同级 `SLOT_KEYS`，以及 `case_report` execute 路径。收割戳记、绑定接受／拒绝、省略 mac 持久化、仅域控 MAC 剩余项丢弃、定位／CIDR 包裹和 C2-domain 持久化保持不变。将线索指定为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC` 对 `DISTRACTOR_MAC`、`lan-user`／`Lan User`，以及合成机器 SAM `lan-host$`。

## 备选方案

**继续只把 `args.who` 和 `args.where` 传进 `completeAcceptedSlot`。** 否决：当前绑定之后用同级键点名受害端身份的结案会丢掉提交的人类 user。

**改省略 user 持久化或唯一性捐出，让人类 SAM 在也有机器账户时胜出。** 否决：本旋钮是当前绑定之后的提交槽位折入。省略持久化仍要求受害端 IP 证据。唯一性捐出仍计入每一个未归属 user。

**把同级机器 SAM（`$`）作为 who/where user 持久化。** 否决：机器账户不是受害端 user。

**用模型提供的同级 ip 替换被绑定的 victim ip。** 否决：已捐出的 victim ip 保留。

**把已有的 who/where 对象或句柄字符串当成省略，让同级键覆盖它。** 否决：已有的对象或句柄字符串结案仍然有效。

**把同级键宣传为必填 schema 字段，或改收割戳记、绑定接受／拒绝、省略 mac 持久化、仅域控 MAC 剩余项丢弃、定位／CIDR 包裹或 C2-domain 持久化。** 否决：本旋钮是已接受结案包上省略 who/where 的折入。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC`／`DISTRACTOR_MAC`、`lan-user`／`Lan User`，以及 `lan-host$`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、`CLIENT_MAC`、`DISTRACTOR_MAC`、`lan-user`／`Lan User`，以及机器 SAM `lan-host$`。当前绑定之后，省略 who/where 并发送同级顶层 `ip`／`mac`／`hostname`／`user`／`full_name`（人类 `lan-user`）的 `case_report`，即使账本还有 `lan-host$` 和另一个未归属 user、且没有会话客户端戳记，也会在 who/where 上持久化 `lan-user`。同级机器 SAM user 不持久化。ip／mac／hostname／`full_name` 保留。`DISTRACTOR_MAC` 不出现。模型提供的同级 ip 不替换被绑定的 victim ip。已有的 who/where 对象或句柄字符串结案仍接受。将线索指定为 victim 仍被拒绝。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一组同级键结案先跑 `bind_relationship` 再跑 `case_report` execute。

## 后果

当前绑定加上省略 who/where、并用同级顶层键点名受害端身份的结案，会把那些键写到已接受的 who/where 上，包括账本上也有机器账户时提交的人类 user。机器 SAM 仍保持不在。域控／网关网卡仍保持不在。已捐出的 ip／hostname／mac／`full_name` 保留。将线索指定为 victim 仍被拒绝。
