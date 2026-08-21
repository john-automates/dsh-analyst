# Agent Note: 当前绑定之后把已收割的人类 user 持久化到省略的 who

Status: implemented

[English](2026-08-21-persist-harvested-human-on-omitted-who.md) | 中文

## 问题

线上 fake-r25（`3fafd8f`）正确绑定了被引用的会话（LAN victim / 非 LAN C2）。身份遗留 3/4：IP／MAC／hostname HIT。黄金 user 已被收割。已接受的 where 有该 user。已接受的 who 省略了 `user`。who 省略 user 时，评分 who-haystack 会错过该 user。

[补全省略的受害端行 mac 与 user](2026-08-21-complete-omitted-victim-mac-user.md) 从受害端 IP 证据（会话客户端戳记）填入省略的 user。[保留提交的受害端行身份](2026-08-21-keep-submitted-victim-row-identities.md) 只在提交了该键的槽位上保留 user。[折入同级身份键](2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md) 仅在整个 who/where 参数被省略时折入同级 `user`。唯一性捐出仍把以 `$` 结尾的机器 SAM 算作 user，因此已收割的人类账户加上机器账户会让 `projectVictimSlot.user` 为空。此时已出现、但省略 `user` 键的 who 对象没有已捐出的值，也没有会话客户端戳记，`completeAcceptedSlot` 就不写 who.user，而 where 已经有该已收割的人类 user。

## 决策

当前绑定之后，当机器 SAM 也存在而导致唯一性捐出让投影行为空时，把已收割的人类 user 持久化到省略的 who/where。

`omittedUserEvidencedOnVictim` 仍先返回会话客户端 user。没有该戳记时，返回唯一已收割的人类 user（忽略并以 `$` 结尾的机器 SAM，且不持久化机器 SAM）。捐给非 victim 的 user 保持不在。两个普通人仍都不持久化。提交的机器 SAM 仍保持不在，并且不会回落到该收割。已经带有 user 的 where 不变。who/where 仍只属于受害端。不编造槽位。

[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 仍复制已捐出的投影键。[补全省略的受害端行 mac 与 user](2026-08-21-complete-omitted-victim-mac-user.md) 仍拥有会话客户端省略 user。唯一性捐出仍计算每一个未归属 user，包括机器 SAM。[保留提交](2026-08-21-keep-submitted-victim-row-identities.md) 与[同级折入](2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md) 保持。线索作为 victim 仍被拒绝。Fastly／akamaized／附加项持久化宽度／authenticatoor 不在本次变更内。

## 备选方案

**投影行为空时继续要求省略的 user 具备会话客户端戳记。** 否决：已出现但省略 `user` 的 who 对象会丢掉 where 已经持久化的已收割人类 user。

**改唯一性捐出，让人类 SAM 在机器账户也存在时获胜。** 否决：此旋钮是已接受结案包上的省略持久化。归属和捐出保持不变。提交的机器 SAM 必须仍保持不在，而不是输给已捐出的人类账户。

**不经收割检查就把已接受的 where.user 复制到省略的 who。** 否决：who/where 仍只属于受害端；捐给非 victim 的 user 不得进入 who。

**把以 `$` 结尾的机器 SAM 作为 user 持久化。** 否决：机器账户不是受害端 user。

**把线上案件用户名写进 harness 代码或测试、发明评测，或重调 Fastly／akamaized／附加项持久化。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、`lan-user` 和机器 SAM `lan-host$`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、`CLIENT_MAC`、`DISTRACTOR_MAC`、`lan-user`／`Lan User` 和机器 SAM `lan-host$`。当前绑定之后，账本上有已收割的 `lan-user` 加上 `lan-host$`、且没有会话客户端戳记时，`projectVictimSlot.user` 为空。`case_report` 的 who 省略 `user`、而 where 已有 `lan-user` 时，把 `lan-user` 持久化到 who 并保留在 where。who 上提交的机器 SAM 保持不在。两个普通人在省略的 who 上都不持久化。线索作为 victim 仍被拒绝。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一省略 who 的结案走 `bind_relationship` 再走 `case_report`。

## 后果

当前绑定加上唯一已收割的人类 user，即使机器 SAM 挡住了唯一性捐出、且 where 已经有该 user，也会把该 user 写到省略的 who。机器 SAM 仍保持不在。两个普通人仍都不持久化。会话客户端省略 user、提交保留和同级折入保持。已捐出的 ip／mac／hostname／`full_name` 保留。
