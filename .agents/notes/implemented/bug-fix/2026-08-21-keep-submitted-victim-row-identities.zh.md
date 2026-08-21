# Agent Note: 在已接受的 who/where 上保留提交的受害端行身份

Status: implemented

[English](2026-08-21-keep-submitted-victim-row-identities.md) | 中文

## 问题

线上 fake-software r1（`mta-2025-01-22`）正确绑定了被引用的会话（LAN victim / 非 LAN C2）。IP、MAC 和 hostname 已持久化。`full_name` 因捐出而持久化。模型在 who 上提交了 `user`。`completeAcceptedSlot` 因为投影受害端行没有已捐出的 user 而丢掉了它。

[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 先复制已捐出的投影键，再忽略该行未捐出的模型提供键。这正确地去掉从未作为受害端 IP 上 `eth.src` 出现、也不在限定于该 IP 的转储里的域控或网关 MAC。它也会丢掉提交的 user——并以同样方式丢掉 hostname 或 `full_name`——当重映射到受害端实体时擦掉已提交的受害端行身份。

## 决策

把 who/where 投影或重映射到被绑定受害端实体时，若模型提供了 user、hostname 或 `full_name`，且投影行没有已捐出的值，则保留该提交值。在已接受的 who/where 上持久化该 user。不编造模型从未提交的 user。

该行未捐出的模型提供 IP 保持不在。提交的 mac 保留见[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md)。捐给其他（非 victim）实体的提交 user、hostname 或 `full_name` 不持久化。行上已有的已捐出 ip／mac／hostname／`full_name` 保留。

漏洞在 `completeAcceptedSlot` 中 `projected[key]` 为空的分支。

[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 仍从该行补全省略的键。[用户／全名会话客户端戳记](2026-08-21-stamp-user-fullname-from-conversation-client.md) 仍拥有捐出。线索作为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2 和空闲或域控 LAN 行。

## 备选方案

**继续忽略该行未捐出的每一个模型提供键。** 否决：重映射到受害端实体会擦掉模型已经提交的 user。

**复制每一个模型提供的槽位键，包括 `mac`。** 否决：从未作为受害端 IP 上 `eth.src` 出现的域控或网关 MAC 必须保持不在。

**模型省略该键且该行未捐出时编造 user。** 否决：模型从未提交的槽位不会被编造。

**持久化捐给非 victim IP 的提交 user、hostname 或 `full_name`。** 否决：那些身份不进入受害端行。

**保留提交的 user 时丢掉已捐出的 ip／mac／hostname／`full_name`。** 否决：那些槽位已经持久化。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2 和空闲或域控 LAN 行。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）和空闲或域控行（`10.0.10.3`）。当前绑定之后，提交 `user` 的 who/where（该行没有已捐出的 user）会持久化该 user，并保留 ip／mac／hostname／`full_name`。提交的域控或网关 MAC 保持不在。捐给非 victim IP 的提交 user 或 hostname 不持久化。省略的 user 不会被编造。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一提交 user 的结案走 `bind_relationship` 再走 `case_report`。

## 后果

当前绑定加上提交的受害端行 user 会写出该 user，即使投影行没有捐出它。域控 MAC 仍保持不在。捐给其他实体的 user 不会持久化。省略的 user 仍不会被编造。已捐出的槽位保留。
