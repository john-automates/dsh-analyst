# Agent Note: 当前绑定之后补全受害端行投影

Status: implemented

[English](2026-08-21-complete-victim-row-projection.md) | 中文

## 问题

线上 lumma-r8（`53a223d`）正确绑定了被引用的会话（LAN victim / 外部 c2）。没有把线索当作 victim。两次 `case_report` 因散文被拒绝；一次 `report.md` 写入被拒绝；第三次接受了 `who.entity_id` 为用户句柄、`where.entity_id` 为 victim IP。持久化的 `investigation/report` who/where 都只变成 `{ entity_id: victim.addr, ip: victim.addr }`。提交的用户句柄被改写成 IP 并丢掉。MAC、主机名、用户和全名在账本上，也在打印出的报告里，但不在已接受的 who/where 中。结案栏 1/5（只有 IP）。

`projectVictimSlot` 已经从已捐出的身份复制 mac／hostname／user，但 `entityIdForIdentity` 只归属显式 `entity_id`、`kind=ip`，或通过 `c2TalkingLanVictim` 归属的 MAC。收割记录的 user／hostname／mac／full_name 没有 `entity_id`，因此留在账本上却不捐出。`CaseIdentitySlot` 没有 `full_name` 字段，即使捐出也无法持久化该槽。

## 决策

当前绑定之后，补全受害端行投影。

`CaseIdentitySlot` 有可选的 `full_name`。`projectVictimSlot` 把它与 mac／hostname／user 一起复制。

未归属的账本身份（没有 `entity_id`，且 `evidence_id` 不指向非 victim）在它是该种类中唯一未归属到其他实体的身份时，捐给被绑定的 victim。`entity_id` 已经是 victim 的身份仍捐出。`entity_id` 是另一端点的 distractor 仍不捐出。不会编造槽位。同一种类有两个未归属值时，两者都不捐出。证据落在被绑定 victim IP 上的 MAC 或主机名在同一种类还有其他值时仍捐出（[受害端 IP 范围捐出](2026-08-21-donate-victim-ip-scoped-mac-hostname.md)）。

持久化的 `investigation/report` who/where 从该投影携带 ip／mac／hostname／user／full_name。句柄字符串强制转换仍映射到 `{ entity_id: victim.addr }`；行从账本填充，不从自由文本填充。

[BindRelationship](../feature/2026-08-21-bind-relationship.md) 仍拥有结案前绑定。[受害端行句柄](2026-08-21-case-report-victim-row-entity-id.md) 仍持久化 victim 地址。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端和 TEST-NET 对等体。

## 备选方案

**继续只在显式 `entity_id` 或来源 MAC 时捐出。** 否决：收割已经把该行写进账本；线上结案丢掉了除 IP 以外的每个槽。

**捐出某一种类的每一个未归属身份。** 否决：同一种类的两个未归属用户必须都不捐出。

**捐出 `entity_id` 是另一端点的 distractor。** 否决：distractor 保持标签，不能填写 who/where。

**从提交的句柄字符串填写 who/where。** 否决：句柄只做强制转换；行来自账本。不会编造槽位。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN IP 和 TEST-NET 对等体。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）和 TEST-NET 对等体（`198.51.100.80`）。当前绑定之后，账本上有未归属的 mac／hostname／user／full_name，外加一个 `entity_id` 为另一 LAN IP 的 distractor 用户时，会持久化受害端行（全部五个槽）并省略 distractor。同一种类的两个未归属用户都不捐出 user。线索作为 victim 仍被拒绝。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一未归属账本先跑 `bind_relationship` 再跑 `case_report`，并持久化带这五个槽的 `investigation/report`。

## 后果

当前绑定加上收割到的未归属身份会写出完整受害端行。句柄字符串或 `entity_id` 仍存储 victim 地址。同一种类的两个未归属值会让该槽留空。线索作为 victim 和对调结案仍以未绑定失败。
