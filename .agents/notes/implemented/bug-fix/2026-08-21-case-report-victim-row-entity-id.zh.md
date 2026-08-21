# Agent Note: 从受害端行投影 case_report 的 who/where

Status: implemented

[English](2026-08-21-case-report-victim-row-entity-id.md) | 中文

## 问题

线上 lumma-r3（`aa1c361`）正确绑定了被引用的会话（LAN victim / 外部 c2，`because` 引用了会话）。第一次 `case_report` 因未绑定被拒绝，这是要求的行为。当前绑定出现后，第二次 `case_report` 仍因未绑定被拒绝：`who.entity_id` 是受害端行上的用户账户，而 `where.entity_id` 是 victim 地址。没有写入 `investigation/report` 结案包。没有对调 token。

`caseReportDenyReason` 只把 `who` / `where` 的 `entity_id` 与被绑定的 victim 地址比较。该行上的用户、主机名、MAC 或全名被当成外来实体 id。[BindRelationship](../feature/2026-08-21-bind-relationship.md) 已在当前绑定之后从受害端行投影 who/where；拒绝检查挡住了这次投影。

## 决策

在恰好有一个 victim 的当前绑定之后，`who.entity_id` 与 `where.entity_id` 可以是被绑定的 victim 地址，或受害端行句柄（用户、主机名、MAC 或全名）。这些句柄不是实体 id。`projectCaseReport` 仍把 `entity_id` 持久化为 victim 地址，并填入已捐出的行字段。非 victim 会话端点或另一个 IPv4 仍视为未绑定。自由文本 who/where 仍视为未绑定。没有当前绑定仍会拒绝。对调的 victim／c2 会被拒绝。不会对调 token。

scout、遗留报告禁令、收割归属和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体，以及该受害端行上的用户。

## 备选方案

**继续只接受 `entity_id ===` victim 地址。** 否决：线上结案在正确绑定之后把账户名放进 `who.entity_id`，从未写出报告。

**在对调时静默交换 C2 与 victim token。** 否决：那是已归档的改写。对调仍以未绑定失败。

**只在提示词里教模型把 victim 地址放进 `who.entity_id`。** 否决：第一次未绑定拒绝已经要求绑定；第二次拒绝是句柄检查。

**在同一次变更里把收割到的用户归属到 victim。** 否决：姓名仍只在受害端有显式 `entity_id` 或来源 MAC 时捐出。本旋钮是结案拒绝。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN IP 加上该行上的用户。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 把合成 LAN 客户端（`10.0.10.2`）绑到 TEST-NET 对等体，并把 `lan-user` 放在该受害端行上。`who.entity_id` 为该用户名的 `case_report` 在未绑定时被拒绝，在 `who.entity_id` 为 c2 地址时被拒绝，绑定后以 `who` / `where` 的 `entity_id` 为 victim 地址结案。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一 fixture 先跑 `bind_relationship` 再跑 `case_report`，并记录 `entity_id` 为 victim 地址、用户已捐出的 `investigation/report`。

## 后果

当前绑定加上受害端行用户句柄会写出 5W1H 结案包。账户名不会存成 `entity_id`。未绑定和对调结案仍以未绑定原因失败。主机名、用户和全名仍只通过捐出进入槽位，不通过改写。
