# Agent Note: 拒绝将线索／观测地址指定为 victim

Status: implemented

[English](2026-08-21-refuse-cue-as-victim.md) | 中文

## 问题

线上 lumma-r7（`ac6f879`）的第一次绑定正确拒绝：victim 是线索／观测地址，且 `because` 没有引用会话。第二次绑定接受了对调：victim 是线索／观测地址，c2 是 LAN 域控，`because` 引用了会话（`evidence_id`、两个端点、端口、talking／packet／flow／peer）。随后两次 `case_report` 把账本用户当作 `who`、把线索地址当作 `where`，两次都返回未绑定。该用户不是那条对调受害端行上的句柄，因此[受害端行句柄字符串强制转换](2026-08-21-case-report-victim-handle-strings.md)没有触发。线索作为 victim 本应保持拒绝。

`resolveEndpoint` 只在 `because` 未通过 `citesConversation` 时，才把线索／观测地址上的 `victim` 标为未绑定。引用会话就足以让检测器 IP 保持为 victim。

## 决策

线索或观测地址不能作为 victim。只要 `role === 'victim' && isCueObservationAddr(addr)`，就返回 `UNBOUND_REASON`。线索或观测地址仍默认 `c2`。不会对调 token。恰好一个 victim。对调的 `case_report` 会被拒绝。受害端行句柄字符串强制转换仍适用于未对调的当前绑定。

[BindRelationship](../feature/2026-08-21-bind-relationship.md) 仍拥有结案前绑定。scout、遗留报告禁令、收割归属和新评测不在本次变更内。测试使用合成 LAN 客户端和 TEST-NET 对等体。

## 备选方案

**保留引用会话的例外。** 否决：线上第二次绑定引用了会话，并对调了 victim／c2。

**当模型发送 `victim` 时，把线索静默指定为 `c2`。** 否决：不会对调 token。拒绝绑定。

**对调已颠倒的 victim／c2。** 否决：那是已归档的改写。对调仍以未绑定失败。

**只改方法论提示词或工具描述。** 否决：第二次绑定仍会被接受。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN IP 和 TEST-NET 线索。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）和 TEST-NET 对等体（`198.51.100.80`）。把 `victim` 指定给 TEST-NET 地址时，无论 `because` 是告警字符串，还是引用了会话、`evidence_id`、两个端点或 `dport`，都会被拒绝。LAN victim 加 TEST-NET `c2` 仍能绑定，且 `case_report` 仍能结案。`packages/analyst/investigation/tests/investigation.spec.ts` 通过 `tools.execute` 拒绝把线索指定为 victim 且 `because` 引用会话的绑定。

## 后果

把线索对调成 victim 的绑定保持未绑定。未对调的 LAN victim 绑定仍能结案，句柄字符串强制转换仍要求受害端行未对调。
