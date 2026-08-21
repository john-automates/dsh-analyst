# Agent Note: 将受害端行句柄字符串强制转换为 case_report who/where

Status: implemented

[English](2026-08-21-case-report-victim-handle-strings.md) | 中文

## 问题

线上 lumma-r6（`3880fd9`）两次绑定了被引用的会话，两次都正确（LAN victim / 外部 c2）。PR16 拒绝了两次 `report.md` 写入。随后三次 `case_report` 都因未绑定被拒绝。`who` / `where` 以自由文本字符串到达，而不是 `entity_id` 对象：先是 `gwyatt (Gabriel Wyatt)` / `10.1.21.58 (desktop-es9f3ml)`，然后是 `gwyatt` / `10.1.21.58`。没有写入 `investigation/report` 结案包。

[句柄投影](2026-08-21-case-report-victim-row-entity-id.md) 与 [JSON 对象强制转换](2026-08-21-case-report-stringified-who-where.md) 从未运行，因为 `caseReportDenyReason` 在 `coerceIdentitySlotArg` 之后仍执行 `if (typeof value === 'string') return UNBOUND_REASON`，而该函数只 JSON 解析以 `{` 开头的字符串。

## 决策

当前绑定之后，当 `who` / `where` 字符串里的每个身份 token 都是受害端行句柄（被绑定的 victim IP，或捐给该 victim、或证据落在该 victim 上的账本用户 / 全名 / 主机名 / MAC）时，`caseReportDenyReason` 把它强制转换成 `{ entity_id: victim.addr }`。随后由已有的受害端行投影写出结案包。JSON 对象字符串强制转换仍优先。没有当前绑定仍会拒绝。点名 c2、干扰项、另一个 IPv4 或无法匹配的身份 token 的字符串仍保持未绑定。不会对调 token。不会解析 `report.md`。不会编造槽位。字段标签、句子包裹、多词 `full_name` 匹配，以及未捐出但证据落在 victim 上的句柄见[带标签的句柄字符串](2026-08-21-case-report-labeled-victim-handle-strings.md)。剩余的仅域控／网关 MAC 会被[丢弃](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)。

scout、遗留报告禁令、收割归属和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体，以及该受害端行上的句柄。

## 备选方案

**只在提示词里教模型发送对象 who/where。** 否决：线上调用在正确绑定之后已经发送了受害端行句柄字符串；拒绝检查把它们当成自由文本丢掉。

**把 `report.md` 解析进 who/where。** 否决：那是另一只旋钮。结案文件写入仍被拒绝；本旋钮是 `case_report` 字符串。

**当一对对调时静默交换 C2 与 victim token。** 否决：那是已归档的改写。对调仍以未绑定失败。

**当前绑定之后把任意字符串强制转换成 victim。** 否决：点名 c2、干扰项、另一个 IPv4 或无法匹配的散文的字符串必须保持未绑定。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN IP 加上该行上的句柄。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 把合成 LAN 客户端（`10.0.10.2`）绑到 TEST-NET 对等体（`198.51.100.80`），并把 `lan-user` / `Lan User` / `lan-host` 放在该受害端行上。绑定之后，`who` / `where` 为受害端行句柄字符串（用户、`user (Full Name)`、victim IP、`IP (HOSTNAME)`）时允许结案，且 who/where 投影到受害端行。C2 IP 字符串、干扰项用户字符串和无法匹配的散文仍视为未绑定。没有当前绑定仍会拒绝。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一句柄字符串 `case_report` 先跑 `bind_relationship` 再跑 `case_report`，并记录 `entity_id` 为 victim 地址、行字段已捐出的 `investigation/report`。

## 后果

当前绑定加上受害端行句柄字符串会写出 5W1H 结案包。账户名不会存成 `entity_id`。未绑定和对调结案仍以未绑定原因失败。JSON 对象字符串 who/where 仍优先强制转换。
