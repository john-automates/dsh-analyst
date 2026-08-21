# Agent Note: 将字符串化的 case_report who/where 强制转换为对象

Status: implemented

[English](2026-08-21-case-report-stringified-who-where.md) | 中文

## 问题

线上 lumma-r4（`59ccfdb`）正确绑定了被引用的会话（LAN victim / 外部 c2）。绑定之后，两次 `case_report` 把 `who` 和 `where` 发成了 Hermes XML 参数文本里的 JSON 对象字符串（`{"entity_id":…}`）。两次都返回未绑定。没有写入 `investigation/report` 结案包。账本已经持有受害端行身份。

[受害端行 entity_id](2026-08-21-case-report-victim-row-entity-id.md) 接受对象槽位上的用户句柄。`caseReportDenyReason` 仍把任何字符串 `who` / `where` 当成自由文本。XML 恢复把每个 `<parameter>` 值存成字符串，因此对象参数会以 JSON 文本到达。`tools/pre-execute` 在 `defineTool` 校验参数之前就运行该拒绝。

## 决策

`caseReportDenyReason` 在自由文本检查之前，把作为 JSON 对象字符串的 `who` / `where` 强制转换成该对象。当前绑定随后可以从受害端行用户句柄投影 `who.entity_id`。`case_report` schema 接受对象或字符串，让这些参数到达拒绝检查而不是 `INVALID_ARGS`。不是 JSON 对象的字符串随后按受害端行句柄文本检查（[句柄字符串](2026-08-21-case-report-victim-handle-strings.md)、[带标签的句柄字符串](2026-08-21-case-report-labeled-victim-handle-strings.md)、[仅域控／网关 MAC 剩余项](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)）。无法匹配的自由文本仍保持未绑定。没有当前绑定仍会拒绝。对调的 victim／c2 会被拒绝。不会对调 token。

scout、遗留报告禁令、收割归属和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体，以及该受害端行上的用户。

## 备选方案

**在 llm-pi-ai 的 XML 恢复里解析 JSON 对象参数。** 否决：那会扩大对每个工具的恢复范围，并且原生 JSON 字符串 `who` / `where` 仍会在绑定检查处失败。要求的结案测试走 `tools.execute`，不走 XML 恢复。

**只在 analyst-tools 的 `case_report` execute 里强制转换。** 否决：`tools/pre-execute` 先对原始参数调用 `caseReportDenyReason`，同一字符串仍会返回未绑定。

**只在提示词里教模型发送对象 who/where。** 否决：线上调用已经在 JSON 文本里给出了 `entity_id`；拒绝检查把它当成自由文本丢掉。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN IP 加上该行上的用户。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 把合成 LAN 客户端（`10.0.10.2`）绑到 TEST-NET 对等体，并把 `lan-user` 放在该受害端行上。`who` / `where` 为 `JSON.stringify({ entity_id })` 时，未绑定会被拒绝，`entity_id` 为 c2 地址会被拒绝，绑定后允许。不是受害端行句柄的非 JSON 字符串仍视为未绑定。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一 JSON 字符串 `case_report` 先跑 `bind_relationship` 再跑 `case_report`，并记录 `entity_id` 为 victim 地址、用户已捐出的 `investigation/report`。

## 后果

当前绑定加上 XML 字符串化或 JSON 字符串 who/where，在 `entity_id` 为 victim 地址或受害端行句柄时会写出 5W1H 结案包。无法匹配的自由文本 who/where 仍以未绑定失败。未绑定和对调结案仍以未绑定原因失败。
