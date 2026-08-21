# Agent Note: 拒绝 write/edit 案件根目录结案文件

Status: implemented

[English](2026-08-21-deny-close-file-writes.md) | 中文

## 问题

线上 lumma-r5（`61894ac`）正确绑定了被引用的会话（LAN victim / 外部 c2）。账本已持有全部五个黄金槽位。模型从未调用 `case_report`。它用 `write()` 写了案件根目录的 `report.md`。[字符串化的 who/where](2026-08-21-case-report-stringified-who-where.md) 强制转换和[受害端行投影](2026-08-21-case-report-victim-row-entity-id.md)没有运行。被接受的 who/where 仍为空。结案栏为 0/5。

`isWritablePath` 仍把案件根目录的 `report.md` 列为允许写入的目标。证据策略只拒绝证据路径，因此在当前绑定之后对 `report.md` 的 `write` / `edit` 会成功，并跳过结案包。

## 决策

BindRelationship 之后，结案只能走 `case_report`。当路径是案件根目录结案文件（`report.md`、`report.txt`、`case_report.md`）时，`tools/pre-execute` 拒绝 `write`、`edit` 和 `str_replace_editor`。拒绝文本是 `close with case_report after BindRelationship.` 不会把 `report.md` 解析进 who/where。`notes/` 仍可写。未绑定的 `case_report` 仍返回 `unbound: assign victim vs c2 on the cited conversation.` 对调的 victim／c2 会被拒绝。不会对调 token。

scout、遗留报告收割禁令和新评测不在本次变更内。测试使用合成 LAN 客户端和 TEST-NET 对等体。

## 备选方案

**静默把 `report.md` 解析进 who/where。** 否决：那会掩盖被跳过的 `case_report`，并编造结案包从未记录的槽位。

**只改方法论提示词。** 否决：模型在当前绑定之后仍可以写 `report.md`。

**只在未绑定期间拒绝 write/edit `report.md`。** 否决：线上失误是在绑定之后写 `report.md`。结案文件从来不是结案路径。

**在同一次变更里禁止从遗留报告收割。** 否决：那是另一条遗留文件旋钮。本旋钮是对结案文件的 write/edit。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN IP 加上 TEST-NET 对等体。

## 测试

`packages/analyst/investigation/tests/policy.spec.ts` 以 `CLOSE_FILE_REASON` 拒绝对案件根目录 `report.md` 及同类结案文件的 `write` / `edit`，并仍允许 `notes/`。`packages/analyst/investigation/tests/investigation.spec.ts` 记录合成绑定（`10.0.10.2` victim / `198.51.100.80` c2），拒绝 `write(report.md)` 和 `edit(report.md)`，然后用 `case_report` 结案。未绑定和对调的 `case_report` 仍被拒绝。

## 后果

当前绑定加上 `write(report.md)` 会以结案文件原因失败。该绑定之后的 `case_report` 仍会写出 5W1H 结案包。未绑定和对调结案仍以未绑定原因失败。磁盘上遗留的 `report.md` 不是结案包。
