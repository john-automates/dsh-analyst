# Agent Note: 将字符串化的 bind_relationship endpoints 与 dport 强制转换

Status: implemented

[English](2026-08-21-bind-relationship-stringified-args.md) | 中文

## 问题

线上 lumma-r14（`f22b0b3`）指定了预定角色（LAN victim / 外部 c2），但 `bind_relationship` 从未接受。两次调用都在 `resolveBind` 之前返回 `INVALID_ARGS`。绑定 1 把 `dport` 发成数字字符串，把 `endpoints` 发成 JSON 数组字符串。绑定 2 省略了 `dport`，并再次把 `endpoints` 发成字符串。没有写入 `investigation/bind` 事件。随后两次 `case_report`（`who` 为账本用户，`where` 为 LAN 地址）因未绑定被拒绝。

[字符串字段强制转换](2026-08-20-pcap-filter-string-fields.md) 和 [字符串化的 who/where](2026-08-21-case-report-stringified-who-where.md) 已经为 `pcap_filter.fields` 和 `case_report` 的 who/where 恢复 Hermes XML 参数文本。`bind_relationship` schema 仍只把 `endpoints` 标成数组、只把 `dport` 标成整数，因此同样被字符串化的结构化参数会在校验时失败。

## 决策

`resolveBind` 在现有绑定检查之前，把作为端点对象 JSON 数组字符串的 `endpoints` 强制转换成该数组，并把作为整数的数字字符串 `dport` 强制转换成该整数。`bind_relationship` schema 接受数组或字符串形式的 `endpoints`，以及整数或字符串形式的 `dport`，让这些参数到达 `resolveBind` 而不是 `INVALID_ARGS`。不是 JSON 数组的字符串仍被拒绝。缺失的 `dport` 不会被编造。`dport` 为 `0` 和 `65536` 仍被拒绝。将线索指定为 victim 仍会点名 [other-end hunt](2026-08-21-other-end-hunt-on-cue-victim.md)。不会接受对调角色。恰好一个 victim。

收割、捐出和 `case_report` 强制转换保持不变。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端和 TEST-NET 对等体。

## 备选方案

**在 llm-pi-ai 的 XML 恢复里解析 JSON 数组参数。** 否决：那会扩大对每个工具的恢复范围，并且原生 JSON 字符串 `endpoints` 仍会在绑定 schema 处失败。要求的绑定测试走 `resolveBind` 和 `tools.execute`，不走 XML 恢复。

**只在 CLI 或一次性解析器里强制转换。** 否决：漏洞在 `bind_relationship` 工具边界。[字符串字段强制转换](2026-08-20-pcap-filter-string-fields.md) 和 [字符串化的 who/where](2026-08-21-case-report-stringified-who-where.md) 已经放在各自的工具入口。

**只在提示词里教模型发送数组和整数。** 否决：线上调用已经给出了预定的 LAN victim 与线索 c2；schema 校验把它们丢掉了。

**在缺失 `dport` 时编造默认端口。** 否决：缺失的端口仍被拒绝。

**强制转换后静默接受对调角色或把线索当作 victim。** 否决：现有 `resolveBind` 规则不变。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN IP 加上 TEST-NET 线索。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 把合成 LAN 客户端（`10.0.10.2`）绑到 TEST-NET 对等体（`198.51.100.80`）。`endpoints` 为 `JSON.stringify([...])` 且 `dport` 为 `"443"` 时，与原生数组加上整数 `dport` 解析为同一绑定。该强制转换之后把线索指定为 victim 仍会点名 other-end hunt。不是 JSON 数组的 `endpoints` 字符串仍被拒绝。缺失的 `dport` 以及 `dport` `"0"` / `"65536"` 仍被拒绝。`packages/analyst/investigation/tests/investigation.spec.ts` 用同一字符串化调用走 `tools.execute`，并记录 `investigation/bind`。

## 后果

JSON 字符串 `endpoints` 列表加上数字字符串 `dport` 会到达 `resolveBind`，并在角色有效时记录 `investigation/bind`。不是 JSON 数组的字符串、缺失端口、超出范围的端口，以及把线索指定为 victim，仍会失败。收割、捐出和 `case_report` 强制转换不变。
