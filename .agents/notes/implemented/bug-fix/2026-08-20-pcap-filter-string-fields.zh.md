# Agent Note: 将 pcap_filter 字符串字段强制转换为 tshark -e 名称

Status: implemented

[English](2026-08-20-pcap-filter-string-fields.md) | 中文

## 问题

现场 r5（`46fa813`，Bedrock 30B，Easy as 123）得 2/5。启动、cwd 和 XML 恢复正常；r4 的 XML 抖动未再现。`pcap_info` 与 `pcap_filter` 已运行。模型尝试了 `kerberos.CNameString`，但把 `fields` 发成字符串，因此 `defineTool` 在 `rejectInvalidTsharkFields` 之前抛出 `INVALID_ARGS`。重试去掉了 `-e`，只看到 AS-REQ；会话中从未出现 `brolf`。SAMR 仍只有头。身份仍只有 IP。`case_report` 的 `who` 幻觉出 `mattw`。主机名 `DESKTOP-TEYQ2NR` 未出现，因为这次运行没有转储 LLMNR/NBNS/BROWSER/SMB。这次字符串类型的 `fields` 调用阻断了 r3 上能结清用户的 hunt。

`pcap_filter` schema 只把 `fields` 标成数组。Qwen 常把单个字段名发成字符串。

## 决策

`pcap_filter` 接受字符串或字符串数组形式的 `fields`。字符串是单个字段，或逗号／空白分隔的列表，并在无效字段拒绝和 `tshark -e` 之前被强制转换为 `string[]`。字符串 `kerberos.CNameString` 会变成 `-e kerberos.CNameString` 并运行。`ldap.sAMAccountName`、`ldap.displayName`、`kerberos.username` 和 `samr.full_name` 仍被拒绝。数组保持为已结构化的列表；其元素不被拆分。

scout、自动运行 hunt、家族收割、主机名摘要收割以及新评测不在本次变更内。这些旋钮仍由[调查分析预设](../feature/2026-08-20-analyst-investigation-preset.md)拥有。

## 备选方案

**保持仅数组的 schema，并在提示词里教模型。** 否决：现场调用已经给出了可用字段名；schema 校验在拒绝列表或 tshark 运行之前就丢弃了它。

**把 `fields` 标成无约束 JSON。** 否决：数字或对象不是字段列表。可接受的输入是字符串或字符串数组。

**拆分含逗号的数组元素。** 否决：数组已经是结构化列表。现场失误是字符串。

**在同一次变更中自动运行 hunt、做家族收割或发明评测。** 否决：那些是另一组旋钮。r5 从未到达带标签的 CNameString 行。

## 测试

`packages/analyst/analyst-tools/tests/tools.spec.ts` 以 `fields: "kerberos.CNameString"` 执行 `pcap_filter`。该调用必须成功，标出列，并以 `-e kerberos.CNameString` 启动 `tshark`。同一路径在 `fields: "ldap.sAMAccountName"` 时必须因无效字段诊断失败，而不是 `INVALID_ARGS`。`fields.spec.ts` 固定逗号／空白拆分，以及强制转换后对四个无效名称的拒绝。

## 后果

Qwen 的字符串 `fields` 会到达 tshark，而不是在参数校验时失败。无效名称仍在启动前失败。模型可以继续发送数组。主机名收割、SAMR 家族收割和 hunt 下发保持不变。
