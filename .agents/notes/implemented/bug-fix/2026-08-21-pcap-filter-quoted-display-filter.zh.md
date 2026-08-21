# Agent Note: 去掉 pcap_filter display_filter 的包裹引号

Status: implemented

[English](2026-08-21-pcap-filter-quoted-display-filter.md) | 中文

## 问题

现场 First to Last r2（`ee72365`，Bedrock 30B）得 2/5。PR8 的 hunt 通知写了 `ip.addr ==` 该主体，但 `c2TalkingLanIps` 从未被这次 pcap 武装：全部五次 `pcap_filter` 调用都被额外加引号并失败，因此[字符串字段强制转换](2026-08-20-pcap-filter-string-fields.md)没有触发。grep 从遗留的 r1 文件收割到一个 IP 后，hunt 仍对其他 IP 下发。`who` 和 MAC 来自遗留的 r1 `report.md` / `live.log`，而不是本次会话的 pcap。

`pcap_filter` 把 `display_filter` 原样传给 tshark `-Y`。Qwen 把整个过滤器包在引号里，像在写 shell 参数。tshark 于是收到 `"ip.addr == …"` 或 `'llmnr or nbns or browser'`，并拒绝该表达式。可用的过滤器从未运行。

## 决策

`pcap_filter` 在交给 tshark `-Y` 之前去掉 `display_filter` 的包裹引号。模型值 `"ip.addr == 1.2.3.4"` 或 `'llmnr or nbns or browser'` 会变成去掉外层引号的过滤器并运行。典型的额外加引号——转义包裹如 `\"…\"`、混合的 `'\"…\"'`，以及多一层匹配包裹——按同样方式剥去。并非整体被包裹的过滤器（包括内含引号字符串的）保持不变。

无效的 tshark 4.4.16 字段仍在启动前被拒绝。[字符串字段强制转换](2026-08-20-pcap-filter-string-fields.md)不变。

scout、遗留报告收割禁令、自动运行 hunt、家族收割以及新评测不在本次变更内。这些旋钮仍由[调查分析预设](../feature/2026-08-20-analyst-investigation-preset.md)拥有。

## 备选方案

**在提示词里教模型不要给 `display_filter` 加引号。** 否决：现场调用已经给出了可用过滤器；tshark 在行数据能武装 `c2TalkingLanIps` 之前就因包裹引号失败。

**通过 shell 启动 tshark，让引号变成 shell 语法。** 否决：辅助进程用无 shell 的 `execFile`。这些引号是 `-Y` 参数里的字符，不是一层 shell。

**在同一次变更中禁止遗留报告收割。** 否决：那是下一次失误（若仍需要）。本旋钮是带引号的 `display_filter` 在读取 pcap 之前就失败。

**自动运行 hunt、发明评测，或把黄金身份写进提示词或测试。** 否决：那些是另一组旋钮。测试使用合成过滤器，例如 `ip.addr == 1.2.3.4`。

## 测试

`packages/analyst/analyst-tools/tests/tools.spec.ts` 以 `display_filter: "\"ip.addr == 1.2.3.4\""` 执行 `pcap_filter`。该调用必须以 `-Y ip.addr == 1.2.3.4` 启动 `tshark`。同一路径在带引号的 `display_filter` 且 `fields: "ldap.sAMAccountName"` 时必须因无效字段诊断失败，而不是 `INVALID_ARGS`。`fields.spec.ts` 固定单引号、双引号、转义与混合包裹，并保持 `http.host == "example.com"` 和 `"smb" or nbns` 不变。

## 后果

Qwen 加了引号的 `display_filter` 会到达 tshark，而不是作为非法表达式失败。无效字段名仍在启动前失败。模型可以继续发送不加引号的过滤器。遗留报告收割、scout 和 hunt 下发保持不变。
