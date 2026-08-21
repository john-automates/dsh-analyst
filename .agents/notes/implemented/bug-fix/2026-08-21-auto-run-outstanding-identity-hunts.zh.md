# Agent Note: 自动运行已下发的身份 hunt

Status: implemented

[English](2026-08-21-auto-run-outstanding-identity-hunts.md) | 中文

## 问题

现场 First to Last r4（`a11b092`，Bedrock 30B）得 0/5。[来源 MAC 收割](2026-08-21-harvest-eth-src-from-c2-talking-ip.md)已经触发：收割到 LAN IP 后，插件下发了带 `(eth.src)` 且 `ip.src ==` 该 LAN 客户端的 `eth-src`。模型从未运行该 hunt。它按任务线索对外部 C2 IP 查询了 `eth.src`，写入了对端 MAC，然后 `who` 变成了空闲 LAN 工作站。从未调用 `case_report`（用了 `write`）。黄金客户端 MAC 从未进入账本。

下发与通知文本已经正确。执行仍在等待 `pcap_filter`。

## 决策

当 `autoHunt` 为 true 时，已下发且尚未执行的身份 hunt——`eth-src`、`name-service`、`kerberos-cname` 与 `samr-userinfo`——会用 `huntFilterSpec` / `huntNotice` 中限定范围的 `display_filter` 和字段跑 `pcap_filter`。插件不等模型调用 `pcap_filter`。每次转储仍按原样收割进身份账本。

已知正在与 C2 通信的 LAN IP 时，只自动运行该主体的 hunt。主体为非 LAN / C2 IP 的 hunt 从不自动运行，但 [`other-end`](2026-08-21-other-end-hunt-on-cue-victim.md) 除外，它猎取与该线索通信的 LAN `ip.src`。主机名和用户 hunt 只在尚未知道 C2 通信 LAN IP 时自动运行。

捕获路径优先用触发 pcap 工具的 `path`（该参数带捕获后缀时），否则取 `evidence/` 或案件根目录下第一个 `*.pcap` / `*.pcapng` / `*.cap`。没有 `pcap_filter` 或没有捕获文件就跳过执行。失败的 hunt 不会让触发工具失败。同一会话上已尝试过的 hunt 不会重试。

[去引号](2026-08-21-pcap-filter-quoted-display-filter.md)、[字符串字段强制转换](2026-08-20-pcap-filter-string-fields.md)、`eth-src` 使用 `ip.src`（不是 `ip.addr`），以及[双客户端融合](2026-08-20-scope-identity-hunts-to-c2-talking-client.md)保持不变。scout、家族收割、遗留报告禁令和新评测不在本次变更内。

## 备选方案

**继续等模型去跑已下发的 hunt。** 否决：r4 已经下发了正确的 `eth-src`，模型却对 C2 IP 跑了另一种过滤器。

**只改方法论提示词。** 否决：通知已经点名 `(eth.src)` 和 `ip.src ==` 该 LAN 客户端。

**对每一个已下发主体自动运行 hunt，包括 C2 IP。** 否决：那会持久化对端网卡。非 LAN 身份 hunt 主体不会自动运行。`other-end` 是单独的例外（[other-end](2026-08-21-other-end-hunt-on-cue-victim.md)）。

**把黄金身份写进提示词或测试。** 否决：测试使用合成的 LAN 客户端和 MAC。案件名称、IP 和 MAC 不是期望答案。

**为 hunt 执行新增 `SessionEventMap` 成员。** 否决：从转储收割的身份已经记入日志。新事件会搅动 SDK snapshot。

**发明评测或改动 scout。** 否决：本旋钮是下发之后的执行。

## 测试

`packages/analyst/investigation/tests/investigation.spec.ts` 注册替身 `pcap_filter`。在 echo 收割到 LAN 客户端之后，已下发的 `eth-src` 会以 `(eth.src)` 和 `ip.src ==` 该客户端执行，即使模型从未调用 `pcap_filter`。合成 MAC 会被收割。C2 IP 主体不会执行。`hunts.spec.ts` 钉住 `huntFilterSpec` 与 `shouldAutoRunHunt`。

## 后果

记录到的 LAN 客户端 `eth-src` 转储会在没有模型调用 `pcap_filter` 的情况下进入账本。模型仍可调用 `pcap_filter`；已执行的 hunt 不会在同一会话上重跑。主机名和用户 hunt 仍取决于这些转储到达收割。
