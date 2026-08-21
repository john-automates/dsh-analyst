# @deepseek-ai/dsh-analyst-tools

[English](README.md) | 中文

`analyst` 预设的 SOC/NSM 工具：`pcap_info`、`pcap_filter`、`logs` 和 `case_report`。它们通过 `ctx.investigation` 使用案件目录和 5W1H 结案包。

## 工具

`pcap_info` 对案件内的捕获文件运行 `capinfos`（若 capinfos 缺失则运行 `tshark -r -q`）。`pcap_filter` 运行带可选显示过滤器与 `-e` 字段的 `tshark`；`display_filter` 上的包裹引号会在 `-Y` 之前被去掉。字符串形式的 `fields` 是单个字段名或逗号／空白分隔的列表，会在无效字段检查之前被强制转换为 `-e` 名称。无效的 tshark 4.4.16 字段（`ldap.sAMAccountName`、`ldap.displayName`、`kerberos.username`、`samr.full_name`）在启动进程前被拒绝。推荐字段：`kerberos.CNameString`、`samr.samr_UserInfo21.account_name`、`samr.samr_UserInfo21.full_name`。字段行带标签，以便身份收割读取。`logs` 读取案件内的文本文件，可按行切片。`case_report` 向调用会话追加 5W1H 结案包。当账本或 `c2TalkingLanIps` 已知正在与 C2 通信的 LAN IP 时，点名非 LAN IP 或对端 MAC 的 `who` / `where` 会被改写为该 LAN IP 及其来源 `eth.src` MAC。不会插入主机名、用户或全名。

辅助进程用 `execFile` 启动（不经过 shell），`cwd` 为案件目录，并遵守工具的 `signal`。

## 配置

```yaml
- id: analyst-tools
  name: '@deepseek-ai/dsh-analyst-tools'
  config:
    maxOutputChars: 32000
    commandTimeoutMs: 60000
    tsharkBin: tshark
    capinfosBin: capinfos
```

四个字段都是 Config。未知键在加载时失败。

这是函数／命名空间插件：导出 `name` / `inject` / `apply`，没有 default。

设计见[调查分析预设](../../../.agents/notes/implemented/feature/2026-08-20-analyst-investigation-preset.md)。

## 模型体验

### 工具 schema

#### 模型看到什么

模型看到生成的 [`pcap_info` / `pcap_filter` / `logs` / `case_report` schema](../../../docs/tool-catalog.md#deepseek-aidsh-analyst-tools)。`pcap_filter` 的描述点名有效的 tshark 4.4.16 字段，并拒绝无效字段。

#### Token 影响

工具可见时，每个请求都带四份稳定 schema。

#### KV Cache 影响

目录在挂载生命周期内保持稳定。

### pcap 与日志结果

#### 模型看到什么

成功调用返回截断后的文本。带 `fields` 的 `pcap_filter` 将每列标为 `field: value`，以便收割记录身份。带引号的 `display_filter`（例如 `"ip.addr == 1.2.3.4"`）会变成 `-Y ip.addr == 1.2.3.4`。字符串 `kerberos.CNameString` 会变成 `-e kerberos.CNameString`。无效字段在 tshark 启动前失败。

#### Token 影响

每个结果留在历史中，并按 `maxOutputChars` 截断。

#### KV Cache 影响

结果追加在可复用请求前缀之后。

### 案件报告

#### 模型看到什么

`case_report` 返回六个 5W1H 字段，并在会话上记录 `investigation/report`。非 agent 调用者会被拒绝。当已知正在与 C2 通信的 LAN 身份时，点名非 LAN IP 或对端 MAC 的 `who` / `where` 会被改写到该 LAN 客户端。

#### Token 影响

渲染后的 5W1H 结案包留在对话历史中。

#### KV Cache 影响

该调用按常规扩展对话。

## 已知限制与延后工作

- 除非 `tsharkBin` / `capinfosBin` 指向其他可执行文件，`pcap_info` 和 `pcap_filter` 需要 PATH 上的 Wireshark CLI 工具。
- 显示过滤器语法属于 tshark；本包只拒绝已点名的无效字段列表。
- `logs` 按 UTF-8 文本读取文件，不解析二进制格式。
