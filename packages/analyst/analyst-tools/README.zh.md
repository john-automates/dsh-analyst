# @deepseek-ai/dsh-analyst-tools

[English](README.md) | 中文

`analyst` 预设的 SOC/NSM 工具：`pcap_info`、`pcap_filter`、`logs` 和 `case_report`。`bind_relationship` 由 `ctx.investigation` 注册。它们使用案件目录和 BindRelationship 结案检查。

## 工具

`pcap_info` 对案件内的捕获文件运行 `capinfos`（若 capinfos 缺失则运行 `tshark -r -q`）。`pcap_filter` 运行带可选显示过滤器与 `-e` 字段的 `tshark`；`display_filter` 上的包裹引号会在 `-Y` 之前被去掉。字符串形式的 `fields` 是单个字段名或逗号／空白分隔的列表，会在无效字段检查之前被强制转换为 `-e` 名称。无效的 tshark 4.4.16 字段（`ldap.sAMAccountName`、`ldap.displayName`、`kerberos.username`、`samr.full_name`）在启动进程前被拒绝。推荐字段：`kerberos.CNameString`、`samr.samr_UserInfo21.account_name`、`samr.samr_UserInfo21.full_name`。字段行带标签，以便身份收割读取。`logs` 读取案件内的文本文件，可按行切片。`case_report` 在 `bind_relationship` 之后追加 5W1H 结案包。`who` 和 `where` 从被绑定受害端实体行投影；已绑定及额外的 C2 IPv4 作为可选的 `c2_ips` 持久化，省略证据主机名为知名 CDN 或更新名的 IP；收割到的、证据落在任何剩余 C2 IP 上的 C2 TLS SNI 或 DNS 名在不是 CDN／更新时作为可选的 `c2_domain` 持久化，不是 who/where 的 hostname。带 `entity_id` 的 JSON 对象字符串，或当前绑定之后剩余身份 token 全是受害端行句柄的字符串（忽略标签、定位剩余词、句子包裹、包裹的 ASCII 引号、通信 IP 帧只从非 victim 来源的剩余 MAC，以及包含被绑定 victim IP 的剩余 CIDR；多词 full_name 为一句柄；捐出或受害端 IP 证据算数），会在自由文本检查之前被强制转换。点名 c2、干扰项用户或主机名、另一个 IPv4、不包含 victim 的 CIDR 或无法匹配剩余词的字符串仍保持未绑定。只含仅域控／网关 MAC、或没有剩余受害端行句柄的字符串仍保持未绑定。对调的 victim／c2 结案会被拒绝。对案件根目录 `report.md` 的 `write` / `edit` 会被拒绝；结案是 BindRelationship 之后的 `case_report`。不会编造主机名、用户或全名。

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

模型看到生成的 [`pcap_info` / `pcap_filter` / `logs` / `case_report` / `bind_relationship` schema](../../../docs/tool-catalog.md#deepseek-aidsh-analyst-tools)。`pcap_filter` 的描述点名有效的 tshark 4.4.16 字段，并拒绝无效字段。`bind_relationship` 由 investigation 注册，并在该服务挂载后出现在同一目录中。

#### Token 影响

工具可见时，每个请求都带五份稳定 schema。

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

`case_report` 返回投影后的受害端槽位以及 what/when/why/how、可选的 `c2_ips`，以及可选的已收割 `c2_domain`，并在会话上记录 `investigation/report`。非 agent 调用者会被拒绝。在没有当前绑定之前结案会被拒绝；对调的 `entity_id` 和无法匹配的自由文本 who/where 会被拒绝。带 `entity_id` 的 JSON 对象字符串，或当前绑定之后剩余身份 token 全是受害端行句柄的字符串（忽略标签、定位剩余词、句子包裹、包裹的 ASCII 引号、通信 IP 帧只从非 victim 来源的剩余 MAC，以及包含被绑定 victim IP 的剩余 CIDR；多词 full_name 为一句柄；捐出或受害端 IP 证据算数），会在自由文本检查之前被强制转换。who/where 的 `entity_id` 若是受害端行上的用户、主机名、MAC 或全名，会投影到被绑定的 victim 地址。持久化的 who/where 从该投影携带 ip／mac／hostname／user／full_name，包括唯一未归属的账本身份，以及证据落在被绑定 victim IP 上的 MAC 或主机名（同行通信 IP，或限定在该 IP 的仅字段 `eth.src` 转储）。拒绝／强制转换之后，模型省略的键（包括 `mac`）从该投影受害端行补全。粘滞的域控捐出或唯一性让该行为空时，省略的 mac 持久化唯一不是仅域控／网关的账本 MAC。省略的 user 仍从受害端 IP 证据持久化。当该行没有已捐出的值、且该身份不捐给其他实体时，保留模型提交的 user、hostname 或 full_name。当前绑定之后，省略的 who/where 会把同一 case_report 参数上的同级顶层身份键（ip、mac、hostname、user、full_name）折入该提交槽位。提交的人类 user 无需会话客户端戳记即可保留。以 `$` 结尾的机器 SAM 不作为 user 持久化。除非通信 IP 帧只从非 victim 来源该 MAC，否则保留提交的 mac。模型提供的 IP 不会替换被绑定的 victim ip。对案件根目录 `report.md` 的 `write` / `edit` 返回 `close with case_report after BindRelationship.` 设计见[结案前的 BindRelationship](../../../.agents/notes/implemented/feature/2026-08-21-bind-relationship.md)、[case_report 受害端行 entity_id](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-row-entity-id.md)、[补全受害端行投影](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-victim-row-projection.md)、[受害端 IP 范围捐出](../../../.agents/notes/implemented/bug-fix/2026-08-21-donate-victim-ip-scoped-mac-hostname.md)、[改戳限定在受害端 IP 的 eth.src](../../../.agents/notes/implemented/bug-fix/2026-08-21-restamp-victim-ip-scoped-eth-src.md)、[持久化省略的受害端行键](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-projected-victim-slot.md)、[保留提交的受害端行身份](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-row-identities.md)、[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-mac-unless-dc-only.md)、[补全省略的受害端行 mac 与 user](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-omitted-victim-mac-user.md)、[仅域控 MAC 须为排他的非 victim 通信 IP](../../../.agents/notes/implemented/bug-fix/2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md)、[字符串化的 who/where](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-stringified-who-where.md)、[受害端行句柄字符串](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-handle-strings.md)、[带标签的受害端行句柄字符串](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-labeled-victim-handle-strings.md)、[仅域控／网关 MAC 剩余项](../../../.agents/notes/implemented/bug-fix/2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)、[定位／CIDR 剩余项](../../../.agents/notes/implemented/bug-fix/2026-08-21-drop-locator-cidr-from-handle-string-coerce.md)、[折入同级身份键](../../../.agents/notes/implemented/bug-fix/2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md)、[拒绝写入结案文件](../../../.agents/notes/implemented/bug-fix/2026-08-21-deny-close-file-writes.md)，[成功绑定后的 C2-domain hunt](../../../.agents/notes/implemented/bug-fix/2026-08-21-c2-domain-hunt-after-live-bind.md)，以及[成功绑定后的 extra-WAN C2 hunt](../../../.agents/notes/implemented/bug-fix/2026-08-21-extra-wan-c2-hunt-after-live-bind.md)。

#### Token 影响

渲染后的 5W1H 结案包留在对话历史中。

#### KV Cache 影响

该调用按常规扩展对话。

## 已知限制与延后工作

- 除非 `tsharkBin` / `capinfosBin` 指向其他可执行文件，`pcap_info` 和 `pcap_filter` 需要 PATH 上的 Wireshark CLI 工具。
- 显示过滤器语法属于 tshark；本包只拒绝已点名的无效字段列表。
- `logs` 按 UTF-8 文本读取文件，不解析二进制格式。
