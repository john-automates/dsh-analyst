# @deepseek-ai/dsh-investigation

[English](README.md) | 中文

案件范围内的调查账本。插件记录唯一的带标签身份，自动下发 Kerberos 然后 SAMR 的 hunt，拒绝写入证据以及案件目录外的操作，并持久化 5W1H 结案包。状态从会话日志折叠得出。

## 服务：`Investigation`（ctx 键：`investigation`）

`caseDir` 必填且必须是绝对路径。`evidenceReadOnly` 与 `autoHunt` 默认为 true，并且仍是 Config 字段。

- `identities(session)` / `hunts(session)` / `report(session)` 折叠日志。
- `recordIdentity` / `recordHunt` 仅在 kind+value（或 kind+subject）为新值时追加。
- `recordReport` 以整值替换 5W1H 结案包。
- `resolveInsideCase`、`isEvidence`、`isWritable` 和 `contains` 强制案件目录范围。

`tools/pre-execute` 拒绝写入证据和捕获文件、离开案件目录的 shell 命令，以及恶意软件运行器（`wine`、`qemu`、捕获的 `.exe`）。`tools/post-execute` 从成功的工具文本中收割 IP、MAC、主机名、用户和全名，包括 UTF-16LE SAMR 十六进制（`Becka Rolf`）。新的 IP 或主机名对该主体下发 `kerberos-cname` 与 `samr-userinfo`；新用户下发 `samr-userinfo`。

`investigation:policy` 章节陈述 DINQ、5W1H、证据优先工作，以及有效的 tshark 4.4.16 字段。`investigation:ledger` 是列出已记录身份与 hunt 的动态上下文。

## 配置

```yaml
- id: investigation
  name: '@deepseek-ai/dsh-investigation'
  config:
    caseDir: !!js process.env.DSH_CASE_DIR ?? process.cwd()
    evidenceReadOnly: true
    autoHunt: true
```

未知键在加载时失败。相对 `caseDir` 在加载时失败。headless 把同一条 `DSH_CASE_DIR` 链绑定为会话工作区，因此 glob、read、bash 和 `{{cwd}}` 看到的是案件目录；`caseDir` 仍拒绝写入案件之外的路径。

设计见[调查分析预设](../../../.agents/notes/implemented/feature/2026-08-20-analyst-investigation-preset.md)。

## 模型体验

### 调查策略系统提示

#### 模型看到什么

每个请求都在提示词顺序 40 处包含方法论章节。

##### 调查方法论

```markdown
You are a network-security investigation analyst, not a coding agent. Define the Investigation Question (DINQ) before collecting more evidence. State who, what, when, where, why, and how (5W1H) as claims you can support with packets or logs. Work evidence-first and question-driven: every tool call answers a named question. Label unverified ideas as hunches and verify them in this case. Evidence under evidence/ and capture files (*.pcap, *.pcapng, *.cap, *.log) is read-only. Do not execute malware, run captured binaries, or operate on paths outside the case directory. Use pcap_info, pcap_filter, and logs. Valid tshark 4.4.16 fields include kerberos.CNameString, samr.samr_UserInfo21.account_name, and samr.samr_UserInfo21.full_name. Do not use ldap.sAMAccountName, ldap.displayName, kerberos.username, or samr.full_name — those fields are invalid. After a hostname or IP appears, hunt Kerberos CNameString, then SAMR QueryUserInfo for the display name. SAMR full_name is UTF-16 (for example Becka Rolf), not an LDAP displayName. Close with case_report using the 5W1H fields once the Investigation Question is answered.
```

#### Token 影响

插件挂载期间，该章节在每个请求上是固定段落。

#### KV Cache 影响

该章节在挂载生命周期内保持稳定。

### 身份账本上下文

#### 模型看到什么

当会话日志持有身份、hunt 或报告时，`investigation:ledger` 将它们列为动态上下文快照。

#### Token 影响

空账本不增加 token；每个新身份或 hunt 增加一行列表。

#### KV Cache 影响

新的身份或 hunt 会改变可复用提示前缀之后的上下文。

### 收割与 hunt 通知

#### 模型看到什么

产生新身份的成功工具结果会追加一条插件来源的通知，点名该身份；当 `autoHunt` 为 true 时，还点名已下发的 hunt 以及有效 tshark 字段。Kerberos 通知会要求模型立刻跑 SAMR QueryUserInfo，而不等待用户名出现。

#### Token 影响

每次真正记录了新内容的收割调用对应一条通知。

#### KV Cache 影响

通知追加在可复用请求前缀之后。

### 被拒绝的工具调用

#### 模型看到什么

被拒绝的写入、越出案件目录或恶意软件运行器调用会返回错误结果，点名案件目录或只读证据规则。

#### Token 影响

该错误像其他失败调用一样留在对话历史中。

#### KV Cache 影响

被拒绝的调用按常规扩展对话。

## 已知限制与延后工作

- Shell 策略按 token 扫描命令；精心构造的一行命令仍可能以扫描器错过的方式点名案件外路径。对证据优先使用 `pcap_filter` 和 `logs`，而不是自由 shell。
- 收割基于文本。从未渲染为文本的结构化工具值不会被记录。
- 账本尚无 Web 投影卡片；UI 读取 `session/event` 或折叠日志。
