# @deepseek-ai/dsh-investigation

[English](README.md) | 中文

案件范围内的调查账本。插件记录唯一的带标签身份，在新 IP 后自动下发 MAC、名称服务、Kerberos，然后 SAMR 的 hunt，在 bind_relationship 把线索指定为 victim 时自动下发 `other-end`，在成功绑定且 C2 为非 LAN 时自动下发 `c2-domain`，并通过 `pcap_filter` 自动运行这些已下发且尚未执行的 hunt，拒绝写入证据以及案件目录外的操作，要求在 `case_report` 之前完成 BindRelationship，拒绝 write/edit 案件根目录的 `report.md` 及同类结案文件，并持久化 who/where 从被绑定受害端投影的 5W1H 结案包。收割到的 C2 TLS SNI 或 DNS 名作为 `c2_domain` 持久化到该结案包。状态从会话日志折叠得出。

## 服务：`Investigation`（ctx 键：`investigation`）

`caseDir` 必填且必须是绝对路径。`evidenceReadOnly` 与 `autoHunt` 默认为 true，并且仍是 Config 字段。

- `identities(session)` / `hunts(session)` / `report(session)` / `bind(session)` 折叠日志。
- `recordIdentity` / `recordHunt` 仅在 kind+value（或 kind+subject）为新值时追加，但 `recordIdentity` 可以把后来的 `evidence_id` 补到第一次收割缺少该字段的行上，或在后来的 id 是被绑定 victim 或 C2 通信 LAN IP 时覆盖 MAC 的域控／对等体戳记。
- `recordBind` 以整值替换当前会话绑定。`recordReport` 以整值替换 5W1H 结案包。当前绑定的 C2 为非 LAN 时，会对该 C2 IPv4 下发 `c2-domain`，并在 `autoHunt` 为 true 时自动跑该 IP 上的 TLS SNI／DNS。收割到的、`evidence_id` 为该 C2 的带点 DNS 名作为 `c2_domain` 持久化到已接受的结案包；它不填 who/where 的 hostname，也不捐给受害端行。在当前绑定恰好有一个 victim 之前，`case_report` 会被拒绝；`who` 和 `where` 从该受害端实体行投影。who/where 的 `entity_id` 若是该行上的用户、主机名、MAC 或全名，只是句柄；持久化结案包使用被绑定的 victim 地址。当前绑定之后，未归属的账本身份（没有 `entity_id`，且 `evidence_id` 不指向非 victim）在它是该种类中唯一未归属到其他实体的身份时捐给被绑定的 victim；同一种类的两个未归属身份都不捐出。工具结果行上来自被绑定 victim IP 的 MAC（`ip.src`、出站 `ip → peer` 或 ARP `is at`），或从限定在该 victim IP 的仅字段 `eth.src` 转储改戳而来的 MAC，即使 hunt 主体 `evidence_id` 点名另一 IP、第一次收割没有 `evidence_id`、账本上还有其他 MAC 值也捐出。证据落在被绑定 victim IP 上的主机名（hunt 主体 `evidence_id`，或限定在该 IP 的名称服务行）即使还有其他主机名值也捐出。Kerberos／SAMR 会话的客户端是被绑定 victim（LAN／非域控端）的用户或全名，即使 hunt 主体 `evidence_id` 点名另一 IP、账本上还有其他域账户也捐出。持久化的 who/where 从该投影携带 ip／mac／hostname／user／full_name。拒绝／强制转换之后，模型省略的键（包括 `mac`）从该投影受害端行补全；粘滞的域控捐出或唯一性让该行为空时，省略的 mac 持久化唯一不是仅域控／网关的账本 MAC；省略的 user 仍从受害端 IP 证据持久化；当该行没有已捐出的值、且该身份不捐给其他实体时，保留模型提交的 user、hostname 或 full_name；除非通信 IP 帧只从非 victim 来源该 MAC，否则保留提交的 mac；模型提供的 IP 不会替换被绑定的 victim ip。带 `entity_id` 的 JSON 对象字符串，或当前绑定之后身份 token 全是受害端行句柄的字符串，会在自由文本检查之前被强制转换。身份 token 忽略字段标签、句子包裹和包裹的 ASCII 引号，并把多词 full_name 当作一句柄。MAC、用户、主机名或全名在捐给 victim，或证据落在该 victim 上（受害端 IP 帧／会话客户端戳记）时是句柄。点名 c2、干扰项、另一个 IPv4 或无法匹配的身份 token 的字符串仍保持未绑定。对调的 victim／c2 结案会被拒绝。线索或观测地址不能作为 victim。被引用的会话必须包含线索／观测地址；两端都在 LAN 的会话保持未绑定。角色 `c2` 不能是 LAN 地址。不会对调 token。两端都在 LAN 的拒绝不下发 `other-end`。端点对象的 JSON 数组字符串，以及作为 1-65535 整数的数字字符串 `dport`，会在这些绑定检查之前被强制转换。不是 JSON 数组的字符串、缺失的 `dport`、或超出 1-65535 的 `dport` 仍被拒绝。不会编造姓名。对案件根目录 `report.md`（及同类结案文件）的 `write` / `edit` 会被拒绝；不会把 `report.md` 解析进 who/where。`c2TalkingLanVictim` 只归属唯一的来源 `eth.src` MAC，不改写槽位。
- `resolveInsideCase`、`isEvidence`、`isWritable` 和 `contains` 强制案件目录范围。

`tools/pre-execute` 拒绝写入证据和捕获文件、write/edit 案件根目录结案文件、离开案件目录的 shell 命令，以及恶意软件运行器（`wine`、`qemu`、捕获的 `.exe`）。`tools/post-execute` 从成功的工具文本中收割 IP、MAC、主机名、用户和全名，包括 UTF-16LE SAMR 十六进制（`Becka Rolf`）以及 NBNS、BROWSER、SMB、LLMNR、TLS SNI 和 DNS 的 tshark 摘要中的主机名。能区分出的工作组和域 token（Domain/Workgroup Announcement、Local Master Announcement，或 NBNS `<1b>`–`<1e>`）不会记为主机名。新的 IP 对该主体下发 `eth-src`、`name-service`、`kerberos-cname` 与 `samr-userinfo`；新主机名下发 `kerberos-cname` 与 `samr-userinfo`；新用户下发 `samr-userinfo`。当一个 LAN IP 与非 LAN 单播对等体出现在同一行时，这些身份 hunt 只对该 C2 通信 IP 下发；`eth-src` 通知使用 `ip.src ==` 该主体，且 MAC 收割只记录来自该 IP 的 `eth.src`，而不是对端或空闲工作站的网卡，并把该通信 IP 写入 `evidence_id`，即使该转储的 hunt 主体是另一个 IPv4。没有通信 IP 的仅字段 `eth.src` 转储把 hunt 主体 `scopeIp`（`ip.src`／`ip.addr ==` 该 IP）写入戳记；后来限定在受害端 IP 的转储会给第一次没有 `evidence_id` 或带域控／对等体戳记的收割改戳。用户和全名收割把会话客户端 IPv4 写入 `evidence_id`，而不是 SAMR／CNameString hunt 主体域控。没有 IP 的仅字段 SAMR／CName 转储，从先前的工具文本把对该域控讲话的 LAN／非域控对等体（`ip.src` 或 `LAN → DC`）写入戳记。协议字段名和截断转储不是用户或全名身份。其他以 IP 为主体的通知使用 `ip.addr ==` 该主体。当 `autoHunt` 为 true 时，已下发且尚未执行的 hunt 会用同一套限定范围的 `display_filter` 和字段跑 `pcap_filter`；插件不等模型调用 `pcap_filter`。优先正在与 C2 通信的 LAN 主体；非 LAN / C2 IP 主体不会自动运行，但绑定把线索指定为 victim 时下发的 `other-end`（`ip.dst ==` 该线索，字段 `ip.src`），以及成功绑定后对该 C2 IPv4 下发的 `c2-domain`（`tls.handshake.extensions_server_name`／`dns.qry.name`／`dns.resp.name` 且 `ip.addr ==` 该 C2）除外。`name-service` 是 `llmnr or nbns or browser`。SMB 不是 hunt 种类。

`investigation:policy` 章节陈述 DINQ、Who/Where 之前的 BindRelationship、5W1H、证据优先工作，以及有效的 tshark 4.4.16 字段。`investigation:ledger` 是列出当前角色卡片、已记录身份与 hunt 的动态上下文。设计见[结案前的 BindRelationship](../../../.agents/notes/implemented/feature/2026-08-21-bind-relationship.md)、[拒绝将线索指定为 victim](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-cue-as-victim.md)、[拒绝将线索指定为 victim 时下发 other-end hunt](../../../.agents/notes/implemented/bug-fix/2026-08-21-other-end-hunt-on-cue-victim.md)、[case_report 受害端行 entity_id](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-row-entity-id.md)、[补全受害端行投影](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-victim-row-projection.md)、[受害端 IP 范围捐出](../../../.agents/notes/implemented/bug-fix/2026-08-21-donate-victim-ip-scoped-mac-hostname.md)、[MAC 通信 IP 戳记](../../../.agents/notes/implemented/bug-fix/2026-08-21-stamp-mac-evidence-from-talking-ip.md)、[改戳限定在受害端 IP 的 eth.src](../../../.agents/notes/implemented/bug-fix/2026-08-21-restamp-victim-ip-scoped-eth-src.md)、[覆盖域控 MAC 戳记](../../../.agents/notes/implemented/bug-fix/2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md)、[用户／全名会话客户端戳记](../../../.agents/notes/implemented/bug-fix/2026-08-21-stamp-user-fullname-from-conversation-client.md)、[仅字段 SAMR／CName 客户端戳记](../../../.agents/notes/implemented/bug-fix/2026-08-21-reject-protocol-field-stamp-field-only-samr.md)、[字符串化的 who/where](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-stringified-who-where.md)、[字符串化的 bind endpoints 与 dport](../../../.agents/notes/implemented/bug-fix/2026-08-21-bind-relationship-stringified-args.md)、[拒绝两端都在 LAN 的绑定](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-both-lan-bind.md)、[持久化省略的受害端行键](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-projected-victim-slot.md)、[保留提交的受害端行身份](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-row-identities.md)、[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-mac-unless-dc-only.md)、[补全省略的受害端行 mac 与 user](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-omitted-victim-mac-user.md)、[仅域控 MAC 须为排他的非 victim 通信 IP](../../../.agents/notes/implemented/bug-fix/2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md)、[受害端行句柄字符串](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-handle-strings.md)、[带标签的受害端行句柄字符串](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-labeled-victim-handle-strings.md)、[拒绝写入结案文件](../../../.agents/notes/implemented/bug-fix/2026-08-21-deny-close-file-writes.md)，以及[成功绑定后的 C2-domain hunt](../../../.agents/notes/implemented/bug-fix/2026-08-21-c2-domain-hunt-after-live-bind.md)。

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
You are a network-security investigation analyst, not a coding agent. Define the Investigation Question (DINQ) before collecting more evidence. Before Who/Where, bind the conversation. The detector’s IP is a hypothesis about the other end until the bind says otherwise. Use bind_relationship to assign victim vs c2 on the cited conversation. Exactly one victim. The cited conversation must include a cue/observation address. Role c2 cannot be a LAN address. Cue and observation addresses default to c2 and cannot be victim. State what, when, why, and how as claims you can support with packets or logs. who and where are projections of the bound victim. Work evidence-first and question-driven: every tool call answers a named question. Label unverified ideas as hunches and verify them in this case. Evidence under evidence/ and capture files (*.pcap, *.pcapng, *.cap, *.log) is read-only. Do not execute malware, run captured binaries, or operate on paths outside the case directory. Use pcap_info, pcap_filter, logs, and bind_relationship. Valid tshark 4.4.16 fields include kerberos.CNameString, samr.samr_UserInfo21.account_name, and samr.samr_UserInfo21.full_name. Do not use ldap.sAMAccountName, ldap.displayName, kerberos.username, or samr.full_name — those fields are invalid. After a hostname or IP appears, hunt Kerberos CNameString, then SAMR QueryUserInfo for the display name. SAMR full_name is UTF-16 (for example Becka Rolf), not an LDAP displayName. Close with case_report only after bind_relationship has assigned the victim.
```

#### Token 影响

插件挂载期间，该章节在每个请求上是固定段落。

#### KV Cache 影响

该章节在挂载生命周期内保持稳定。

### 身份账本上下文

#### 模型看到什么

当会话日志持有绑定、身份、hunt 或报告时，`investigation:ledger` 将角色卡片和这些行列为动态上下文快照。当前绑定上的身份会标上端点角色。

#### Token 影响

空账本不增加 token；每个新身份或 hunt 增加一行列表。

#### KV Cache 影响

新的身份或 hunt 会改变可复用提示前缀之后的上下文。

### 收割与 hunt 通知

#### 模型看到什么

产生新身份的成功工具结果会追加一条插件来源的通知，点名该身份；当 `autoHunt` 为 true 时，还点名已下发的 hunt 以及有效 tshark 4.4.16 字段。IP 通知会点名 `eth.src`，以及会产生 DESKTOP-* / NBNS Registration / BROWSER Host Announcement 行的 `llmnr or nbns or browser` 过滤器。`eth-src` 通知包含 `ip.src ==` 该主体；其他以 IP 为主体的通知包含 `ip.addr ==` 该主体。通知点名已经跑过的过滤器；自动运行之后不再让模型去跑 `pcap_filter`。见到正在与 C2 通信的 LAN IP 之后，空闲 LAN 工作站不会收到 eth-src、Kerberos 或 SAMR hunt，且 MAC 收割不记录它们的网卡，也不记录双向转储中的对端网卡。已下发且尚未执行的 hunt 随后按这些过滤器执行；转储中的身份在同一次工具结果中进入账本。Kerberos 通知会要求模型立刻跑 SAMR QueryUserInfo，而不等待用户名出现。

#### Token 影响

每次真正记录了新内容的收割调用对应一条通知。

#### KV Cache 影响

通知追加在可复用请求前缀之后。

### 被拒绝的工具调用

#### 模型看到什么

被拒绝的写入、越出案件目录或恶意软件运行器调用会返回错误结果，点名案件目录或只读证据规则。write/edit 案件根目录 `report.md`（或同类结案文件）返回 `close with case_report after BindRelationship.` 未绑定、对调或自由文本的 `case_report`（或任何设置 `who` / `where` 的工具）返回 `unbound: assign victim vs c2 on the cited conversation.` 在 `bind_relationship` 上把 victim 指定给线索／观测地址返回 `unbound: hunt LAN ip.src talking to <cue> (ip.dst == <cue>).` 两端都在 LAN 的会话返回 `unbound: cite the LAN host talking to the cue/observation address, not a LAN DC/AD service.` 把 `c2` 指定给 LAN 地址返回 `unbound: role c2 cannot be a LAN address.`

#### Token 影响

该错误像其他失败调用一样留在对话历史中。

#### KV Cache 影响

被拒绝的调用按常规扩展对话。

## 已知限制与延后工作

- Shell 策略按 token 扫描命令；精心构造的一行命令仍可能以扫描器错过的方式点名案件外路径。对证据优先使用 `pcap_filter` 和 `logs`，而不是自由 shell。
- 收割基于文本。从未渲染为文本的结构化工具值不会被记录。来自 tshark 摘要的主机名限于 NBNS、BROWSER、SMB 和 LLMNR 的主机形式；已区分的工作组和域 token 会被省略。见到 C2 通信 IP 之后，只记录来自该 IP 的 MAC；没有 IPv4 的纯 `eth.src` 字段转储回退到严格多数，对端网卡仍可能占多数。
- 账本尚无 Web 投影卡片；UI 读取 `session/event` 或折叠日志。
