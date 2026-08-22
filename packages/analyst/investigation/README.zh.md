# @deepseek-ai/dsh-investigation

[English](README.md) | 中文

案件范围内的调查账本。插件在会话开始时盖上 Mission 戳，目的是受害端身份 + C2 调查，记录唯一的带标签身份，在新 IP 后下发 MAC、名称服务、Kerberos，然后 SAMR 的 hunt，在 bind_relationship 把线索指定为 victim 时自动下发 `other-end`，在成功绑定且有唯一 LAN victim 与已绑定、不是知名 CDN 或更新目的地址的非 LAN C2、并且 Plan 已点名 C2 假设与 CDN／DC／更新替代假设时自动下发 `extra-wan` 然后 `c2-domain`，仅在 Plan 就绪时（已点名且 valid 或显式 open 的线索、C2 假设、CDN／DC／更新替代、清单）通过 `pcap_filter` 自动运行已下发且尚未执行的 hunt，拒绝写入证据以及案件目录外的操作，要求在 `case_report` 之前完成 BindRelationship，拒绝 write/edit 案件根目录的 `report.md` 及同类结案文件，即使散文 `case_report` 保持未绑定也从 Report 钩子持久化遗留附加项，持久化 who/where 从被绑定受害端投影的 5W1H 结案包，并在 Mission 仍为 cue-pending、Plan 未就绪、或当前绑定之后仍有已收割的 LAN 工作站未绑定时，拒绝仅有文本的 `turn/end` complete。绑定角色 infra、AD SRV／DC 定位器主机名，以及 LAN 域控／文件服务器／网关角色主机名，不是剩余工作站。已绑定 C2 加上盖上受害端戳的 extra-wan 目的地址作为 `c2_ips` 持久化，省略证据主机名为知名 CDN 或更新名的 IP，以及落在已公布 Cloudflare 或 Fastly 任播段上的 IP。躲过那些省略的未点名 extra-wan 目的地址仍持久化。收割到的、证据落在已证明目的地址上的 C2 TLS SNI 或 DNS 名在不是 CDN／更新时作为 `c2_domain` 持久化。模型不能覆盖 Mission 目的。Mission 只给案件定范围。状态从会话日志折叠得出。

## 服务：`Investigation`（ctx 键：`investigation`）

`caseDir` 必填且必须是绝对路径。`evidenceReadOnly` 与 `autoHunt` 默认为 true，并且仍是 Config 字段。

- `identities(session)` / `hunts(session)` / `report(session)` / `bind(session)` / `mission(session)` / `extras(session)` 折叠日志。
- `recordIdentity` / `recordHunt` 仅在 kind+value（或 kind+subject）为新值时追加，但 `recordIdentity` 可以把后来的 `evidence_id` 补到第一次收割缺少该字段的行上，或在后来的 id 是被绑定 victim 或 C2 通信 LAN IP 时覆盖 MAC 的域控／对等体戳记。
- `recordBind` 以整值替换当前会话绑定，并在已有 5W1H 结案包时把该绑定已补全的受害端行持久化到结案包上。`recordReport` 写出 5W1H 结案包，重新合并遗留附加项，并按 `entity_id` 折叠已发布的受害端行。后来接受的结案或当前绑定若点名不同 victim，会把先前的行留在 `victims` 上（每个 victim 一行 who/where，且仅限 victim）；后来对同一 victim 的结案更新该行。绑定角色 infra 不会出现在那些行上。`recordMission`／`recordPlan`／`recordAction` 持久化底盘阶段；Plan 只追加。当前绑定有唯一 LAN victim 与已绑定、不是知名 CDN 或更新目的地址的非 LAN C2 时，仅在 Plan 就绪后对该 victim 下发 `extra-wan`（`ip.src ==` 该 victim，字段 `ip.dst`，在输出裁切之前按首次出现顺序去重），并对每个剩余 C2 IPv4（已绑定加上收割到的额外地址）下发 `c2-domain`。当 `autoHunt` 为 true 时这些 hunt 会自动运行；即使已有 C2 通信焦点 IP，`extra-wan` 仍会运行。已绑定 C2 加上盖上受害端戳的 extra-wan 目的地址持久化到 `investigation/extras` 并作为 `c2_ips`，省略证据主机名为知名 CDN 或更新名的 IP，以及落在已公布 Cloudflare 或 Fastly 任播段上的 IP。躲过那些省略的未点名 extra-wan 目的地址仍持久化。extra-wan 仍收割盖上受害端戳的附加项。收割到的、证据落在已证明目的地址上的带点 DNS 名在不是 CDN／更新时作为 `c2_domain` 持久化到已接受的结案包；它不填 who/where 的 hostname，也不捐给受害端行。在当前绑定恰好有一个 victim 之前，`case_report` 会被拒绝；`who` 和 `where` 从该受害端实体行投影。who/where 的 `entity_id` 若是该行上的用户、主机名、MAC 或全名，只是句柄；持久化结案包使用被绑定的 victim 地址。当前绑定之后，未归属的账本身份（没有 `entity_id`，且 `evidence_id` 不指向非 victim）在它是该种类中唯一未归属到其他实体的身份时捐给被绑定的 victim；同一种类的两个未归属身份都不捐出。工具结果行上来自被绑定 victim IP 的 MAC（`ip.src`、出站 `ip → peer` 或 ARP `is at`），或从限定在该 victim IP 的仅字段 `eth.src` 转储改戳而来的 MAC，即使 hunt 主体 `evidence_id` 点名另一 IP、第一次收割没有 `evidence_id`、账本上还有其他 MAC 值也捐出。证据落在被绑定 victim IP 上的主机名（hunt 主体 `evidence_id`，或限定在该 IP 的名称服务行）即使还有其他主机名值也捐出。AD SRV／DC 定位器主机名（`_ldap._tcp…`、`_msdcs.`、`_sites.dc.` 及同类下划线 AD DNS 定位器）不作为 who/where 的 hostname 持久化；保留提交或已收割的工作站主机名；只收割到该定位器时 hostname 保持省略。Kerberos／SAMR 会话的客户端是被绑定 victim（LAN／非域控端）的用户或全名，即使 hunt 主体 `evidence_id` 点名另一 IP、账本上还有其他域账户也捐出。持久化的 who/where 从该投影携带 ip／mac／hostname／user／full_name。拒绝／强制转换之后，模型省略的键（包括 `mac`）从该投影受害端行补全；粘滞的域控捐出或唯一性让该行为空时，省略的 mac 持久化唯一不是仅域控／网关的账本 MAC；省略的 user 仍从受害端 IP 证据持久化，或在机器 SAM 挡住唯一性捐出时持久化唯一已收割的人类 user；当该行没有已捐出的值、且该身份不捐给其他实体时，保留模型提交的 user、hostname 或 full_name；当前绑定之后，省略的 who/where 会把同一 case_report 参数上的同级顶层身份键（ip、mac、hostname、user、full_name）折入该提交槽位；提交的人类 user 无需会话客户端戳记即可保留；以 `$` 结尾的机器 SAM 不作为 user 持久化；除非通信 IP 帧只从非 victim 来源该 MAC，否则保留提交的 mac；模型提供的 IP 不会替换被绑定的 victim ip。带 `entity_id` 的 JSON 对象字符串，或当前绑定之后剩余身份 token 全是受害端行句柄的字符串，会在自由文本检查之前被强制转换。身份 token 忽略字段标签、定位剩余词（client／ip／located／at／on／network）、LAN／网关／域控／AD 域包裹（lan／gateway／dc／ad／domain／workgroup／controller）、句子包裹、包裹的 ASCII 引号、通信 IP 帧只从非 victim 来源的剩余 MAC、包含被绑定 victim IP 的剩余 CIDR、剩余 LAN 基础设施 IPv4，以及剩余域／工作组公告，并把多词 full_name 当作一句柄。MAC、用户、主机名或全名在捐给 victim，或证据落在该 victim 上（受害端 IP 帧／会话客户端戳记）时是句柄。点名 c2、干扰项用户或主机名、另一个剩余的具名非 infra IPv4、不包含 victim 的 CIDR 或无法匹配剩余词的字符串仍保持未绑定。只含该仅域控／网关 MAC、或只含该包含受害端 CIDR 的字符串仍保持未绑定。剩余项只是 LAN／网关／域控／AD 域包裹以及剩余 LAN 基础设施 IPv4／域公告／仅域控 MAC 的字符串会强制转换成受害端行。对调的 victim／c2 结案会被拒绝。线索或观测地址不能作为 victim。被引用的会话必须包含线索／观测地址；两端都在 LAN 的会话保持未绑定。角色 `c2` 不能是 LAN 地址或知名 CDN 或更新目的地址。不会对调 token。两端都在 LAN 或 CDN／更新 C2 的拒绝不下发 `other-end`。端点对象的 JSON 数组字符串，以及作为 1-65535 整数的数字字符串 `dport`，会在这些绑定检查之前被强制转换。不是 JSON 数组的字符串、缺失的 `dport`、或超出 1-65535 的 `dport` 仍被拒绝。不会编造姓名。对案件根目录 `report.md`（及同类结案文件）的 `write` / `edit` 会被拒绝；不会把 `report.md` 解析进 who/where。`c2TalkingLanVictim` 只归属唯一的来源 `eth.src` MAC，不改写槽位。
- `resolveInsideCase`、`isEvidence`、`isWritable` 和 `contains` 强制案件目录范围。

`tools/pre-execute` 拒绝写入证据和捕获文件、write/edit 案件根目录结案文件、离开案件目录的 shell 命令，以及恶意软件运行器（`wine`、`qemu`、捕获的 `.exe`）。`tools/post-execute` 从成功的工具文本中收割 IP、MAC、主机名、用户和全名，包括 UTF-16LE SAMR 十六进制（`Becka Rolf`）以及 NBNS、BROWSER、SMB、LLMNR、TLS SNI 和 DNS 的 tshark 摘要中的主机名。能区分出的工作组和域 token（Domain/Workgroup Announcement、Local Master Announcement，或 NBNS `<1b>`–`<1e>`）不会记为主机名。新的 IP 对该主体下发 `eth-src`、`name-service`、`kerberos-cname` 与 `samr-userinfo`；新主机名下发 `kerberos-cname` 与 `samr-userinfo`；新用户下发 `samr-userinfo`。当一个 LAN IP 与非 LAN 单播对等体出现在同一行时，这些身份 hunt 只对该 C2 通信 IP 下发；`eth-src` 通知使用 `ip.src ==` 该主体，且 MAC 收割只记录来自该 IP 的 `eth.src`，而不是对端或空闲工作站的网卡，并把该通信 IP 写入 `evidence_id`，即使该转储的 hunt 主体是另一个 IPv4。没有通信 IP 的仅字段 `eth.src` 转储把 hunt 主体 `scopeIp`（`ip.src`／`ip.addr ==` 该 IP）写入戳记；后来限定在受害端 IP 的转储会给第一次没有 `evidence_id` 或带域控／对等体戳记的收割改戳。用户和全名收割把会话客户端 IPv4 写入 `evidence_id`，而不是 SAMR／CNameString hunt 主体域控。没有 IP 的仅字段 SAMR／CName 转储，从先前的工具文本把对该域控讲话的 LAN／非域控对等体（`ip.src` 或 `LAN → DC`）写入戳记。协议字段名和截断转储不是用户或全名身份。收割到的 IP 在 hunt 主体 `scopeIp` 已设定时把该范围写入 `evidence_id`。其他以 IP 为主体的通知使用 `ip.addr ==` 该主体。当 `autoHunt` 为 true 时，已下发且尚未执行的 hunt 仅在 Plan 就绪时用同一套限定范围的 `display_filter` 和字段跑 `pcap_filter`；插件不等模型调用 `pcap_filter`。仅有 Mission 不会自动运行。`agent/turn-stopping` 在 Mission 仍为 cue-pending、Plan 未就绪、或当前绑定之后仍有已收割的 LAN 工作站未绑定时，用点名原因做 steering（中途引导），因此仅有文本的 `turn/end` complete 不能关闭会话。绑定角色 infra、AD SRV／DC 定位器主机名，以及 LAN 域控／文件服务器／网关角色主机名，不是剩余工作站。优先正在与 C2 通信的 LAN 主体；非 LAN / C2 IP 主体不会自动运行，但绑定把线索指定为 victim 时下发的 `other-end`（`ip.dst ==` 该线索，字段 `ip.src`），成功绑定后对该 LAN victim 下发的 `extra-wan`（`ip.src ==` 该 victim，字段 `ip.dst`，在输出裁切之前按首次出现顺序去重），以及对每个 C2 IPv4 下发的 `c2-domain`（`tls.handshake.extensions_server_name`／`dns.qry.name`／`dns.resp.name` 且 `ip.addr ==` 该 C2）除外。`name-service` 是 `llmnr or nbns or browser`。SMB 不是 hunt 种类。

`investigation:policy` 章节陈述 DINQ、包裹 Observation → Question → Hypothesis → Answer → Bind → Who/Where 的 Mission／Plan／Action／Report、Who/Where 之前的 BindRelationship、5W1H、证据优先工作，以及有效的 tshark 4.4.16 字段。`investigation:ledger` 是列出 Mission、Plan、当前角色卡片、已记录身份与 hunt 的动态上下文。设计见[在没有 5W1H 结案时持久化遗留 C2 附加项](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-c2-extras-without-close.md)、[在 cue-pending 或 Plan 未就绪时拒绝 complete](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-complete-while-cue-pending.md)、[在已收割 LAN 工作站仍未绑定时拒绝 complete](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-complete-while-unbound-workstation.md)、[从剩余工作站中省略 LAN 基础设施角色主机名](../../../.agents/notes/implemented/bug-fix/2026-08-22-omit-lan-infra-role-hostnames-from-leftover.md)、[结案前的 BindRelationship](../../../.agents/notes/implemented/feature/2026-08-21-bind-relationship.md)、[拒绝将线索指定为 victim](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-cue-as-victim.md)、[拒绝将线索指定为 victim 时下发 other-end hunt](../../../.agents/notes/implemented/bug-fix/2026-08-21-other-end-hunt-on-cue-victim.md)、[case_report 受害端行 entity_id](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-row-entity-id.md)、[补全受害端行投影](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-victim-row-projection.md)、[受害端 IP 范围捐出](../../../.agents/notes/implemented/bug-fix/2026-08-21-donate-victim-ip-scoped-mac-hostname.md)、[MAC 通信 IP 戳记](../../../.agents/notes/implemented/bug-fix/2026-08-21-stamp-mac-evidence-from-talking-ip.md)、[改戳限定在受害端 IP 的 eth.src](../../../.agents/notes/implemented/bug-fix/2026-08-21-restamp-victim-ip-scoped-eth-src.md)、[覆盖域控 MAC 戳记](../../../.agents/notes/implemented/bug-fix/2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md)、[用户／全名会话客户端戳记](../../../.agents/notes/implemented/bug-fix/2026-08-21-stamp-user-fullname-from-conversation-client.md)、[仅字段 SAMR／CName 客户端戳记](../../../.agents/notes/implemented/bug-fix/2026-08-21-reject-protocol-field-stamp-field-only-samr.md)、[字符串化的 who/where](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-stringified-who-where.md)、[字符串化的 bind endpoints 与 dport](../../../.agents/notes/implemented/bug-fix/2026-08-21-bind-relationship-stringified-args.md)、[拒绝两端都在 LAN 的绑定](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-both-lan-bind.md)、[持久化省略的受害端行键](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-projected-victim-slot.md)、[保留提交的受害端行身份](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-row-identities.md)、[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-mac-unless-dc-only.md)、[补全省略的受害端行 mac 与 user](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-omitted-victim-mac-user.md)、[仅域控 MAC 须为排他的非 victim 通信 IP](../../../.agents/notes/implemented/bug-fix/2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md)、[受害端行句柄字符串](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-handle-strings.md)、[带标签的受害端行句柄字符串](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-labeled-victim-handle-strings.md)、[仅域控／网关 MAC 剩余项](../../../.agents/notes/implemented/bug-fix/2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)、[定位／CIDR 剩余项](../../../.agents/notes/implemented/bug-fix/2026-08-21-drop-locator-cidr-from-handle-string-coerce.md)、[LAN／网关／域控剩余项](../../../.agents/notes/implemented/bug-fix/2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md)、[折入同级身份键](../../../.agents/notes/implemented/bug-fix/2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md)、[在省略的 who 上持久化已收割的人类 user](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-harvested-human-on-omitted-who.md)、[省略 AD SRV 定位器主机名](../../../.agents/notes/implemented/bug-fix/2026-08-21-omit-ad-srv-locator-hostname.md)、[持久化每一个已绑定受害端行](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-every-bound-victim-row.md)、[拒绝写入结案文件](../../../.agents/notes/implemented/bug-fix/2026-08-21-deny-close-file-writes.md)，[成功绑定后的 C2-domain hunt](../../../.agents/notes/implemented/bug-fix/2026-08-21-c2-domain-hunt-after-live-bind.md)，[成功绑定后的 extra-WAN C2 hunt](../../../.agents/notes/implemented/bug-fix/2026-08-21-extra-wan-c2-hunt-after-live-bind.md)、[第二个 C2 角色存在时仍把会话 dest 当作已绑定 C2](../../../.agents/notes/implemented/bug-fix/2026-08-21-bound-c2-conversation-dest-when-second-c2.md)，[在裁切之前对 extra-wan 目的地址按首次出现去重](../../../.agents/notes/implemented/bug-fix/2026-08-21-unique-collapse-extra-wan-before-clip.md)，[拒绝 CDN／更新 C2](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-cdn-update-c2.md)，[省略 Cloudflare IPv4 C2 目的地址](../../../.agents/notes/implemented/bug-fix/2026-08-21-omit-cloudflare-ipv4-c2-dests.md)，[省略 Fastly IPv4 C2 目的地址](../../../.agents/notes/implemented/bug-fix/2026-08-21-omit-fastly-ipv4-c2-dests.md)，[只持久化已证明 C2 目的地址](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-attested-c2-dests.md)，以及[持久化未点名 extra-wan 目的地址](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-unnamed-extra-wan-c2-dests.md)。

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
You are a network-security investigation analyst, not a coding agent. Define the Investigation Question (DINQ) before collecting more evidence. Mission, Plan, Action, and Report wrap Observation, then Question, then Hypothesis, then Answer, then Bind, then Who/Where. Do not skip Observation or Question or Hypothesis. The chassis stamps Mission as a victim-identity + C2 investigation. Mission scopes the case. Auto-hunts run after Plan is ready, including a named cue that is valid or explicitly open. Bind needs a named C2 hypothesis and CDN/DC alternatives on the Plan. Plan names each hypothesis as I believe X because Y plus a disconfirm test, including a C2 hypothesis and a CDN, DC, or update alternative. After a named live cue, omitted inventory defaults to the case capture when one exists. Empty inventory is not a finished Plan. After a named live cue, omitted CDN/DC/update alternative defaults to an open CDN-or-update hypothesis. Before Who/Where, bind the conversation. The detector’s IP is a hypothesis about the other end until the bind says otherwise. Use bind_relationship to assign victim vs c2 on the cited conversation. Exactly one victim. The cited conversation must include a cue/observation address. Role c2 cannot be a LAN address or a well-known CDN or update destination. Cue and observation addresses default to c2 and cannot be victim. State what, when, why, and how as claims you can support with packets or logs. who and where are projections of the bound victim. Work evidence-first and question-driven: every tool call answers a named question. Label unverified ideas as hunches and verify them in this case. Evidence under evidence/ and capture files (*.pcap, *.pcapng, *.cap, *.log) is read-only. Do not execute malware, run captured binaries, or operate on paths outside the case directory. Use pcap_info, pcap_filter, logs, and bind_relationship. Valid tshark 4.4.16 fields include kerberos.CNameString, samr.samr_UserInfo21.account_name, and samr.samr_UserInfo21.full_name. Do not use ldap.sAMAccountName, ldap.displayName, kerberos.username, or samr.full_name — those fields are invalid. After a hostname or IP appears, hunt Kerberos CNameString, then SAMR QueryUserInfo for the display name. SAMR full_name is UTF-16 (for example Becka Rolf), not an LDAP displayName. Close with case_report only after bind_relationship has assigned the victim.
```

#### Token 影响

插件挂载期间，该章节在每个请求上是固定段落。

#### KV Cache 影响

该章节在挂载生命周期内保持稳定。

### 身份账本上下文

#### 模型看到什么

当会话日志持有 Mission、Plan、绑定、身份、hunt 或报告时，`investigation:ledger` 将这些行列为动态上下文快照。当前绑定上的身份会标上端点角色。

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

被拒绝的写入、越出案件目录或恶意软件运行器调用会返回错误结果，点名案件目录或只读证据规则。write/edit 案件根目录 `report.md`（或同类结案文件）返回 `close with case_report after BindRelationship.` 未绑定、对调或自由文本的 `case_report`（或任何设置 `who` / `where` 的工具）返回 `unbound: assign victim vs c2 on the cited conversation.` 在 `bind_relationship` 上把 victim 指定给线索／观测地址返回 `unbound: hunt LAN ip.src talking to <cue> (ip.dst == <cue>).` 两端都在 LAN 的会话返回 `unbound: cite the LAN host talking to the cue/observation address, not a LAN DC/AD service.` 把 `c2` 指定给 LAN 地址返回 `unbound: role c2 cannot be a LAN address.` 把 `c2` 指定给知名 CDN 或更新目的地址返回 `unbound: role c2 cannot be a well-known CDN or update destination.` 已解析绑定在 Plan 上没有 C2 假设时返回 `unbound: name a C2 hypothesis on the Plan before bind_relationship.` 已解析绑定没有 CDN／DC／更新替代时返回 `unbound: check CDN/DC alternatives on the Plan before bind_relationship.` 已解析绑定没有清单时返回 `unbound: inventory what can attest on the Plan before bind_relationship.` 已点名现场线索之后，省略或空的清单在存在案件捕获时默认成该捕获；空清单不是完成的 Plan。已点名现场线索之后，省略的 CDN／DC／更新替代会默认成一条仍开放的 CDN 或更新假设；已提交的替代会保留。底盘尚未点名的线索，或缺少 valid 或显式 open 的已点名线索，返回 `unbound: slot 0a must name a real cue (valid or explicitly open) before bind_relationship.`

#### Token 影响

该错误像其他失败调用一样留在对话历史中。

#### KV Cache 影响

被拒绝的调用按常规扩展对话。

## 已知限制与延后工作

- Shell 策略按 token 扫描命令；精心构造的一行命令仍可能以扫描器错过的方式点名案件外路径。对证据优先使用 `pcap_filter` 和 `logs`，而不是自由 shell。
- 收割基于文本。从未渲染为文本的结构化工具值不会被记录。来自 tshark 摘要的主机名限于 NBNS、BROWSER、SMB 和 LLMNR 的主机形式；已区分的工作组和域 token 会被省略。见到 C2 通信 IP 之后，只记录来自该 IP 的 MAC；没有 IPv4 的纯 `eth.src` 字段转储回退到严格多数，对端网卡仍可能占多数。
- 账本尚无 Web 投影卡片；UI 读取 `session/event` 或折叠日志。
