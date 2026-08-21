# Agent Note: 结案前用 BindRelationship 绑定 victim 与 c2

Status: implemented

[English](2026-08-21-bind-relationship.md) | 中文

## 问题

攻击是关系。在有人给被引用的会话指定 victim 与 c2 之前，检测器给出的 IP 只是对另一端的假设。调查账本里已经有该会话，以及正在与 C2 通信的 LAN 身份。模型从未看到这些角色。

`formatLedger` 是没有标签的扁平列表。hunt 通知在已下发 hunt 已经自动跑完之后，仍让模型去跑 `pcap_filter`。`METHODOLOGY_SECTION` 写了 DINQ 与 5W1H，没有 victim 对 c2 的规则。`case_report` 接受六个自由文本字符串，且没有 `tools/pre-execute` 检查。无密钥 pcap-case 快照从 `pcap_filter` 一跳就到 `case_report`。

把 `who` / `where` 静默改写到正在与 C2 通信的 LAN IP，会掩盖对调，而不是强制绑定。该改写已归档为[将 case_report 的 who/where 绑定到正在与 C2 通信的 LAN 身份](../../archived/bug-fix/2026-08-21-case-report-c2-talking-lan-identity.md)。

## 决策

`bind_relationship` 是思考原语。它记录 `investigation/bind`，字段为 `{src, dst, dport, t, evidence_id}`，端点为 `{addr, role ∈ victim|c2|infra|distractor|unknown, because}`。恰好一个 victim。线索或观测地址（非 LAN 单播）默认 `c2`，且不能作为 victim（[拒绝将线索指定为 victim](../bug-fix/2026-08-21-refuse-cue-as-victim.md)）；该拒绝点名为该线索猎取 LAN `ip.src` 的 [other-end hunt](../bug-fix/2026-08-21-other-end-hunt-on-cue-victim.md)。其余未指定地址默认 `unknown`。

当前绑定通过 `investigation:ledger` 发布焦点／角色卡片。那张卡片不是又一条收件箱拼接。hunt 通知点名已经跑过的过滤器。

`tools/pre-execute` 在没有恰好一个 victim 的当前绑定时报错拒绝 `case_report`，以及任何设置 `who` 或 `where` 的工具参数。身份槽的 `evidence_id` 指向非 victim，或 `who` / `where` 的 `entity_id` 点名非 victim 端点或另一个 IPv4 时，同样拒绝。用户、主机名、MAC 或全名是受害端行句柄，不是实体 id；持久化结案包使用被绑定的 victim 地址（[受害端行 entity_id](../bug-fix/2026-08-21-case-report-victim-row-entity-id.md)）。拒绝文本是 `unbound: assign victim vs c2 on the cited conversation.` 对调的 victim／c2 会被拒绝。不会对调 token。

`case_report` 的 `who` / `where` 是受害端实体行（IP、MAC、主机名、用户、全名）的投影，不是自由文本填写。IP 以自身作为实体。显式 `entity_id` 优先。唯一的来源 `eth.src` MAC 通过 `c2TalkingLanVictim` 归属到被绑定的 victim；该辅助函数不改写 `who` / `where`。当前绑定之后，证据落在被绑定 victim IP 上的 MAC 或主机名仍捐出，即使账本上还有同一种类的其他值（[受害端 IP 范围捐出](../bug-fix/2026-08-21-donate-victim-ip-scoped-mac-hostname.md)）。第一次在域控或对等体 hunt 下戳记的 MAC，只要后来的帧把它从来自 victim IP 的方向送出，就仍捐出（[通信 IP 戳 MAC](../bug-fix/2026-08-21-stamp-mac-evidence-from-talking-ip.md)）。未归属的账本身份在它是该种类中唯一未归属到其他实体的身份时捐出（[补全受害端行投影](../bug-fix/2026-08-21-complete-victim-row-projection.md)）。`entity_id` 已经是 victim 的身份仍捐出。同一种类的两个未归属身份都不捐出。distractor 留在账本上，不能捐出身份槽。不编造姓名。

[去引号](../bug-fix/2026-08-21-pcap-filter-quoted-display-filter.md)、[字符串字段强制转换](../bug-fix/2026-08-20-pcap-filter-string-fields.md)、`eth-src` 使用 `ip.src`、[来源 MAC 收割](../bug-fix/2026-08-21-harvest-eth-src-from-c2-talking-ip.md) 和[自动运行](../bug-fix/2026-08-21-auto-run-outstanding-identity-hunts.md) 仍是辅助手段。BindRelationship 是结案检查。scout、遗留报告禁令和新评测不在本次变更内。

## 备选方案

**把 who/where 静默改写到正在与 C2 通信的 LAN IP。** 否决：那会掩盖对调。模型必须绑定会话。先前的改写已归档。

**把账本字段合并进 who/where 当作产品。** 否决：BindRelationship 是思考原语，不是又一次静默投影。

**只改方法论提示词或工具描述。** 否决：模型仍可以在未绑定时报案。

**对调已颠倒的 victim／c2 token。** 否决：那是换了名字的静默改写。拒绝结案。

**把 who/where 里的空闲 LAN IP 改写成焦点 IP。** 否决：那是[双客户端融合](../bug-fix/2026-08-20-scope-identity-hunts-to-c2-talking-client.md)。

**编造账本上没有的主机名、用户或全名。** 否决：不编造姓名。当前绑定之后，唯一未归属的账本身份会捐出（[补全受害端行投影](../bug-fix/2026-08-21-complete-victim-row-projection.md)）。

**把 Easy as 123、First to Last 或 Lumma 的黄金 IP、MAC 或姓名写进提示词或测试。** 否决：测试使用合成 LAN 客户端和 TEST-NET 对等体。

**发明评测或改动 scout。** 否决：本旋钮是结案前的绑定。

**允许两个 victim 或零个 victim。** 否决：绑定必须恰好一个 victim。

**让 distractor 捐出 MAC、主机名或用户。** 否决：distractor 保持标签，不能填写 who/where。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET 对等体（`198.51.100.80`）和空闲 distractor。它检查线索默认 `c2`、线索作为 victim 被拒绝、两个／零个 victim 被拒绝、从受害端行投影、distractor 不捐出、唯一来源 MAC 归属、唯一未归属的 mac／hostname／user／full_name 捐出、另一行存在时受害端 IP 范围内的 mac／hostname 捐出、两个未归属用户或 MAC 都不捐出、未绑定／对调／自由文本拒绝，以及受害端行用户句柄（`who.entity_id` 为用户名）用 victim 地址结案。`packages/analyst/investigation/tests/investigation.spec.ts` 记录 `bind_relationship`，在没有当前 victim 之前拒绝 `case_report`，并在账本上渲染角色卡片。`packages/analyst/analyst-tools/tests/tools.spec.ts` 要求先绑定再结案，并从受害端投影 who/where，包括该行上的用户名句柄以及未归属的收割行。无密钥 `examples/analyst` pcap-case 快照是 `pcap_filter`，然后 `bind_relationship`，然后 `case_report`。

## 后果

结案必须先调用 `bind_relationship`。对调或未绑定的 `case_report` 以未绑定原因失败。模型在账本卡片上看到 victim 与 c2。自动运行、去引号和字段强制转换仍是辅助手段，不指定角色。主机名、用户和全名来自收割捐出——受害端上的显式 `entity_id`、受害端 IP 范围内的 mac／hostname，或唯一未归属的账本身份——不来自改写。
