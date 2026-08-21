# Agent Note: 把用户和全名的 evidence_id 戳成会话客户端，而不是 hunt 主体

Status: implemented

[English](2026-08-21-stamp-user-fullname-from-conversation-client.md) | 中文

## 问题

线上 lumma-r12（`1b29190`）正确绑定了被引用的会话（victim `10.1.21.58`／c2 `153.92.1.49`）。[通信 IP 戳 MAC](2026-08-21-stamp-mac-evidence-from-talking-ip.md) 已从受害端 IP 帧改戳黄金 MAC 并标成 `[victim]`；域控和网关 MAC 没有进入受害端行。结案栏 3/5 — 用户失败、全名失败。两者都只在账本上且未打标签。r11 为 4/5（有用户和姓名，缺 MAC）。

`harvestIdentities` 给 MAC（通信 IP）和主机名（hunt 主体）戳 `evidence_id`。用户和全名没有戳记。SAMR／CNameString hunt 通常限定在域控。账本上还有其他域账户时，`uniqueUnaffiliated` 捐出会失败，或者这些身份一直未归属，从未持久化到 who／where。

## 决策

收割到的用户（`kerberos.CNameString`／`account_name`）或全名（`samr.samr_UserInfo21.full_name`）把 `evidence_id` 写成该会话的客户端 IPv4：LAN／非域控端（对域控讲话的 `ip.src`，或不是 hunt 主体 `scopeIp` 的对等体）。hunt 主体 `scopeIp`（通常是域控）不戳用户或全名。

当前绑定之后，即使用户或全名第一次出现在域控或对等体 hunt 下，只要该会话的客户端是被绑定 victim，就仍捐给 victim。hunt 主体 `evidence_id` 不能否决。持久化的 who／where 携带该用户和全名。从未作为客户端是被绑定 victim 的会话之客户端出现的域账户不捐出。不会编造槽位。

[通信 IP 戳 MAC](2026-08-21-stamp-mac-evidence-from-talking-ip.md) 和[主机名捐出](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) 保持不变。线索作为 victim 仍被拒绝，并仍下发 [other-end](2026-08-21-other-end-hunt-on-cue-victim.md)。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体和空闲或域控 LAN 行。

## 备选方案

**继续让用户和全名不打标签，只让 `uniqueUnaffiliated` 忽略其他域账户。** 否决：账本上的其他账户是真实的。唯一性分不清哪个账户是会话客户端。

**把 hunt 主体 `evidence_id` 戳在用户和全名上。** 否决：SAMR／CNameString hunt 通常限定在域控。那会把工作站账户锁到域控，正是 [通信 IP 戳记](2026-08-21-stamp-mac-evidence-from-talking-ip.md) 已经补上的 MAC 漏洞。

**在后来的受害端客户端转储上改戳 `evidence_id`。** 否决：`recordIdentity` 按 kind+value 唯一。捐出读会话，不改写账本行。

**捐出同一种类的每一个未归属用户或全名。** 否决：没有受害端客户端会话的两个域账户必须都不捐出。

**捐出从未作为客户端是被绑定 victim 的会话之客户端出现的域账户。** 否决：那些账户不进入受害端行。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture（测试前置数据）是合成 LAN IP、TEST-NET 对等体和空闲或域控 LAN 行。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET 对等体（`198.51.100.80`）和空闲或域控行（`10.0.10.3`）。客户端为 `10.0.10.2` 的 Kerberos／SAMR 会话上的用户或全名即使 `scopeIp` 是 `10.0.10.3` 也戳成该 IP。主机名仍戳 hunt 主体。只有 CNameString 字段的转储不会把 hunt 主体 `evidence_id` 继承到用户。

`packages/analyst/investigation/tests/bind.spec.ts` 先把用户+全名记成 `evidence_id=10.0.10.3`（或来自域控限定转储的未打标签值），再给出客户端为 `10.0.10.2` 的 Kerberos／SAMR 会话证据文本。当前绑定之后，这些值捐出并持久化到 who／where。`10.0.10.3` 上的第二个域账户不捐出。MAC 和主机名捐出以及拒绝将线索指定为 victim 保持不变。

## 后果

当会话点名了不同的客户端 IP 时，限定在域控的第一次收割不能把工作站用户或全名锁到域控。即使第一次戳记错误或该行未打标签，后来的 Kerberos／SAMR 文本显示被绑定 victim 是该会话的客户端时仍会捐出。没有该客户端的其他域账户不进入受害端行。MAC 通信 IP 捐出和主机名捐出不变。
