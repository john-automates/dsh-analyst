# Agent Note: 拒绝协议字段收割，并把仅字段 SAMR／CName 戳成会话客户端

Status: implemented

[English](2026-08-21-reject-protocol-field-stamp-field-only-samr.md) | 中文

## 问题

线上 lumma-r13（`97a1e42`）正确绑定了被引用的会话（victim `10.1.21.58`／c2 `153.92.1.49`）。结案栏 3/5 — IP 通过、主机名通过、全名通过（唯一未归属）。用户失败：工作站账户只在账本上打印。MAC 失败是单独的[通信 IP 捐出](2026-08-21-stamp-mac-evidence-from-talking-ip.md)回归，不在本次变更内。

[会话客户端戳记](2026-08-21-stamp-user-fullname-from-conversation-client.md)没有触发。SAMR／CName 转储只有字段（`kerberos.CNameString`／`samr.samr_UserInfo21.account_name`，行上没有 `ip.src`），因此 `conversationClientIp` 返回 undefined，收割没有写入 `evidence_id`。绑定之后，全名靠唯一未归属捐出。用户没有，因为唯一性被进入用户账本的垃圾收割打破：tshark 表头或空字段（`samr.samr_UserInfo21.account_name:`）和截断转储（`account_name: [truncated:`）。

## 决策

协议字段名和截断转储不是身份。看起来像 tshark／SAMR／Kerberos 字段的捕获用户或全名（`samr.samr_UserInfo21.account_name`、`kerberos.CNameString`、带 `.` 的协议前缀、尾随 `:`）或截断标记（`[truncated`、`[truncated:`）不进入账本。空捕获仍然拒绝。

仅字段、限定在域控的真实 SAMR／CName 收割，把 `evidence_id` 写成 `evidenceText` 里的会话客户端：对该域控讲话的 LAN／非域控对等体（`ip.src` 或 `LAN → DC`）。hunt 主体域控不会获胜。已戳成客户端的 `evidence_id` 不会当作域控传进 `conversationClientIp`。

当前绑定之后，只要其他真实域账户不是受害端客户端，戳在或证据落在受害端客户端上的真实用户即使账本上还有那些账户也捐出。垃圾行不存在，不会破坏唯一性。持久化的 who／where 携带该用户。不会编造槽位。

[会话客户端戳记](2026-08-21-stamp-user-fullname-from-conversation-client.md)仍拥有行上 Kerberos／SAMR `ip.src`。[通信 IP 戳 MAC](2026-08-21-stamp-mac-evidence-from-talking-ip.md)和[主机名捐出](2026-08-21-donate-victim-ip-scoped-mac-hostname.md)保持不变。线索作为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体和空闲或域控 LAN 行。

## 备选方案

**继续收割协议字段和截断捕获，只让 `uniqueUnaffiliated` 忽略它们。** 否决：那些字符串不是身份。它们不得进入用户或全名账本。

**把 hunt 主体 `evidence_id` 戳在仅字段 SAMR／CName 转储上。** 否决：SAMR／CName hunt 通常限定在域控。那会把工作站账户锁到域控。

**把已戳成客户端的 `evidence_id` 当作 hunt 主体 `scopeIp` 传进 `conversationClientIp`。** 否决：正确收割戳记之后客户端 IP 等于 `ip.src`。把该戳记当成域控会返回另一端，并捐给域控。[会话客户端戳记](2026-08-21-stamp-user-fullname-from-conversation-client.md)已经记录过这一点。

**改 MAC 通信 IP 路径，让仅字段 SAMR 转储也改戳 MAC。** 否决：MAC 捐出仍看通信 IP 帧。这个旋钮不改那条路径。

**垃圾消失之后捐出每一个未归属用户。** 否决：没有受害端客户端会话的两个真实域账户必须都不捐出。选出工作站账户的是受害端客户端戳记或证据。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture（测试前置数据）是合成 LAN IP、TEST-NET 对等体和空闲或域控 LAN 行。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET 对等体（`198.51.100.80`）和空闲或域控行（`10.0.10.3`）。`samr.samr_UserInfo21.account_name:` 和 `account_name: [truncated:` 不会收割成用户。仅字段、限定在域控的真实 `kerberos.CNameString: lan-user` 或 `samr.samr_UserInfo21.account_name: lan-user`，在证据文本有 `10.0.10.2 → 10.0.10.3` 或对该域控讲话的 `ip.src` `10.0.10.2` 时戳成 `evidence_id=10.0.10.2`。把客户端当作 `scopeIp` 传入不会戳成域控。

`packages/analyst/investigation/tests/bind.spec.ts` 记录该客户端戳记用户，再加上来自 `10.0.10.3` 的第二个域账户。当前绑定之后，客户端用户捐出并持久化到 who／where。来自域控的账户不捐出。MAC 通信 IP 捐出和主机名捐出保持不变。

## 后果

限定在域控的仅字段第一次收割仍能把工作站账户戳到会话客户端。协议字段和截断捕获不能占用用户账本，也不能否决唯一未归属捐出。没有受害端客户端会话的其他真实域账户不进入受害端行。MAC 通信 IP 捐出和主机名捐出不变。
