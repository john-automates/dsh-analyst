# Agent Note: 将带标签或句子包裹的受害端行句柄字符串强制转换

Status: implemented

[English](2026-08-21-case-report-labeled-victim-handle-strings.md) | 中文

## 问题

线上 fake-software r4（`cd66ca2`，在[省略的 mac／user 持久化](2026-08-21-complete-omitted-victim-mac-user.md)之后）正确绑定了被引用的会话（LAN victim／非 LAN C2）。两次 `case_report` 都因未绑定被拒绝。模型提交的是带标签的散文字符串，而不是 `{ entity_id }`：

- who：`User Account: <user> / Full Name: <full name> / MAC Address: <mac>`（第二次调用还加了 `Hostname: <host>`）
- where：一句点名受害端 IP 与主机名的句子

[句柄字符串强制转换](2026-08-21-case-report-victim-handle-strings.md) 已经接受身份 token 全是受害端行句柄的 who/where 字符串。`identityLikeTokens` 把每个剩余词都当成 token（`User`、`Account`、`Full`、`Name`、`MAC`、`Address`、`The`、`infected`、`host`、`was`、`identified`、`as`）。这些词通不过句柄检查。按空白切分也会拆开多词 `full_name`。`victimRowHandles` 只包含已捐出的身份，所以黄金 MAC 即使先捐给域控、后来由受害端 IP 帧送出，也不是句柄。

省略的 mac／user 持久化从未运行，因为没有任何调用被接受。

## 决策

当前绑定之后，当 `who` / `where` 字符串里的每个身份 token 都是受害端行句柄（IP／MAC／主机名／用户／`full_name`）时，`caseReportDenyReason` 把它强制转换成 `{ entity_id: victim }`，即使字符串还带字段标签或句子包裹。随后由已有的完整投影路径持久化省略的 mac／user。

标签词和句子包裹不是身份 token。ASCII 单引号和双引号是 who/where 分隔符，所以带引号的主机名仍作为一句柄匹配。多词 `full_name` 作为一句柄匹配。MAC、用户、主机名或 `full_name` 在捐给被绑定 victim，或按省略 mac／user 持久化的同一方式（受害端 IP 帧／会话客户端戳记）证据落在该 victim 上时，是受害端行句柄。粘滞的域控捐出不会让受害端 IP 送来的 MAC 通不过句柄检查。

通信 IP 帧只从非 victim 来源的剩余 MAC 会被丢弃而不是保持未绑定（[仅域控／网关 MAC 剩余项](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)）。定位剩余词和包含被绑定 victim IP 的剩余 CIDR 会被丢弃（[定位／CIDR 剩余项](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md)）。点名 C2、干扰项用户或主机名、另一个 IPv4 或无法匹配剩余词的字符串仍保持未绑定。无法匹配的身份 token 仍拒绝。不编造身份。不对调 token。将线索指定为 victim 仍被拒绝。

漏洞在 `packages/analyst/investigation/src/bind.ts` 的 `isVictimHandleText`／`identityLikeTokens`／`victimRowHandles`。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC` 对 `DISTRACTOR_MAC`，以及 `lan-user`／`Lan User`。

## 备选方案

**继续把每个剩余词都当成身份 token。** 否决：字段标签和句子包裹会在正确绑定之后让句柄检查失败。

**句柄边界仍只认空白和 `,;:|/`。** 否决：主机名外的 ASCII 引号会让 `"hostname"` 成为无法匹配的剩余 token。

**当前绑定之后把任意字符串强制转换成 victim。** 否决：点名 C2、干扰项、另一个 IPv4 或无法匹配的身份 token 的字符串必须保持未绑定。

**`victimRowHandles` 仍只收已捐出的身份。** 否决：先捐给域控、后来由受害端 IP 帧送出的 MAC 必须仍是句柄，省略持久化才能运行。

**改 `entityIdForIdentity`，让显式域控 `entity_id` 输给受害端 IP 帧。** 否决：本旋钮是句柄字符串强制转换。归属和角色标签保持不变。

**编造身份、对调 token，或接受将线索指定为 victim。** 否决：不编造槽位，对调仍未绑定，将线索指定为 victim 仍被拒绝。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC`／`DISTRACTOR_MAC`，以及 `lan-user`／`Lan User`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、`CLIENT_MAC`、`DISTRACTOR_MAC`、`lan-user`、`Lan User` 和 `lan-host`。当前绑定之后，带标签的 who `User Account: lan-user / Full Name: Lan User / MAC Address: CLIENT_MAC` 会强制转换并接受。点名受害端 IP 与主机名的句子 where 会强制转换并接受，包括 `The infected host was identified as <IP>, hostname "<hostname>"`。同样的字符串若还点名 C2 则保持未绑定。剩余的仅域控／网关 MAC 由[该剩余项规则](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)丢弃。没有身份 token 的无法匹配散文保持未绑定。强制转换之后，粘滞域控捐出让投影行为空时，省略的 mac／user 从受害端 IP 帧／会话客户端证据持久化。行上已有的 ip／hostname 保留。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一带标签／句子 `case_report` 先跑 `bind_relationship` 再跑 `case_report`。

## 后果

当前绑定加上带标签或句子包裹的 who/where 字符串，在剩余身份 token 是受害端行句柄时写出 5W1H 结案包。省略的 mac／user 随后可以补全粘滞域控行。剩余的仅域控／网关 MAC 不会让整串保持未绑定。点名 C2、干扰项用户或主机名、另一个 IPv4 或无法匹配剩余词的字符串仍以未绑定失败。将线索指定为 victim 仍被拒绝。
