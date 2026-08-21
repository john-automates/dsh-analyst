# Agent Note: 从 who/where 句柄字符串强制转换中丢弃定位包裹与包含受害端的 CIDR

Status: implemented

[English](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md) | 中文

## 问题

线上 fake-software r7（`mta-2025-01-22`，master `a0c6a15`，在[带标签的句柄字符串强制转换](2026-08-21-case-report-labeled-victim-handle-strings.md)与[仅域控／网关 MAC 剩余项](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)之后）正确绑定了被引用的会话（LAN victim／非 LAN C2）。没有任何 `case_report` 被接受。结案调用都因未绑定被拒绝。提交的 who/where 是带标签或句子散文，不是 `{ entity_id }`。

[带标签的句柄字符串强制转换](2026-08-21-case-report-labeled-victim-handle-strings.md) 只在每个剩余身份 token 都是受害端行句柄时接受 who/where 字符串。定位剩余词（`Client`、`IP`、`located`、`at`、`on`、`network`）不在 `HANDLE_WRAPPER_WORDS` 里，所以通不过句柄检查。`/` 是 who/where 分隔符，因此包含 victim 的 CIDR 会被拆成剩余的非 victim IPv4（网络地址）外加剩余的前缀数字。这些剩余项会毒化本应正确的受害端行字符串。[省略持久化](2026-08-21-complete-omitted-victim-mac-user.md) 从未运行，因为没有任何调用被接受。

## 决策

当前绑定之后，`identityLikeTokens` 把定位剩余词 `client`／`ip`／`located`／`at`／`on`／`network` 当成包裹，而不是无法匹配的 token。它在分隔符切分之前把剩余的 IPv4／前缀 CIDR 抽成一个 token，以免 `/` 把它拆碎。`isVictimHandleText` 随后在该 CIDR 包含被绑定 victim IP 时丢弃它。剩余的受害端行句柄仍把字符串强制转换成 `{ entity_id: victim }`。

LAN／网关／域控剩余项和剩余 LAN 基础设施 IPv4／域公告 token 由[另一规则丢弃](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md)。剩余的 C2 IPv4、干扰项用户或主机名、另一个不是该包含受害端 CIDR 的剩余具名非 infra IPv4、不包含 victim 的 CIDR，或无法匹配的剩余词仍保持未绑定。没有剩余受害端行句柄的字符串仍保持未绑定，LAN／网关／域控丢弃之后的空剩余项除外。域控／网关网卡不会被持久化。不丢弃 ip、hostname、user 或 `full_name`。收割戳记、绑定接受／拒绝、省略 mac 持久化和 C2-domain 持久化保持不变。

漏洞在 `packages/analyst/investigation/src/bind.ts` 的 `isVictimHandleText`／`identityLikeTokens`／`HANDLE_WRAPPER_WORDS`。将线索指定为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC` 对 `DISTRACTOR_MAC`，以及包含该客户端的合成 LAN CIDR。

## 备选方案

**继续把定位剩余词和被拆碎的 CIDR 当成无法匹配的身份 token。** 否决：正确 victim IP 外的句子包裹，外加该 victim 所在子网 CIDR，会在正确绑定之后毒化句柄检查。

**把每个剩余 IPv4 或每个剩余 CIDR 都当成包裹。** 否决：剩余的 C2 IPv4、另一个非 victim IPv4，或不包含 victim 的 CIDR 必须保持未绑定。

**当前绑定之后把任意字符串强制转换成 victim。** 否决：无法匹配的剩余词和非 victim 身份必须保持未绑定。

**用同样方式丢弃剩余的 ip、hostname、user 或 `full_name`。** 否决：那些剩余项仍用来区分 victim 与 C2。

**改收割戳记、绑定接受／拒绝、省略 mac 持久化或 C2-domain 持久化，让散文结案变成 victim。** 否决：本旋钮是当前绑定之后的句柄字符串强制转换。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC`／`DISTRACTOR_MAC`，以及 `10.0.10.0/24`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、`CLIENT_MAC`、`DISTRACTOR_MAC`，以及 LAN CIDR `10.0.10.0/24`。当前绑定之后，带标签的 who `Client IP: <LAN> / MAC Address: CLIENT_MAC` 与句子 where `The client was located at <LAN> on the 10.0.10.0/24 network` 会强制转换并接受。持久化的 who/where 是受害端行；`DISTRACTOR_MAC` 不出现。混入 C2 IPv4、不包含 victim 的 CIDR（`172.16.0.0/12`）或无法匹配的剩余词仍保持未绑定。只含该包含受害端 CIDR 的字符串仍保持未绑定。已有的仅域控／网关 MAC 剩余项丢弃和将线索指定为 victim 的拒绝保持不变。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一组定位／CIDR `case_report` 先跑 `bind_relationship` 再跑 `case_report`。

## 后果

当前绑定加上带标签或句子包裹的 who/where 字符串，在剩余身份 token 是受害端行句柄时写出 5W1H 结案包，即使还留下定位包裹或包含 victim 的 CIDR。C2 IPv4、干扰项用户或主机名、另一个 IPv4、不包含 victim 的 CIDR、无法匹配的剩余词，或没有剩余受害端行句柄的字符串仍以未绑定失败。将线索指定为 victim 仍被拒绝。
