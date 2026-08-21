# Agent Note: 从 who/where 句柄字符串强制转换中丢弃 LAN／网关／域控剩余项

Status: implemented

[English](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md) | 中文

## 问题

线上 fake-software r26（`mta-2025-01-22`，master `4558993`，在[定位／CIDR 剩余项](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md)、[仅域控／网关 MAC 剩余项](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)与[在省略的 who 上持久化已收割的人类 user](2026-08-21-persist-harvested-human-on-omitted-who.md)之后）正确绑定了被引用的会话（LAN victim／非 LAN C2）。没有任何 `case_report` 被接受。结案调用都因未绑定被拒绝。提交的 where 是 LAN／网关／域控／AD 域散文外加剩余的网关／域控 IPv4，不是 `{ entity_id }`。模型还混入了剩余的仅域控／网关 MAC。

[定位／CIDR 剩余项](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md) 把 `client`／`ip`／`located`／`at`／`on`／`network` 当成包裹，并丢弃包含被绑定 victim IP 的剩余 CIDR。[仅域控／网关 MAC 剩余项](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md) 丢弃通信 IP 帧只从非 victim 来源的剩余 MAC。LAN／网关／域控／AD 域角色词不在 `HANDLE_WRAPPER_WORDS` 里。剩余的网关／域控 IPv4 仍是无法匹配的 token。这些剩余项会在正确绑定之后毒化本应正确的结案。[省略持久化](2026-08-21-complete-omitted-victim-mac-user.md) 从未运行，因为没有任何调用被接受。

## 决策

当前绑定之后，`identityLikeTokens` 把 LAN／网关／域控／AD 域剩余词 `lan`／`gateway`／`dc`／`ad`／`domain`／`workgroup`／`controller` 当成包裹。`isVictimHandleText` 随后丢弃绑定角色为 `infra` 的剩余 LAN IPv4，或通信 IP 帧从该 IPv4 来源仅域控／网关 MAC、且该 IPv4 不是剩余的具名非 infra 绑定句柄的剩余 LAN IPv4。它丢弃不是受害端行句柄、也不是 C2 戳记（已证明 C2 目的地址，或捐给非 LAN 实体）的剩余带点名称。剩余的受害端行句柄仍把字符串强制转换成 `{ entity_id: victim }`。这些丢弃之后若留下空剩余项，并且出现过那些包裹或剩余 LAN 基础设施 IPv4／域公告 token，则强制转换成受害端行。持久化的是投影受害端行。域控／网关网卡不会被持久化到 who/where。

剩余的 C2 IPv4、剩余的带 C2 戳记 DNS 名、干扰项用户或主机名、另一个剩余的具名非 infra IPv4、不包含 victim 的 CIDR，或无法匹配的剩余词仍保持未绑定。只含该仅域控／网关 MAC、或只含该包含受害端 CIDR、且没有 LAN／网关／域控／AD 域包裹或剩余 LAN 基础设施 IPv4 的字符串仍保持未绑定。不会列出线上案件主机名或 IPv4。不丢弃作为剩余句柄的 ip、hostname、user 或 `full_name`。收割戳记、绑定接受／拒绝、省略持久化和 C2-domain 持久化保持不变。

漏洞在 `packages/analyst/investigation/src/bind.ts` 的 `isVictimHandleText`／`identityLikeTokens`／`HANDLE_WRAPPER_WORDS`。将线索指定为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC` 对 `DISTRACTOR_MAC`、合成网关 IPv4，以及合成带点 AD 域 token。

## 备选方案

**继续把 LAN／网关／域控／AD 域剩余项当成无法匹配的身份 token。** 否决：角色包裹外加剩余的网关／域控 IPv4 会在正确绑定之后毒化句柄检查。

**把每个剩余 LAN IPv4 都当成包裹。** 否决：剩余的具名非 infra 绑定端点，包括作为 who/where 提交的空闲 LAN IPv4，必须保持未绑定。

**把每个剩余带点名称都当成包裹。** 否决：剩余的带 C2 戳记 DNS 名必须保持未绑定。

**当前绑定之后把任意字符串强制转换成 victim。** 否决：无法匹配的剩余词和剩余的非 victim 句柄必须保持未绑定。

**用同样方式丢弃剩余的 ip、hostname、user 或 `full_name`。** 否决：那些剩余项仍用来区分 victim 与 C2。

**改收割戳记、绑定接受／拒绝、省略持久化或 C2-domain 持久化，让散文结案变成 victim。** 否决：本旋钮是当前绑定之后的句柄字符串强制转换。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、合成 `CLIENT_MAC`／`DISTRACTOR_MAC`、网关 `10.0.10.1`，以及 `ad.example.lan`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、网关 `10.0.10.1`、基础设施 `10.0.10.4`、`CLIENT_MAC`、`DISTRACTOR_MAC`，以及 `ad.example.lan`。当前绑定未把域控／网关点名为非 infra 端点时，where `ad.example.lan LAN, gateway 10.0.10.1, DC 10.0.10.3` 外加 `DISTRACTOR_MAC` 会强制转换并接受。只含包裹的 `LAN, gateway, DC` 会强制转换。绑定角色 `infra` 的剩余 IPv4 会强制转换。持久化的 who/where 是受害端行；`DISTRACTOR_MAC`、网关／域控 IPv4 和 AD 域 token 不出现。混入 C2 IPv4、剩余的带 C2 戳记 DNS 名、干扰项用户或无法匹配的剩余词仍保持未绑定。只含 `DISTRACTOR_MAC` 或只含包含受害端 CIDR 的字符串仍保持未绑定。已有的定位／CIDR、仅域控／网关 MAC 剩余项丢弃、带标签句柄强制转换，以及将线索指定为 victim 的拒绝保持不变。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一组 LAN／网关／域控 `case_report` 先跑 `bind_relationship` 再跑 `case_report`。

## 后果

当前绑定加上 who/where 字符串，在剩余身份 token 是受害端行句柄时写出 5W1H 结案包，即使还留下 LAN／网关／域控／AD 域包裹、剩余 LAN 基础设施 IPv4、剩余域／工作组公告，或剩余的仅域控／网关 MAC。这些丢弃之后的空剩余项会强制转换成投影受害端行。C2 IPv4、剩余的带 C2 戳记 DNS 名、干扰项用户或主机名、另一个剩余的具名非 infra IPv4、无法匹配的剩余词，或只含该仅域控／网关 MAC、或只含该包含受害端 CIDR 的字符串仍以未绑定失败。将线索指定为 victim 仍被拒绝。
