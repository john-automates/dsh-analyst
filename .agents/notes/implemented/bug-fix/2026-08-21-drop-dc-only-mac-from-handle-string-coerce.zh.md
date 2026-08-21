# Agent Note: 从 who/where 句柄字符串强制转换中丢弃仅域控／网关 MAC 剩余项

Status: implemented

[English](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md) | 中文

## 问题

线上 fake-software r6（`mta-2025-01-22`，master `cd6c426`，在[带标签的句柄字符串强制转换](2026-08-21-case-report-labeled-victim-handle-strings.md)与[仅域控通信 IP 持久化](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md)之后）正确绑定了被引用的会话（LAN victim／非 LAN C2）。没有任何 `case_report` 被接受。结案调用都因未绑定被拒绝。提交的 who/where 是带标签或句子字符串，不是 `{ entity_id }`。where 点名了域控／网关网卡，外加剩余的受害端行句柄。

[带标签的句柄字符串强制转换](2026-08-21-case-report-labeled-victim-handle-strings.md) 只在每个剩余身份 token 都是受害端行句柄时接受 who/where 字符串。仅域控／网关 MAC 是无法匹配的剩余 token，所以整串保持未绑定。[仅域控通信 IP 持久化](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md) 从未运行，因为没有任何调用被接受。黄金客户端 MAC 仍粘滞在域控账本行上。

## 决策

当前绑定之后，`identityLikeTokens` 把剩余的冒号或短横线 MAC 抽成一个 token（冒号是 who/where 分隔符，按词切分会把它拆碎）。`isVictimHandleText` 随后丢弃通信 IP 帧只从非 victim 来源的剩余 MAC——与[持久化](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md)相同的仅域控／网关测试（`macIsDcOrGatewayOnly`）。剩余的受害端行句柄仍把字符串强制转换成 `{ entity_id: victim }`。随后已有的省略 mac 路径可以补上唯一不是仅域控／网关的客户端 MAC。

只含该仅域控／网关 MAC 的字符串仍保持未绑定。定位剩余词和包含被绑定 victim IP 的剩余 CIDR 会被[另行丢弃](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md)。LAN／网关／域控剩余项和剩余 LAN 基础设施 IPv4／域公告 token 由[另一规则丢弃](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md)。剩余的 C2 IPv4、干扰项用户或主机名、另一个剩余的具名非 infra IPv4，或不是字段标签／句子包裹／引号的无法匹配词仍保持未绑定。域控／网关网卡不会持久化到 who/where。不丢弃 ip、hostname、user 或 `full_name`。收割戳记、绑定接受／拒绝和 C2-domain 持久化保持不变。

漏洞在 `packages/analyst/investigation/src/bind.ts` 的 `isVictimHandleText`／`identityLikeTokens`／`coerceIdentitySlotArg`。将线索指定为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行，以及合成 `CLIENT_MAC` 对 `DISTRACTOR_MAC`。

## 备选方案

**继续要求每个剩余 token（包括仅域控／网关 MAC）都是受害端行句柄。** 否决：一张域控／网关网卡会在正确绑定之后毒化本应是受害端行的带标签或句子字符串。

**把剩余的仅域控／网关 MAC 当成受害端行句柄。** 否决：那会把域控／网关网卡持久化到 who/where。

**丢弃每个剩余 MAC，或在当前绑定之后强制转换任意剩余 token。** 否决：剩余的 C2 IPv4、干扰项用户或主机名、另一个非 victim IPv4 或无法匹配词必须保持未绑定。没有通信 IP 证据不是仅域控。

**用同样方式丢弃剩余的 ip、hostname、user 或 `full_name`。** 否决：那些剩余项仍用来区分 victim 与 C2。

**改收割戳记、绑定接受／拒绝或 C2-domain 持久化，让粘滞域控行变成 victim。** 否决：本旋钮是当前绑定之后的句柄字符串强制转换。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行，以及合成 `CLIENT_MAC`／`DISTRACTOR_MAC`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、`CLIENT_MAC`，以及只从空闲／域控 IP 讲话的 `DISTRACTOR_MAC`。当前绑定之后，带标签的 who 或句子 where 在点名受害端行句柄外加 `DISTRACTOR_MAC` 时强制转换并接受。持久化的 who/where 是受害端行；`DISTRACTOR_MAC` 不出现；唯一不是仅域控／网关的 `CLIENT_MAC` 可通过省略持久化补上。混入 C2 IPv4、干扰项用户、另一个非 victim IPv4 或无法匹配的剩余词仍保持未绑定。只含 `DISTRACTOR_MAC` 的字符串仍保持未绑定。将线索指定为 victim 仍被拒绝。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一混合带标签／句子 `case_report` 先跑 `bind_relationship` 再跑 `case_report`。

## 后果

当前绑定加上带标签或句子包裹的 who/where 字符串，在剩余身份 token 是受害端行句柄时写出 5W1H 结案包，即使混入仅域控／网关 MAC。省略持久化随后可以补上唯一不是仅域控／网关的客户端 MAC。域控／网关网卡不进入 who/where。C2 IPv4、干扰项用户或主机名、另一个 IPv4、无法匹配的剩余词，或只含该仅域控／网关 MAC 的字符串仍以未绑定失败。将线索指定为 victim 仍被拒绝。
