# Agent Note: 仅域控 MAC 须为排他的非 victim 通信 IP

Status: implemented

[English](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md) | 中文

## 问题

线上 fake-software r5（`mta-2025-01-22`）正确绑定了被引用的会话（LAN victim / 非 LAN C2）。`case_report` 接受了结构化 who/where。User、hostname 和 ip 已持久化。MAC 失败。

提交的 where 带有 mac。持久化的 who/where 没有 mac。该提交 MAC 粘在域控账本上（第一次收割／捐出把域控 `evidence_id`／`entity_id` 戳上）。`completeAcceptedSlot` 把它当作没有受害端 IP 证据而剥掉。省略 mac 的补全也返回空。真正的域控／网关网卡保持不在。

[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) 已经写明除非仅域控／网关否则保留。它的仅域控测试要求同行通信 IP（`eth.src` + `ip.src` victim）或限定在受害端 IP 的 `eth.src` 转储为正例。[补全省略的受害端行 mac 与 user](2026-08-21-complete-omitted-victim-mac-user.md) 使用同一正例测试。缺少那些帧被当成仅域控，因此粘滞的第一次捐出隐藏了通信 IP 从未证明为仅域控的网卡。

## 决策

当前绑定之后，除非通信 IP 帧只从非 victim 来源该 MAC（从未作为被绑定 victim IP 上的 `eth.src`；也不是该 victim 的网卡），否则在受害端 who/where 上持久化提交的 mac。所有权测试不使用账本 `evidence_id`、`entity_id` 或第一次捐出。没有通信 IP 证据不是仅域控。

省略的 mac 用同一规则补全：持久化唯一不是仅域控／网关的账本 MAC。粘滞的域控戳记不得隐藏未被证明为仅域控的网卡。若干同样未被证明的 MAC 都不持久化。

只从域控／空闲主机讲话的提交或省略域控／网关网卡保持不在。不丢掉 ip、hostname、user 或 `full_name`。不用模型提供的 IP 替换被绑定的 victim ip。收割戳记、绑定接受／拒绝和 C2-domain 持久化保持不变。

`offeredMacEvidencedOnVictim`／`omittedMacEvidencedOnVictim` 使用通信 IP 排他性。`evidencedOnVictimIp` 仍拥有捐出和限定在受害端 IP 的转储归属。[句柄字符串强制转换](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md) 对带标签或句子 who/where 里的剩余 MAC 使用同一仅域控／网关测试。

[除非仅出现在域控／网关帧上，否则保留提交的受害端 MAC](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) 仍在非仅域控时保留提交的 mac；本注记拥有仅域控测试。[补全省略的受害端行 mac 与 user](2026-08-21-complete-omitted-victim-mac-user.md) 仍补全省略的 mac；未被证明的 MAC 之间的唯一性仍是散落防护。线索作为 victim 仍被拒绝。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行，以及合成 `CLIENT_MAC` 与域控／网关 `DISTRACTOR_MAC`。

## 备选方案

**继续要求同行受害端 IP 通信行或限定在受害端 IP 的转储，才持久化提交或省略的 MAC。** 否决：粘在域控上、没有受害端 IP 转储的客户端网卡会被剥掉，即使通信 IP 从未只从非 victim 来源它。

**把账本 `evidence_id`、`entity_id` 或第一次捐出当作仅域控。** 否决：那些戳记是收割／捐出归属，不是通信 IP 所有权。

**把没有通信 IP 证据当作仅域控。** 否决：仅域控是排他的非 victim 通信 IP。缺少帧不能证明网卡是域控或网关。

**把账本上每一个省略的 MAC 复制到受害端行。** 否决：若干同样未被证明的 MAC 不得从那一堆里编造一个。

**改收割戳记、绑定接受／拒绝、捐出或 C2-domain 持久化，让粘滞的域控行变成 victim。** 否决：此旋钮是当前绑定之后已接受 who/where 的持久化。

**丢掉 ip、hostname、user 或 `full_name`，或把模型提供的 IP 复制到被绑定的 victim ip 上。** 否决：那些槽位已经持久化。

**把黄金身份写进 harness 代码或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行，以及合成 `CLIENT_MAC`／`DISTRACTOR_MAC`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、`CLIENT_MAC` 和 `DISTRACTOR_MAC`。当前绑定之后，先捐给域控的客户端 MAC（`evidence_id` 和 `entity_id` 为空闲／域控）在证据文本只有域控通信帧、只有会话或为空时，仍持久化到提交的 where 和省略的 who。只从空闲／域控 IP 讲话的提交域控 MAC 保持不在。若干同样未被证明的 MAC 在省略的 who 上都不持久化。User、hostname 和 ip 仍持久化。捐出、改戳、唯一性和域控网卡保持不在的覆盖仍在。`packages/analyst/analyst-tools/tests/tools.spec.ts` 在没有通信 IP 帧时，用同一唯一省略的客户端 MAC 走 `bind_relationship` 再走 `case_report`。

## 后果

当前绑定加上提交的或唯一省略的客户端 MAC 会写出该 mac，即使粘滞的域控捐出让投影行为空，且证据文本没有受害端 IP `eth.src` 行。只从域控／空闲主机讲话的域控／网关网卡仍保持不在。若干未被证明的 MAC 仍都不持久化。被绑定的 victim ip 保持不变。提交的 user／hostname／`full_name` 和已捐出的槽位保留。收割戳记和绑定接受／拒绝保持不变。
