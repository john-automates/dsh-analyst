# Agent Note: 后来的受害端 IP hunt 收割到该 MAC 时覆盖域控／对等体戳记

Status: implemented

[English](2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md) | 中文

## 问题

线上 lumma-r18（`90eaf1c`）正确绑定了被引用的会话。结案栏 4/5。ip／hostname／user／full_name 已持久化。`mac` 没有。模型提交的域控／网关 MAC 保持不在。

黄金 MAC 已在账本上，第一次收割把 `evidence_id` 戳成域控 hunt 主体。后来的受害端 IP `eth.src` hunt 跑过了（过滤器 `(eth.src) and ip.src == <victim>`，字段 `eth.src`），并收割到同一 MAC。[受害端 IP 范围改戳](2026-08-21-restamp-victim-ip-scoped-eth-src.md) 只补缺少的 `evidence_id`。`recordIdentity`／`foldIdentities` 拒绝覆盖粘住的域控戳记。捐出于是把它当成域控范围，没有把 `mac` 持久化到 who／where。

只出现在域控／网关帧上的 MAC 必须保持不在。后来的域控／对等体收割不得覆盖已有的受害端戳记。

## 决策

限定在某个通信 IP 的受害端 IP `eth.src` hunt 或仅字段转储之后，即使第一次见到的行已有域控／对等体 `evidence_id`，也把该 MAC 改戳到该 IP。再经现有捐出和 `completeAcceptedSlot` 把 `mac` 持久化到 who／where。ip／hostname／user／full_name 保留。

`recordIdentity` 仍按 kind+value 得到一行。后来的 MAC 事件在新 id 是被绑定 victim 或 C2 通信 LAN IP、且现有 id 不是时覆盖 `evidence_id`。缺少的第一次戳记仍会补上。后来的域控／对等体戳记不会覆盖受害端或 C2 通信戳记。其他种类保留第一次非空戳记。

从未作为受害端 IP 帧上的 `eth.src` 出现、也不在限定于该 IP 的转储里的域控或网关 MAC 保持不在。“域控范围保持不在”指只出现在域控／网关帧上的 MAC，不是先在域控 hunt 主体下收割、后来又出现在受害端 IP 帧上的 MAC。

[受害端 IP 范围改戳](2026-08-21-restamp-victim-ip-scoped-eth-src.md) 仍拥有补缺少戳记。[MAC 通信 IP 戳记](2026-08-21-stamp-mac-evidence-from-talking-ip.md) 仍拥有同行捐出。[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 仍拥有省略补全。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体和空闲或域控 LAN 行。

## 备选方案

**继续只在 `evidence_id` 为空时改戳。** 否决：线上黄金 MAC 已经带着域控 hunt 主体戳记。仅字段转储的捐出要求 `evidence_id` 是 victim，粘住的域控戳记因此丢掉了 `mac`。

**让捐出把仅字段受害端 IP `eth.src` 转储当成受害端来源，而不改写账本行。** 否决：自动运行的转储文本只有 `eth.src: MAC`。范围在 hunt／`display_filter` 上，收割已经写成 `evidence_id`。把后来的戳记折进第一次见到的行，就是 [受害端 IP 范围改戳](2026-08-21-restamp-victim-ip-scoped-eth-src.md) 已经使用的改戳规则。

**用后来的域控／对等体戳记覆盖受害端或 C2 通信戳记。** 否决：正确的受害端戳记必须粘住。

**捐出从未作为受害端 IP 帧上 `eth.src` 出现、也不在限定于该 IP 的转储里的 MAC。** 否决：那些网卡不进入受害端行。

**编造 MAC、丢掉 ip／hostname／user／full_name、把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：持久化仍只复制已捐出的槽位。fixture（测试前置数据）是合成 LAN 客户端、TEST-NET 对等体和空闲或域控 LAN 行。

## 测试

`packages/analyst/investigation/tests/investigation.spec.ts` 在当前绑定（victim `10.0.10.2`）之后把 `CLIENT_MAC` 记成 `evidence_id=10.0.10.3`，再给出仅字段受害端 IP `eth.src` 转储。该行改戳成 `10.0.10.2`。后来对同一 MAC 的域控范围转储不会覆盖。日志里有当前绑定或 C2 通信行时，折叠会覆盖域控→受害端，并保留受害端→域控。主机名保留第一次非空戳记。

`packages/analyst/investigation/tests/bind.spec.ts` 先把 `CLIENT_MAC` 戳成 `10.0.10.3`，再改戳成 `10.0.10.2`，外加限定在域控的域控 MAC。当前绑定之后，省略 `mac` 的 who／where 持久化 `CLIENT_MAC`，并保留 ip／hostname／user／full_name。域控 MAC 保持不在。

## 后果

限定在受害端 IP 的仅字段 `eth.src` 转储在域控／对等体第一次戳记之后仍把该 MAC 归属到 victim。只出现在域控／网关帧上的 MAC 保持不在。后来的域控范围收割不会移动受害端戳记。同行通信 IP 捐出和省略键持久化保持不变。
