# Agent Note: 把限定在受害端 IP 的 eth.src 改戳到受害端行

Status: implemented

[English](2026-08-21-restamp-victim-ip-scoped-eth-src.md) | 中文

## 问题

线上 lumma-r17（`e964637`）正确绑定了被引用的会话（victim `10.1.21.58`／c2 `153.92.1.49`）。结案栏 4/5。[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 补全了 ip／hostname／user／full_name。`mac` 没有补上。黄金 MAC 只在账本上，没有 `evidence_id`。受害端 IP 的 `eth.src` hunt 跑过了，但转储同一行没有 `ip.src`／出站／ARP，所以 [通信 IP 捐出](2026-08-21-stamp-mac-evidence-from-talking-ip.md) 没有触发。账本上三个 MAC 挡住了唯一未归属捐出。持久化只写已捐出的受害端 IP MAC，因此什么也没写。域控和网关 MAC 保持不在已接受的 who/where 上。

限定在受害端 IP 的仅字段 `eth.src` 转储不会戳通信 IP `evidence_id`（行上没有 `ip.src`）。该 MAC 的第一次收割未归属。捐出要求同一行 `ip.src` 或唯一性。`recordIdentity` 按 kind+value 唯一，留着空的第一次戳记。绑定之后，该 MAC 从未归属到受害端行。

## 决策

当前绑定之后，把受害端 IP hunt 里的 `eth.src` 改戳到受害端行，再把该 mac 持久化到 who/where。

限定在某个 IPv4 的 `eth-src` hunt 或转储（`scopeIp`，`display_filter` 为 `ip.addr`／`ip.src ==` 该 IP）在行上没有通信 IP 时，把收割到的 `eth.src` 的 `evidence_id` 写成该 IP。行上有 `ip.src`、出站 `ip → peer` 或 ARP `is at` 时，通信 IP 仍胜出。当前绑定之后，若该 IP 是 victim，该 MAC 捐给受害端行。

全账本唯一性和第一次收割缺少 `evidence_id`，不能挡住出现在受害端 IP 帧上或限定在受害端 IP 的 `eth.src` 转储里的 MAC。`recordIdentity` 仍按 kind+value 得到一行；后来的事件可以补上缺少的 `evidence_id`。

从未共享那些受害端 IP 帧或受害端范围转储的域控或网关 MAC 保持不在。限定在域控的 `eth-src` hunt 不把那些 MAC 捐给 victim。

已接受的 who/where 仍是该投影行的 `completeAcceptedSlot`。模型省略 `mac` 时仍持久化已捐出的 mac。ip／hostname／user／full_name 保留。两端都在 LAN 的拒绝和绑定强制转换保持不变。不会编造槽位。

[MAC 通信 IP 戳记](2026-08-21-stamp-mac-evidence-from-talking-ip.md) 仍拥有同行捐出。[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 仍拥有省略补全。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 对等体和 LAN 域控。

## 备选方案

**继续拒绝在每一份仅字段 `eth.src` 转储上戳 hunt 主体 `evidence_id`。** 否决：限定在受害端 IP 的仅字段转储就是点名通信 IP 的 hunt。`evidence_id` 留空会让捐出依赖同一行 `ip.src` 或唯一性，线上转储给不了这些。

**保持 `recordIdentity` 按 kind+value 唯一且不改戳，改让捐出从证据文本解析 hunt 过滤器。** 否决：自动运行的转储文本只有 `eth.src: MAC`。范围在 hunt／`display_filter` 上，收割已经以 `scopeIp` 收到。把后来的 `evidence_id` 折进第一次见到的行，就是在记录该范围。

**用后来的范围转储覆盖已有的通信 IP 或域控 `evidence_id`。** 否决：行上仍是通信 IP 胜出。域控范围的第一次戳记保留；后来的帧把该 MAC 从来自 victim 的方向送出时，捐出已经忽略它。本次变更只补第一次收割缺少的 `evidence_id`。

**捐出从未出现在受害端 IP 帧上、也不在限定于受害端 IP 的转储里的域控或网关 MAC。** 否决：那些网卡不进入受害端行。

**编造 MAC、丢掉 ip／hostname／user／full_name、把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：持久化仍只复制已捐出的槽位。fixture（测试前置数据）是合成 LAN 客户端、TEST-NET 对等体和 LAN 域控。

## 测试

`packages/analyst/investigation/tests/harvest.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET 对等体（`198.51.100.80`）和 LAN 域控（`10.0.10.3`）。`scopeIp=10.0.10.2` 的仅字段 `eth.src` 转储戳成该 IP。行上有 `ip.src` 时通信 IP 仍胜出。同行捐出保持不变。

`packages/analyst/investigation/tests/bind.spec.ts` 先把 `CLIENT_MAC` 收割成没有 `evidence_id`，再给出 `scopeIp=10.0.10.2` 的仅字段 `eth.src: CLIENT_MAC` 转储，外加限定在域控的域控 MAC。当前绑定之后，省略 `mac` 的 who/where 持久化 `CLIENT_MAC`。域控 MAC 保持不在。三个未归属 MAC 都不捐出，除非其中一个出现在限定于受害端 IP 的转储上。

`packages/analyst/investigation/tests/investigation.spec.ts` 先记录没有 `evidence_id` 的 `CLIENT_MAC`，再由限定范围的 `pcap_filter` 仅字段转储给该行改戳。后来的域控范围改戳不会覆盖受害端戳记。

## 后果

限定在受害端 IP 的仅字段 `eth.src` 转储在绑定之后把该 MAC 归属到 victim，即使第一次收割没有 `evidence_id`、账本上还有其他 MAC。限定在域控的转储不把它的 MAC 捐给 victim。同行通信 IP 捐出和省略键持久化保持不变。
