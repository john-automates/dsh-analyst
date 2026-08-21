# Agent Note: 第二个 C2 角色存在时仍把会话 dest 当作已绑定 C2

Status: implemented

[English](2026-08-21-bound-c2-conversation-dest-when-second-c2.md) | 中文

## 问题

[`boundC2Ipv4`](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) 要求恰好一个角色为 `c2` 的 IPv4。当前绑定有唯一 LAN victim、会话 dest 角色为 `c2`、且另一个端点也是 `c2` 时，`boundC2Ipv4` 为 undefined。extra-wan 不下发。持久化 `c2_ips` 丢掉会话 dest。extra-wan 的其他 WAN 过滤器没有可排除的 dest。

下发 extra-wan 或持久化该 dest 不要求唯一 C2 角色。两个 `c2` 角色且 dest 不是 `c2` 时不得发明 IP。

## 决策

当会话 dest 端点角色为 `c2` 且是非 LAN 单播 IPv4 时，`boundC2Ipv4` 就是该 dest，即使另一个端点也是 `c2`。否则仍取唯一角色为 `c2` 的 IPv4。两个 `c2` 角色且 dest 不是 `c2` 时返回 undefined。extra-wan 仍只在唯一 LAN victim 与该已绑定 C2 上下发。持久化 `acceptedC2Ips` 仍从该已绑定 dest 开始，并受现有 CDN／CF 省略约束。没有 victim 的绑定仍不下发 extra-wan。

[成功绑定后的 extra-WAN C2 hunt](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) 仍拥有 extra-wan 下发、dest 排除和已证明附加项。[持久化未点名 extra-wan 目的地址](2026-08-21-persist-unnamed-extra-wan-c2-dests.md) 仍拥有未点名持久化与 CDN／CF 省略。unique-collapse 裁切、refuse-complete、`acceptedC2Domain` 选择、身份遗留、who/where、Plan／Mission／cue-pending 和线上案件黄金 IP 不在本次变更内。测试使用合成 LAN 客户端、TEST-NET dest `198.51.100.80` 和第二 C2 `203.0.113.50`。

## 备选方案

**继续要求恰好一个角色为 `c2`。** 否决：dest 加上第二个 `c2` 会清空 `boundC2Ipv4`，extra-wan 不下发，持久化丢掉 dest。

**在没有已绑定 C2 时仍从 victim 下发 extra-wan。** 否决：extra-wan 过滤器需要排除 dest；持久化会没有 dest。

**dest 不是 `c2` 时把第一个角色为 `c2` 的端点当作已绑定。** 否决：两个 `c2` 角色且没有会话 dest 时不得发明 IP。

**持久化每一个角色为 `c2` 的端点。** 否决：这个旋钮是 dest 作为 `boundC2Ipv4`。盖上受害端戳的附加项仍留在已证明集合上。

**把 185.188 或 45.125 目的地址写进 harness 代码或测试。** 否决：测试使用 TEST-NET。

**重调未点名 extra-wan 持久化、unique-collapse、refuse-complete、`acceptedC2Domain` 或身份遗留。** 否决：那些旋钮保持不变。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 在额外 WAN `203.0.113.50` 也是 `c2` 时仍把 dest `198.51.100.80` 留作 `boundC2Ipv4`，对 LAN `10.0.10.2` 下发 extra-wan，把 dest 持久化到 `c2_ips`，在 dest 为 `infra` 且另两个端点为 `c2` 时返回 undefined，并在 dest 为 `infra` 且只有一个唯一 `c2` 时仍下发 extra-wan。`investigation.spec.ts` 在该双 C2 绑定之后为 dest 下发 extra-wan 和 `c2-domain`。`analyst-tools/tests/tools.spec.ts` 把 dest 留在 `case_report` 的 `c2_ips` 上。唯一 C2、未点名持久化和 CDN／CF 省略保持不变。

## 后果

当前绑定把 dest 标为 `c2` 且另有一个 `c2` 时，仍会 hunt 额外 WAN 目的地址，并能持久化该 dest。两个 `c2` 角色且没有会话 dest 时不发明地址。who/where 仍是受害端行。
