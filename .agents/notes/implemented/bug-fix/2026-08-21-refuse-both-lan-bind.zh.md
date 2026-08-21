# Agent Note: 拒绝两端都在 LAN 的 BindRelationship；c2 不能是 LAN

Status: implemented

[English](2026-08-21-refuse-both-lan-bind.md) | 中文

## 问题

线上 lumma-r15（`3c6d25c`）在[字符串化绑定强制转换](2026-08-21-bind-relationship-stringified-args.md)接受调用后，身份 5/5 结案。被引用的会话是指向域控的 Kerberos。绑定角色是 LAN victim／LAN 域控作为 `c2`，而不是受害端与恶意软件线索／观测地址的会话。`whitepepper.su` 和家族附加项没有落地。5 槽 who/where 条是从该域控会话上的捐出填满的。

[BindRelationship](../feature/2026-08-21-bind-relationship.md) 已经要求恰好一个 victim，并[拒绝将线索指定为 victim](2026-08-21-refuse-cue-as-victim.md)。它不要求被引用的会话包含线索／观测地址，并且接受把 `c2` 放在 LAN 域控上。

## 决策

强制转换之后，`resolveBind` 要求被引用的会话（`relationship` 的 src／dst）包含线索／观测地址（`isCueObservationAddr`：非 LAN 单播 IPv4）。两端都在 LAN 的会话（工作站↔域控的 Kerberos／SAMR／LDAP）保持未绑定。拒绝文本是 `unbound: cite the LAN host talking to the cue/observation address, not a LAN DC/AD service.` 它不编造恶意软件 C2 IP。

角色 `c2` 不能是 LAN 地址（`isLanIpv4`）。不会对调 token。[将线索指定为 victim](2026-08-21-refuse-cue-as-victim.md) 仍被拒绝。

两端都在 LAN 的拒绝不下发 hunt。[other-end](2026-08-21-other-end-hunt-on-cue-victim.md) 仍只用于在包含线索的会话上把线索指定为 victim。捐出、who/where 投影和垃圾用户拒绝保持不变。没有新的身份槽。

[BindRelationship](../feature/2026-08-21-bind-relationship.md) 仍拥有结案前绑定。scout、遗留报告禁令和新评测不在本次变更内。测试使用合成 LAN 客户端、TEST-NET 线索和 LAN 域控。

## 备选方案

**当线索是恶意软件 C2 时，仍接受指向域控的 Kerberos 作为被引用会话。** 否决：那会把 C2 绑到 LAN 域控／AD 服务。

**把 LAN 域控静默改成 `infra`、把线索改成 `c2`。** 否决：不会对调 token。拒绝绑定。

**在拒绝文本、hunt、提示词或测试里编造恶意软件 C2 IP。** 否决：模型必须引用已经包含线索的会话。

**在两端都在 LAN 的拒绝之后下发 `other-end` 或另一条编造 C2 的 hunt。** 否决：`other-end` 仍只用于把线索指定为 victim。

**只改方法论提示词或工具描述。** 否决：lumma-r15 仍会接受域控会话。

**把黄金身份写进提示词或测试、发明评测或改动 scout。** 否决：fixture 是合成 LAN 客户端、TEST-NET 线索和 LAN 域控。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET 线索（`198.51.100.80`）和 LAN 域控（`10.0.10.3`）。`10.0.10.2` ↔ `10.0.10.3` 且 `c2=10.0.10.3` 被拒绝，且不下发 `other-end`。`10.0.10.2` ↔ `198.51.100.80` 且 victim=`10.0.10.2`／c2=`198.51.100.80` 被接受。把线索指定为 victim 仍点名 other-end hunt。字符串化的 `endpoints` 加上 `dport` `"443"` 仍会强制转换，然后在受害端↔线索会话上接受。身份捐出测试保持通过。`packages/analyst/investigation/tests/investigation.spec.ts` 通过 `tools.execute` 拒绝两端都在 LAN 的调用，且不记录 `other-end`。

## 后果

工作站↔域控绑定保持未绑定。LAN `c2` 保持未绑定。当前的 LAN victim／线索 c2 绑定仍能结案。`other-end` 仍只在把线索指定为 victim 时触发。
