# Agent Note: 跨已接受结案持久化每一个已绑定受害端行

Status: implemented

[English](2026-08-21-persist-every-bound-victim-row.md) | 中文

## 问题

一次线上双客户端收割绑定了两台受感染的 LAN 工作站，然后 CaseReport 只发布了一个 victim。后来接受的绑定点名了另一个 victim IPv4；该行被第一条已发布的 who/where 覆盖或折入其中。Chassis 的 Mission／closed-means 仍是单 victim 遗留（表格遗漏）。没有 hunt 的主机遗留和家族附加项是另一种持久化。

[持久化投影受害端行](2026-08-21-persist-projected-victim-slot.md) 会补全当前绑定行上省略的键。`investigation/report` 仍按最后一次写入一条 who/where。后来的结案或附加项回写会替换先前的 victim。

## 决策

当前绑定之后，持久化每一个已绑定受害端行。按 `entity_id` 折叠已发布的行。

`who`／`where` 仍是最近一次已接受结案的投影受害端行。当已发布两个或更多不同的 victim IPv4 时，`victims` 按首次出现保存那些行。单次绑定的结案省略 `victims`。后来接受的结案或当前绑定若点名不同 victim 则追加。后来对同一 victim 的结案更新该行，不编造重复行。`recordBind` 在已有结案包时把该绑定已补全的受害端行持久化到结案包上，并在没有结案包时不编造 5W1H。`foldReport` 从日志重建同样的行。省略槽位补全仍按每个 victim 从该 victim 的收割运行，包括[省略的 user](2026-08-21-persist-harvested-human-on-omitted-who.md) 和 [AD SRV 主机名跳过](2026-08-21-omit-ad-srv-locator-hostname.md)。绑定角色 infra、域控、网关和文件服务器行不会发布。不会编造用户、主机名或 MAC。

[LAN／网关／域控剩余项强制转换](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md) 和 [省略 AD SRV 定位器主机名](2026-08-21-omit-ad-srv-locator-hostname.md) 保持不变。`acceptedC2Ips`／`acceptedC2Domain`／extra-wan／Fastly／Cloudflare／CDN 后缀、Mission／Plan／cue-pending、拒绝 complete，以及家族持久化保持不变。Chassis 表格仍是单 victim 遗留。

测试使用合成 RFC1918／TEST-NET 替身。

## 备选方案

**继续按最后一次写入一条 who/where。** 否决：后来接受的绑定若点名不同 victim，就会丢掉已发布的行。

**把 who/where 改成数组。** 否决：单次绑定的 Easy as 123／fake-software 结案仍在 who/where 上发布一行受害端。

**在任何结案之前于绑定时编造 5W1H 结案包。** 否决：无结案持久化不编造 who/where。

**重调 LAN／网关／域控剩余项强制转换或 AD SRV 主机名省略。** 否决：此旋钮是已投影受害端行的持久化。

**把绑定角色 infra、域控、网关或文件服务器发布为受害端行。** 否决：每一行的 who/where 仍仅限 victim。

**同一 victim 再次结案时编造重复行。** 否决：该结案更新已有行。

**把线上案件的黄金 IP、MAC、主机名、用户或真实 AD 域写进 fixture 或注记。** 否决：测试使用 `10.0.10.2`／`10.0.10.8`、TEST-NET C2 `198.51.100.80`／`198.51.100.81`，以及域控／基础设施 `10.0.10.3`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 victim `10.0.10.2` 与 `10.0.10.8`、TEST-NET C2 `198.51.100.80`／`198.51.100.81`，以及域控／基础设施 `10.0.10.3`。一次绑定仍发布一行受害端。两次已接受结案且 victim IPv4 不同时，发布两行受害端（每个 victim 一行 who/where，且仅限 victim），包括从每个 victim 收割做省略槽位补全以及 AD SRV 跳过。对同一 victim 的第二次结案更新该行。基础设施保持不在。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一双绑定路径走 `bind_relationship` 再走 `case_report`，包括后来绑定之后、第二次结案之前就持久化第二个 victim。

## 后果

两次当前绑定且 victim IPv4 不同时，两行受害端都会发布。后来的不同 victim 不会替换第一条已发布的行。单次绑定结案仍是一行。同一 victim 再次结案更新该行。基础设施不会出现在 who/where 上。
