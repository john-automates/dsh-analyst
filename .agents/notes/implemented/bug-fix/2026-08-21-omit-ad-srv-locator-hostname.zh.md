# Agent Note: 省略受害端 hostname 持久化中的 AD SRV／DC 定位器名

Status: implemented

[English](2026-08-21-omit-ad-srv-locator-hostname.md) | 中文

## 问题

线上 fake-r27 正确绑定了被引用的会话（LAN victim / 非 LAN C2）并接受了 `case_report`。身份遗留 3/4：IP／MAC／user HIT。hostname 遗留：底盘把 AD SRV／DC 定位器名（`_ldap._tcp…._sites.dc._msdcs.…`）发布到已提交的工作站主机名之上。

[受害端 IP 范围捐出](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) 把 hunt 主体 `evidence_id` 是被绑定 victim IP 的每一个主机名都归属过去。因此限定在受害端的名称服务转储会捐出在该 IP 上收割到的 AD SRV 查询。`projectVictimSlot` 的种类优先接着把该定位器复制为 hostname。[持久化省略的受害端行键](2026-08-21-persist-projected-victim-slot.md) 在[保留提交](2026-08-21-keep-submitted-victim-row-identities.md) 之前复制已捐出的投影键，所以提交的工作站主机名会输给已捐出的定位器。who/where 以 JSON 对象到达时，[LAN／网关／域控剩余项](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md) 保持空闲。

## 决策

当前绑定之后，who/where 的 hostname 从不是 AD SRV／DC 定位器名（`_ldap._tcp…`、`_msdcs.`、`_sites.dc.`、`_service._tcp`／`_udp`）。

`projectVictimSlot` 的种类优先跳过这些定位器，方式与跳过作为 user 的机器 SAM 相同。`completeAcceptedSlot` 把已捐出的定位器视为未捐出，以便保留提交的工作站主机名。省略的 hostname 持久化唯一已收割的工作站主机名（忽略定位器）。只收割到该定位器时 hostname 保持省略。提交的定位器保持不在，并且不会回落到该收割。who/where 仍只属于受害端。不编造工作站主机名。

唯一性捐出仍计算每一个未归属主机名，包括定位器。[LAN／网关／域控剩余项](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md)、[在省略的 who 上持久化已收割的人类 user](2026-08-21-persist-harvested-human-on-omitted-who.md)、authenticatoor／`acceptedC2Domain`／`acceptedC2Ips`、extra-wan、Fastly／Cloudflare／CDN 后缀、Mission／Plan／cue-pending 和拒绝 complete 保持。收割仍把定位器名记入账本。线索作为 victim 仍被拒绝。

## 备选方案

**保持种类优先的 hostname 捐出，并让已捐出的定位器覆盖提交的工作站名。** 否决：限定在受害端的名称服务转储会在正确绑定之后把 AD SRV 发布为 who/where 的 hostname。

**重调 LAN／网关／域控剩余包裹，让 JSON 受害端行结案丢掉定位器。** 否决：此旋钮是拒绝／强制转换之后的持久化选择。线上遗漏以 JSON 对象到达，不是剩余自由文本。

**改唯一性捐出，让工作站主机名在定位器也存在时获胜。** 否决：此旋钮是已接受结案包上的持久化。归属和捐出保持不变。提交的定位器必须仍保持不在，而不是输给已捐出的工作站。

**在收割时丢掉 AD SRV 名。** 否决：hostname 的实体优先在持久化里。账本对定位器查询的收割保持。

**没有工作站名时把 AD SRV／DC 定位器作为受害端 hostname 持久化。** 否决：定位器不是工作站主机名。

**只收割到定位器时编造工作站主机名。** 否决：不编造槽位。

**把线上案件主机名、IP 或真实 AD 域写进 harness 代码或测试、发明评测，或重调 extra-wan／authenticatoor／Fastly。** 否决：fixture 是合成 LAN 客户端、TEST-NET C2、空闲或域控 LAN 行、工作站 `desktop-test01`／`lan-host`，以及 AD SRV `_ldap._tcp.default-first-site-name._sites.dc._msdcs.ad.example.lan`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 使用合成 LAN 客户端（`10.0.10.2`）、TEST-NET C2（`198.51.100.80`）、空闲或域控行（`10.0.10.3`）、工作站 `desktop-test01`／`lan-host`，以及 AD SRV `_ldap._tcp.default-first-site-name._sites.dc._msdcs.ad.example.lan`。当前绑定之后，账本先捐出该 SRV 再加上工作站时，把工作站持久化到 who/where，包括 where 以 JSON 提交工作站而 who 省略 hostname 的情况。当 SRV 也存在而导致唯一性捐出让该行为空时，省略的 hostname 持久化唯一已收割的工作站。只收割到该 SRV 的案件让 hostname 保持省略，并且不编造工作站名。提交的 SRV 保持不在。线索作为 victim 仍被拒绝。`packages/analyst/analyst-tools/tests/tools.spec.ts` 用同一提交工作站和仅定位器的结案走 `bind_relationship` 再走 `case_report`。

## 后果

当前绑定加上提交或已收割的工作站主机名，即使 AD SRV／DC 定位器也捐出，也会把该名写到 who/where。定位器从不作为受害端 hostname 持久化。只收割到定位器时 hostname 保持省略。唯一性捐出、剩余项强制转换、省略的 user 和线索作为 victim 保持。
