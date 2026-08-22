# Agent Note: 从剩余已收割工作站中省略 LAN 域控／文件服务器／网关角色主机名

Status: implemented

[English](2026-08-22-omit-lan-infra-role-hostnames-from-leftover.md) | 中文

## 问题

当前绑定之后，[在已收割 LAN 工作站仍未绑定时拒绝 complete](2026-08-21-refuse-complete-while-unbound-workstation.md) 会正确点名剩余的已收割工作站。同一份剩余列表也可能在该 IPv4 已有主机名或 MAC 时点名 LAN 域控、文件服务器或网关。那些主机是基础设施。诸如 `*-DC`、`*FILESERVER*`、`*FILE-SERVER*` 或 `gateway` 的 NetBIOS 或 DNS 角色名不是 AD SRV／DC 定位器，因此剩余项分类器把它当成工作站身份。

[拒绝 complete](2026-08-21-refuse-complete-while-unbound-workstation.md) 保持不变。Who/Where 之前先绑定保持不变。未绑定主机不会持久化到 who/where。

## 决策

`unboundHarvestedLanWorkstations` 即使那些 IPv4 已有主机名或 MAC，也省略域控／文件服务器／网关基础设施。剩余基础设施是绑定角色 `infra`、已经与 AD SRV／DC 定位器主机名关联的 IPv4，以及与 LAN 域控／文件服务器／网关角色主机名关联的 IPv4。第一个 NetBIOS／DNS 标签匹配 `*-dc`、`dc`、`*fileserver*`、`*file-server*` 或 `gateway`。工作站 `desktop-*` 不匹配。`.1` LAN IPv4 仅在已经作为网关或基础设施已知时才是基础设施。

`workstationIdentityOn` 不把那些角色名当成工作站身份。`completeDenyReason` 仍点名剩余的已收割工作站，且不被重调。剩余的已收割工作站仍拒绝 complete。只剩域控／网关／文件服务器等其他 LAN 身份的单 victim 案件在一次绑定之后可以 complete。拒绝文本不点名域控。who/where 持久化仍只使用 AD SRV 定位器省略。

测试使用合成 RFC1918／TEST-NET 替身。

## 备选方案

**把每一个非 AD SRV 主机名都当成工作站身份。** 否决：域控／文件服务器／网关角色名随后会出现在剩余列表和 complete 拒绝文本中。

**重调拒绝 complete、多 victim 持久化、LAN／DC 剩余项强制转换，或 who/where 上的 AD SRV 主机名省略。** 否决：此旋钮是剩余基础设施成员资格。

**把每一个 `.1` LAN IPv4 都当成网关。** 否决：`.1` 仅在已经作为网关或基础设施已知时才是基础设施。`.1` 上的剩余工作站仍拒绝 complete。

**自动绑定基础设施，或把未绑定主机持久化到 who/where。** 否决：Who/Where 之前先绑定保持不变。

**把线上案件的黄金 IP、MAC、主机名、用户或真实 AD 域写进 fixture 或注记。** 否决：测试使用已绑定 victim `10.0.10.2`（主机名 `lan-host`）、剩余工作站 `10.0.10.8`（主机名 `lan-host-b`）、域控 `10.0.10.3`（主机名 `lan-dc` 或 `TEST-DC`）、文件服务器 `10.0.10.4`（主机名 `lan-fileserver`）、网关 `10.0.10.1`（主机名 `gateway`），以及 TEST-NET C2 `198.51.100.80`。

## 测试

`packages/analyst/investigation/tests/bind.spec.ts` 钉住 `unboundHarvestedLanWorkstations`：一次绑定之后剩余的 `10.0.10.8`（`lan-host-b`）仍在；域控 `lan-dc`／`TEST-DC`、文件服务器 `lan-fileserver`／`lan-file-server` 和网关 `gateway` 即使带有 MAC 也是空剩余项；带工作站主机名 `desktop-test01` 的 `.1` IPv4 仍是剩余项；`requireCaseReport` 的 who/where 仍落在已绑定 victim `10.0.10.2` 上、不发布 `10.0.10.8`。`packages/analyst/investigation/tests/mindset.spec.ts` 钉住 `completeDenyReason`：剩余 `lan-host-b` 加上域控／文件服务器／网关角色名仍只点名该工作站；只有那些角色名剩余项时允许 complete。`packages/analyst/investigation/tests/investigation.spec.ts` 触发 `agent/turn-stopping`：一次绑定加上剩余 `lan-host-b` 以及域控／文件服务器／网关角色名会 steering（中途引导）点名该工作站的拒绝且不点名域控；一次绑定且只剩那些角色名剩余项则不做 steering。

## 后果

complete 拒绝的剩余文本点名已收割工作站，并省略域控／文件服务器／网关。只剩那些剩余项时，单 victim 结案仍可进行。拒绝 complete、who/where 持久化，以及 Who/Where 之前先绑定保持不变。
