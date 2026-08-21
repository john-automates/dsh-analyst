# Agent Note: 在裁切之前对 extra-wan 目的地址按首次出现去重

Status: implemented

[English](2026-08-21-unique-collapse-extra-wan-before-clip.md) | 中文

## 问题

成功绑定之后，[`extra-wan`](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) 猎取受害端的其他 WAN 目的地址（`ip.src ==` 该 victim，字段 `ip.dst`）。`pcap_filter` 先按 `maxOutputChars`（默认 32000）裁切 tshark 原始 stdout，再给行加标签。受害端→WAN 转储若有数千行重复目的地址，会超过该裁切。后来首次出现的目的地址仍在 pcap 中，也匹配 extra-wan 过滤器，但不会成为会话命中。躲过 CDN／CF 省略的未点名 extra-wan 目的地址会持久化（[持久化未点名 extra-wan 目的地址](2026-08-21-persist-unnamed-extra-wan-c2-dests.md)）。who/where 仍只属于受害端。这个旋钮是 hunt 可见性，不是放宽持久化。

提高 `maxOutputChars` 会把逐包重复留在历史里。裁切之后再去重无法找回裁切已经丢掉的目的地址。

## 决策

`pcap_filter` 在输出裁切之前，按首次出现顺序对 extra-wan 的 `ip.dst` 去重。extra-wan 是唯一字段恰好为 `ip.dst` 的 hunt。其他 hunt（`eth-src`、`name-service`、`kerberos-cname`、`samr-userinfo`、`other-end`、`c2-domain`）仍保持逐包。extra-wan 的显示过滤器和字段不变。`maxOutputChars` 仍是 32000。当去重后的文本仍超过上限时，裁切仍作用于去重结果。

未点名的 extra-wan 目的地址可以成为会话命中。那些目的地址的持久化见[持久化未点名 extra-wan 目的地址](2026-08-21-persist-unnamed-extra-wan-c2-dests.md)。who/where 仍是受害端行。不列出线上案件的黄金 IP。测试使用 TEST-NET 额外地址 `203.0.113.10` 和 `203.0.113.99`。

## 备选方案

**提高 `maxOutputChars`，让后来的逐包目的地址留下来。** 否决：extra-wan 有用的结果是唯一目的地址。更大的逐包转储会把重复留在历史里。

**对每个 hunt 字段转储都去重。** 否决：身份 hunt 和 `other-end` 需要逐包行。extra-wan 是目的地址清单。

**在 `clipOutput` 之后再去重。** 否决：首次出现落在裁切之后的目的地址永远不会出现。

**把线上案件的目的地址写进 harness 代码或测试。** 否决：测试使用 TEST-NET 额外地址。

**放宽持久化，让未点名 extra-wan 目的地址进入 `c2_ips`。** 否决：这个旋钮是 hunt 可见性。持久化仍只含已证明目的地址。

**改动身份遗留、authenticatoor.org 选择、CDN／CF 省略、Plan／Mission 门或 cue-pending。** 否决：那些遗留是分开的。

## 测试

`packages/analyst/analyst-tools/tests/tools.spec.ts` 对仅含 `ip.dst` 的转储去重，使首次出现超过裁切预算的目的地址带上标签，保持首次出现顺序，并在去重结果仍超过预算时继续裁切；`ip.src`（`other-end`）转储仍逐包，因此该晚到目的地址保持隐藏。`packages/analyst/investigation/tests/hunts.spec.ts` 钉住 extra-wan 字段为 `ip.dst`，并保持其他 hunt 不使用该单独字段。

## 后果

extra-wan 会话命中包含后来首次出现的 WAN 目的地址，且不提高输出上限。未点名目的地址的持久化见[持久化未点名 extra-wan 目的地址](2026-08-21-persist-unnamed-extra-wan-c2-dests.md)。who/where 仍是受害端行。超过 `maxOutputChars` 的唯一目的地址列表仍会被裁切。
