# @deepseek-ai/dsh-analyst-tools

English | [中文](README.zh.md)

SOC/NSM tools for the `analyst` preset: `pcap_info`, `pcap_filter`, `logs`, and `case_report`. `bind_relationship` is registered by `ctx.investigation`. They consume the case directory and the BindRelationship close check.

## Tools

`pcap_info` runs `capinfos` (or `tshark -r -q` when capinfos is missing) against a capture inside the case. `pcap_filter` runs `tshark` with an optional display filter and `-e` fields; wrapping quotes on `display_filter` are stripped before `-Y`. A string `fields` value is one name or a comma/space-separated list and is coerced to `-e` names before the invalid-field check. Invalid tshark 4.4.16 fields (`ldap.sAMAccountName`, `ldap.displayName`, `kerberos.username`, `samr.full_name`) are rejected before spawn. Recommended fields: `kerberos.CNameString`, `samr.samr_UserInfo21.account_name`, `samr.samr_UserInfo21.full_name`. Field rows are labeled so identity harvest can read them. A sole `ip.dst` field dump (extra-wan) unique-collapses dests in first-seen order before the output clip. `logs` reads a text file in the case, optionally sliced by line. `case_report` appends a 5W1H packet after `bind_relationship`. `who` and `where` project from the bound victim entity row; the bound C2 plus victim-stamped extra-wan dests persist as optional `c2_ips`, omitting an IP whose evidenced hostname is a well-known CDN or update name; an unnamed extra-wan dest that survives those omits persists; a harvested C2 TLS SNI or DNS name evidenced on an attested dest persists as optional `c2_domain` when it is not CDN/update and is not a who/where hostname. A JSON object string with `entity_id`, or after a live bind a string whose leftover identity tokens are victim-row handles (labels, locator leftovers, sentence wrappers, wrapping ASCII quotes, a leftover MAC that talking-IP frames source only from a non-victim, and a leftover CIDR that contains the bound victim IP ignored; a multi-word full_name is one handle; donate or victim-IP evidence counts), is coerced before the free-text check. A string that names the c2, a distractor user or hostname, another IPv4, a CIDR that does not contain the victim, or unmatched leftover words stays unbound. A string that is only a DC/gateway-only MAC, or that has no remaining victim-row handle, stays unbound. An inverted victim/c2 close is denied. `write` / `edit` of case-root `report.md` is denied; close is `case_report` after BindRelationship. Hostname, user, and full name are not invented.

Helpers spawn with `execFile` (no shell), `cwd` set to the case directory, and the tool's `signal`.

## Configuration

```yaml
- id: analyst-tools
  name: '@deepseek-ai/dsh-analyst-tools'
  config:
    maxOutputChars: 32000
    commandTimeoutMs: 60000
    tsharkBin: tshark
    capinfosBin: capinfos
```

All four fields are Config. Unknown keys fail at load.

A function/namespace plugin: it exports `name` / `inject` / `apply` and no default.

Design: [analyst investigation preset](../../../.agents/notes/implemented/feature/2026-08-20-analyst-investigation-preset.md), [unique-collapse extra-wan before clip](../../../.agents/notes/implemented/bug-fix/2026-08-21-unique-collapse-extra-wan-before-clip.md).

## Model Experience

### Tool schemas

#### What the model sees

The model sees the generated [`pcap_info` / `pcap_filter` / `logs` / `case_report` / `bind_relationship` schemas](../../../docs/tool-catalog.md#deepseek-aidsh-analyst-tools). `pcap_filter`'s description names the valid tshark 4.4.16 fields and rejects the invalid ones. `bind_relationship` is registered by investigation and appears in the same catalog after that service mounts.

#### Token effect

Five stable schemas on every request where the tools are visible.

#### KV Cache effect

The catalog is stable for the life of the mount.

### pcap and log results

#### What the model sees

Successful calls return clipped text. `pcap_filter` with `fields` labels each column as `field: value` so harvest can record identities. A sole `ip.dst` field dump unique-collapses first-seen dests before that clip. A quoted `display_filter` such as `"ip.addr == 1.2.3.4"` becomes `-Y ip.addr == 1.2.3.4`. A string `kerberos.CNameString` becomes `-e kerberos.CNameString`. Invalid fields fail before tshark starts.

#### Token effect

Each result stays in history, clipped at `maxOutputChars`.

#### KV Cache effect

Results append after the reusable request prefix.

### Case report

#### What the model sees

`case_report` returns the projected victim slots plus what/when/why/how, optional `c2_ips`, and an optional harvested `c2_domain`, and records `investigation/report` on the session. A non-agent caller is rejected. Close is denied until a live bind exists; inverted `entity_id` and unmatched free-text who/where are refused. A JSON object string with `entity_id`, or after a live bind a string whose leftover identity tokens are victim-row handles (labels, locator leftovers, sentence wrappers, wrapping ASCII quotes, a leftover MAC that talking-IP frames source only from a non-victim, and a leftover CIDR that contains the bound victim IP ignored; a multi-word full_name is one handle; donate or victim-IP evidence counts), is coerced before the free-text check. A who/where `entity_id` that is a user, hostname, MAC, or full_name on the victim row projects to the bound victim address. The persisted who/where carry ip/mac/hostname/user/full_name from that projection, including a unique unaffiliated ledger identity and a MAC or hostname evidenced on the bound victim IP (same-line talking IP or a victim-IP-scoped field-only `eth.src` dump). After deny/coerce, keys the model omitted (including `mac`) are filled from that projected victim row. Omitted mac persists the unique ledger MAC that is not DC/gateway-only when a sticky DC donate or uniqueness left the row empty. Omitted user still persists from victim-IP evidence, or the unique harvested human user when machine SAMs blocked uniqueness donate. A submitted user, hostname, or full_name is kept when the row has no donated value and that identity does not donate to a different entity. After a live bind, omitted who/where fold sibling top-level identity keys (ip, mac, hostname, user, full_name) from the same case_report arguments into that submitted slot. A submitted human user is kept without a conversation-client stamp. A machine SAM ending in `$` is not persisted as user. A submitted mac is kept unless talking-IP frames source that MAC only from a non-victim. A model-offered IP does not replace the bound victim ip. `write` / `edit` of case-root `report.md` returns `close with case_report after BindRelationship.` Design: [BindRelationship before Who/Where](../../../.agents/notes/implemented/feature/2026-08-21-bind-relationship.md), [case_report victim-row entity_id](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-row-entity-id.md), [complete victim-row projection](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-victim-row-projection.md), [victim-IP-scoped donate](../../../.agents/notes/implemented/bug-fix/2026-08-21-donate-victim-ip-scoped-mac-hostname.md), [restamp victim-IP-scoped eth.src](../../../.agents/notes/implemented/bug-fix/2026-08-21-restamp-victim-ip-scoped-eth-src.md), [persist omitted victim-row keys](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-projected-victim-slot.md), [keep submitted victim-row identities](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-row-identities.md), [keep submitted victim MAC unless DC-only](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-mac-unless-dc-only.md), [complete omitted victim-row mac and user](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-omitted-victim-mac-user.md), [DC-only MAC is exclusive non-victim talking-IP](../../../.agents/notes/implemented/bug-fix/2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md), [stringified who/where](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-stringified-who-where.md), [victim-row handle strings](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-handle-strings.md), [labeled victim-row handle strings](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-labeled-victim-handle-strings.md), [DC/gateway-only MAC leftover](../../../.agents/notes/implemented/bug-fix/2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md), [locator/CIDR leftovers](../../../.agents/notes/implemented/bug-fix/2026-08-21-drop-locator-cidr-from-handle-string-coerce.md), [fold sibling identity keys](../../../.agents/notes/implemented/bug-fix/2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md), [persist harvested human on omitted who](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-harvested-human-on-omitted-who.md), [deny close-file writes](../../../.agents/notes/implemented/bug-fix/2026-08-21-deny-close-file-writes.md), [C2-domain hunt after live bind](../../../.agents/notes/implemented/bug-fix/2026-08-21-c2-domain-hunt-after-live-bind.md), and [extra-WAN C2 hunt after live bind](../../../.agents/notes/implemented/bug-fix/2026-08-21-extra-wan-c2-hunt-after-live-bind.md).

#### Token effect

The rendered 5W1H packet remains in conversation history.

#### KV Cache effect

The call extends the conversation normally.

## Known Limitations and Deferred Work

- `pcap_info` and `pcap_filter` require Wireshark CLI tools on PATH unless `tsharkBin` / `capinfosBin` point at another executable.
- Display-filter syntax is tshark's; this package only rejects the named invalid field list.
- `logs` reads the file as UTF-8 text and does not parse binary formats.
