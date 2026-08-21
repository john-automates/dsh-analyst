# @deepseek-ai/dsh-analyst-tools

English | [中文](README.zh.md)

SOC/NSM tools for the `analyst` preset: `pcap_info`, `pcap_filter`, `logs`, and `case_report`. `bind_relationship` is registered by `ctx.investigation`. They consume the case directory and the BindRelationship close check.

## Tools

`pcap_info` runs `capinfos` (or `tshark -r -q` when capinfos is missing) against a capture inside the case. `pcap_filter` runs `tshark` with an optional display filter and `-e` fields; wrapping quotes on `display_filter` are stripped before `-Y`. A string `fields` value is one name or a comma/space-separated list and is coerced to `-e` names before the invalid-field check. Invalid tshark 4.4.16 fields (`ldap.sAMAccountName`, `ldap.displayName`, `kerberos.username`, `samr.full_name`) are rejected before spawn. Recommended fields: `kerberos.CNameString`, `samr.samr_UserInfo21.account_name`, `samr.samr_UserInfo21.full_name`. Field rows are labeled so identity harvest can read them. `logs` reads a text file in the case, optionally sliced by line. `case_report` appends a 5W1H packet after `bind_relationship`. `who` and `where` project from the bound victim entity row; a JSON object string with `entity_id` is coerced to that object before the free-text check. Free-text who/where and an inverted victim/c2 close are denied. Hostname, user, and full name are not invented.

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

Design: [analyst investigation preset](../../../.agents/notes/implemented/feature/2026-08-20-analyst-investigation-preset.md).

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

Successful calls return clipped text. `pcap_filter` with `fields` labels each column as `field: value` so harvest can record identities. A quoted `display_filter` such as `"ip.addr == 1.2.3.4"` becomes `-Y ip.addr == 1.2.3.4`. A string `kerberos.CNameString` becomes `-e kerberos.CNameString`. Invalid fields fail before tshark starts.

#### Token effect

Each result stays in history, clipped at `maxOutputChars`.

#### KV Cache effect

Results append after the reusable request prefix.

### Case report

#### What the model sees

`case_report` returns the projected victim slots plus what/when/why/how, and records `investigation/report` on the session. A non-agent caller is rejected. Close is denied until a live bind exists; inverted `entity_id` and free-text who/where are refused. A JSON object string with `entity_id` is coerced to that object before the free-text check. A who/where `entity_id` that is a user, hostname, MAC, or full_name on the victim row projects to the bound victim address. Design: [BindRelationship before Who/Where](../../../.agents/notes/implemented/feature/2026-08-21-bind-relationship.md), [case_report victim-row entity_id](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-row-entity-id.md), and [stringified who/where](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-stringified-who-where.md).

#### Token effect

The rendered 5W1H packet remains in conversation history.

#### KV Cache effect

The call extends the conversation normally.

## Known Limitations and Deferred Work

- `pcap_info` and `pcap_filter` require Wireshark CLI tools on PATH unless `tsharkBin` / `capinfosBin` point at another executable.
- Display-filter syntax is tshark's; this package only rejects the named invalid field list.
- `logs` reads the file as UTF-8 text and does not parse binary formats.
