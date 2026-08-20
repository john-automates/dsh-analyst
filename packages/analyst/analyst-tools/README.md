# @deepseek-ai/dsh-analyst-tools

English | [中文](README.zh.md)

SOC/NSM tools for the `analyst` preset: `pcap_info`, `pcap_filter`, `logs`, and `case_report`. They consume `ctx.investigation` for the case directory and the 5W1H close packet.

## Tools

`pcap_info` runs `capinfos` (or `tshark -r -q` when capinfos is missing) against a capture inside the case. `pcap_filter` runs `tshark` with an optional display filter and `-e` fields; invalid tshark 4.4.16 fields (`ldap.sAMAccountName`, `ldap.displayName`, `kerberos.username`, `samr.full_name`) are rejected before spawn. Recommended fields: `kerberos.CNameString`, `samr.samr_UserInfo21.account_name`, `samr.samr_UserInfo21.full_name`. Field rows are labeled so identity harvest can read them. `logs` reads a text file in the case, optionally sliced by line. `case_report` appends a 5W1H packet to the calling session.

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

The model sees the generated [`pcap_info` / `pcap_filter` / `logs` / `case_report` schemas](../../../docs/tool-catalog.md#deepseek-aidsh-analyst-tools). `pcap_filter`'s description names the valid tshark 4.4.16 fields and rejects the invalid ones.

#### Token effect

Four stable schemas on every request where the tools are visible.

#### KV Cache effect

The catalog is stable for the life of the mount.

### pcap and log results

#### What the model sees

Successful calls return clipped text. `pcap_filter` with `fields` labels each column as `field: value` so harvest can record identities. Invalid fields fail before tshark starts.

#### Token effect

Each result stays in history, clipped at `maxOutputChars`.

#### KV Cache effect

Results append after the reusable request prefix.

### Case report

#### What the model sees

`case_report` returns the six 5W1H fields and records `investigation/report` on the session. A non-agent caller is rejected.

#### Token effect

The rendered 5W1H packet remains in conversation history.

#### KV Cache effect

The call extends the conversation normally.

## Known Limitations and Deferred Work

- `pcap_info` and `pcap_filter` require Wireshark CLI tools on PATH unless `tsharkBin` / `capinfosBin` point at another executable.
- Display-filter syntax is tshark's; this package only rejects the named invalid field list.
- `logs` reads the file as UTF-8 text and does not parse binary formats.
