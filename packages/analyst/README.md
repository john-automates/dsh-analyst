# analyst/ — investigation analyst capability family

English | [中文](README.zh.md)

Case-scoped investigation state and the SOC/NSM tools that write it. This is a product family, not a coding-agent skin: Standard, Minimal, Code, and Creator stay shipped.

| Package | Role | ctx key |
|---|---|---|
| [`investigation/`](investigation/README.md) | Case directory, evidence policy, identity harvest, auto-issued hunts, BindRelationship, 5W1H report | `ctx.investigation` |
| [`analyst-tools/`](analyst-tools/README.md) | `pcap_info`, `pcap_filter`, `logs`, and `case_report` | (registers on `ctx.tools`; `bind_relationship` is registered by investigation) |

Select the `analyst` preset. Design: [analyst investigation preset](../../.agents/notes/implemented/feature/2026-08-20-analyst-investigation-preset.md).
