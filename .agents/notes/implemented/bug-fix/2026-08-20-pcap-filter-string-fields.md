# Agent Note: Coerce pcap_filter string fields into tshark -e names

Status: implemented

English | [中文](2026-08-20-pcap-filter-string-fields.zh.md)

## Problem

Live r5 (`46fa813`, Bedrock 30B, Easy as 123) scored 2/5. Boot, cwd, and XML recovery were fine; the r4 XML flake did not recur. `pcap_info` and `pcap_filter` ran. The model attempted `kerberos.CNameString` but sent `fields` as a string, so `defineTool` raised `INVALID_ARGS` before `rejectInvalidTsharkFields`. The retry omitted `-e` and showed AS-REQ only; `brolf` never entered the session. SAMR stayed a header. Identities stayed IP-only. `case_report` `who` hallucinated `mattw`. Hostname `DESKTOP-TEYQ2NR` never appeared because this run did not dump LLMNR/NBNS/BROWSER/SMB. That string-typed `fields` call blocked the hunt that closed user on r3.

The `pcap_filter` schema typed `fields` as an array only. Qwen often emits a single field name as a string.

## Decision

`pcap_filter` accepts `fields` as a string or a string array. A string is one field or a comma/space-separated list and is coerced to `string[]` before invalid-field rejection and `tshark -e`. A string `kerberos.CNameString` becomes `-e kerberos.CNameString` and runs. `ldap.sAMAccountName`, `ldap.displayName`, `kerberos.username`, and `samr.full_name` are still rejected. Arrays stay structured lists; their elements are not split.

Scout, auto-run hunts, family harvest, hostname-summary harvest, and new evals stay out of this change. The [analyst investigation preset](../feature/2026-08-20-analyst-investigation-preset.md) still owns those knobs.

## Alternatives considered

**Keep the array-only schema and teach the model in the prompt.** Rejected: the live call already sent a usable field name; schema validation discarded it before the reject list or tshark could run.

**Type `fields` as unconstrained JSON.** Rejected: a number or object is not a field list. The accepted inputs are a string or a string array.

**Split comma-bearing array elements.** Rejected: arrays are already structured. The live miss was a string.

**Auto-run hunts, family harvest, or invent evals in the same change.** Rejected: those are separate knobs. r5 never reached a labeled CNameString row.

## Testing

`packages/analyst/analyst-tools/tests/tools.spec.ts` executes `pcap_filter` with `fields: "kerberos.CNameString"`. The call must succeed, label the column, and spawn `tshark` with `-e kerberos.CNameString`. The same path with `fields: "ldap.sAMAccountName"` must fail with the invalid-field diagnostic, not `INVALID_ARGS`. `fields.spec.ts` pins comma/space splitting and rejection of the four invalid names after coerce.

## Consequences

A Qwen string `fields` value reaches tshark instead of dying at argument validation. Invalid names still fail before spawn. Models may keep sending arrays. Hostname harvest, SAMR family harvest, and hunt issuance are unchanged.
