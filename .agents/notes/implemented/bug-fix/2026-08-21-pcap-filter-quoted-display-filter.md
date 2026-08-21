# Agent Note: Strip wrapping quotes from pcap_filter display_filter

Status: implemented

English | [中文](2026-08-21-pcap-filter-quoted-display-filter.zh.md)

## Problem

Live First to Last r2 (`ee72365`, Bedrock 30B) scored 2/5. PR8 hunt notices mentioned `ip.addr ==` the subject, but `c2TalkingLanIps` never armed from the pcap: all five `pcap_filter` calls were extra-quoted and failed, so [string-field coerce](2026-08-20-pcap-filter-string-fields.md) did not fire. After grep harvested an IP from leftover r1 files, hunts still issued for other IPs. `who` and MAC came from leftover r1 `report.md` / `live.log`, not this session's pcap.

`pcap_filter` passed `display_filter` to tshark `-Y` verbatim. Qwen wrapped the whole filter in quotes as if it were a shell argument. tshark then received `"ip.addr == …"` or `'llmnr or nbns or browser'` and rejected the expression. The usable filter never ran.

## Decision

`pcap_filter` strips wrapping quotes from `display_filter` before tshark `-Y`. A model value `"ip.addr == 1.2.3.4"` or `'llmnr or nbns or browser'` becomes that filter without the outer quotes and runs. Typical extra-quoting — escaped wrappers such as `\"…\"`, mixed `'\"…\"'`, and an extra matching layer — is peeled the same way. A filter that is not wholly wrapped, including one with inner quoted strings, is unchanged.

Invalid tshark 4.4.16 fields are still rejected before spawn. [String-field coerce](2026-08-20-pcap-filter-string-fields.md) is unchanged.

Scout, leftover-report harvest bans, auto-run hunts, family harvest, and new evals stay out of this change. The [analyst investigation preset](../feature/2026-08-20-analyst-investigation-preset.md) still owns those knobs.

## Alternatives considered

**Teach the model in the prompt not to quote `display_filter`.** Rejected: the live calls already sent a usable filter; tshark died on the wrapping quotes before rows could arm `c2TalkingLanIps`.

**Spawn tshark through a shell so the quotes become shell syntax.** Rejected: helpers use `execFile` with no shell. The quotes are characters in the `-Y` argument, not a shell layer.

**Ban leftover-report harvest in the same change.** Rejected: that is the next miss if needed. This knob is quoted `display_filter` failing before the pcap is read.

**Auto-run hunts, invent evals, or bake gold identities into prompts or tests.** Rejected: those are separate knobs. Tests use synthetic filters such as `ip.addr == 1.2.3.4`.

## Testing

`packages/analyst/analyst-tools/tests/tools.spec.ts` executes `pcap_filter` with `display_filter: "\"ip.addr == 1.2.3.4\""`. The call must spawn `tshark` with `-Y ip.addr == 1.2.3.4`. The same path with a quoted `display_filter` and `fields: "ldap.sAMAccountName"` must fail with the invalid-field diagnostic, not `INVALID_ARGS`. `fields.spec.ts` pins single, double, escaped, and mixed wrappers, and leaves `http.host == "example.com"` and `"smb" or nbns` unchanged.

## Consequences

A Qwen-quoted `display_filter` reaches tshark instead of dying as an invalid expression. Invalid field names still fail before spawn. Models may keep sending unquoted filters. Leftover-report harvest, scout, and hunt issuance are unchanged.
