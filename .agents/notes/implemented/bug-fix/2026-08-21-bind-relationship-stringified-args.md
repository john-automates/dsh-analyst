# Agent Note: Coerce stringified bind_relationship endpoints and dport

Status: implemented

English | [中文](2026-08-21-bind-relationship-stringified-args.zh.md)

## Problem

Live lumma-r14 (`f22b0b3`) assigned the intended roles (LAN victim / external c2) but `bind_relationship` never accepted. Both calls returned `INVALID_ARGS` before `resolveBind`. Bind 1 sent `dport` as a numeric string and `endpoints` as a JSON array string. Bind 2 omitted `dport` and again sent `endpoints` as a string. No `investigation/bind` event was written. Two later `case_report` calls (`who` = a ledger user, `where` = the LAN address) were rejected unbound.

[String-field coerce](2026-08-20-pcap-filter-string-fields.md) and [stringified who/where](2026-08-21-case-report-stringified-who-where.md) already recover Hermes XML parameter text for `pcap_filter.fields` and `case_report` who/where. The `bind_relationship` schema still typed `endpoints` as an array only and `dport` as an integer only, so the same stringified structured arguments died at validation.

## Decision

`resolveBind` coerces `endpoints` from a JSON array string of endpoint objects into that array, and `dport` from a numeric string that is an integer into that integer, before the existing bind checks. The `bind_relationship` schema accepts `endpoints` as an array or a string, and `dport` as an integer or a string, so those arguments reach `resolveBind` instead of `INVALID_ARGS`. A string that is not a JSON array stays denied. A missing `dport` is not invented. `dport` `0` and `65536` stay denied. Cue-as-victim still names the [other-end hunt](2026-08-21-other-end-hunt-on-cue-victim.md). Inverted roles are not accepted. Exactly one victim.

Harvest, donate, and `case_report` coerce stay unchanged. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client and a TEST-NET peer.

## Alternatives considered

**Parse JSON array parameters in llm-pi-ai XML recovery.** Rejected: that widens recovery for every tool, and a native JSON-string `endpoints` still dies at the bind schema. The required bind test goes through `resolveBind` and `tools.execute`, not XML recovery.

**Coerce only in a CLI or one-off parser.** Rejected: the hole is the `bind_relationship` tool boundary. [String-field coerce](2026-08-20-pcap-filter-string-fields.md) and [stringified who/where](2026-08-21-case-report-stringified-who-where.md) already live at their tool intake.

**Teach the model in the prompt to send an array and an integer.** Rejected: the live calls already sent the intended LAN victim and cue c2; schema validation discarded them.

**Invent a default `dport` when it is missing.** Rejected: a missing port stays denied.

**Silently accept inverted roles or a cue as victim after coerce.** Rejected: existing `resolveBind` rules run unchanged.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP and a TEST-NET cue.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` binds a synthetic LAN client (`10.0.10.2`) to a TEST-NET peer (`198.51.100.80`). `endpoints` as `JSON.stringify([...])` plus `dport` `"443"` resolves to the same bind as a native array plus integer `dport`. Cue-as-victim after that coerce still names the other-end hunt. An `endpoints` string that is not a JSON array stays denied. A missing `dport` and `dport` `"0"` / `"65536"` stay denied. `packages/analyst/investigation/tests/investigation.spec.ts` executes the same stringified call through `tools.execute` and records `investigation/bind`.

## Consequences

A JSON-string `endpoints` list plus a numeric-string `dport` reaches `resolveBind` and can record `investigation/bind` when the roles are valid. A string that is not a JSON array, a missing port, an out-of-range port, and cue-as-victim still fail. Harvest, donate, and `case_report` coerce are unchanged.
