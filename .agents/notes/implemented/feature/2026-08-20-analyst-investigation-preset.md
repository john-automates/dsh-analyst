# Agent Note: Analyst investigation preset

Status: implemented

English | [中文](2026-08-20-analyst-investigation-preset.zh.md)

## Problem

A SOC/NSM analyst needs a harness composition that encodes an investigation mindset: define the Investigation Question (DINQ), collect 5W1H claims from packets and logs, keep evidence read-only, and persist identities. The shipped Standard, Minimal, Code, and Creator presets are coding-agent compositions. Skinning one of them with a different persona would still expose write-anywhere tools, web fetch, and no pcap field discipline.

John's prior analyst workflow (Chris Sanders investigation method; Kerberos `CNameString` then SAMR `QueryUserInfo` for display names such as Becka Rolf) lived outside this fork. Upstream DeepSeek Harness does not accept external PRs, so the work has to land here as plugins and a preset, not a kernel rewrite.

## Decision

Add a fifth shipped preset, `analyst`, and two packages under `packages/analyst/`. Standard, Minimal, Code, and Creator stay. The preset is selectable in the Web picker and is the default when headless is patched with `examples/analyst/headless.cordis.yml`.

`@deepseek-ai/dsh-investigation` is a Service (`ctx.investigation`). It owns `caseDir` (absolute), `evidenceReadOnly`, and `autoHunt` as Config. Identities, hunts, and the 5W1H report are `SessionEventMap` members folded from the log. `tools/pre-execute` denies evidence writes, case escapes, and malware runners. `tools/post-execute` harvests unique labeled IP, MAC, hostname, user, and full name — including UTF-16LE SAMR hex and hostnames from NBNS, BROWSER, SMB, and LLMNR tshark summaries, excluding distinguished workgroup and domain tokens ([hostname summaries](../bug-fix/2026-08-20-harvest-hostname-from-tshark-summaries.md)) — and auto-issues `kerberos-cname` and `samr-userinfo` after a new IP or hostname, and `samr-userinfo` after a new user. SAMR QueryUserInfo is how `user_full_name` (Becka Rolf, UTF-16) appears; it does not wait for a harvested user.

`@deepseek-ai/dsh-analyst-tools` is a function plugin. It registers `pcap_info`, `pcap_filter`, `logs`, and `case_report`. `pcap_filter` rejects `ldap.sAMAccountName`, `ldap.displayName`, `kerberos.username`, and `samr.full_name` before spawn. Helpers use `execFile` with the case directory as cwd.

Qwen is documented as a first-class custom OpenAI-completions provider (`supportsDeveloperRole: false`, `maxTokensField: max_tokens`). Bedrock Qwen3 Coder and a local 35B use the same adapter with different routes. Boot does not require `DEEPSEEK_API_KEY`. Headless joins `ctx.agentPresets.mount` when a roster is composed. `DSH_CASE_DIR` is the session workspace (glob, read, bash, `{{cwd}}`) as well as the investigation containment root; see [DSH_CASE_DIR session workspace](../bug-fix/2026-08-20-dsh-case-dir-session-workspace.md).

## Alternatives considered

**Replace Standard or Minimal with the analyst persona.** Rejected because coding presets remain the default product; an investigation composition is a different tool catalog and policy, not a prompt swap.

**Clone Beldum/scout or copy Claude Code harvest hooks.** Rejected: those trees are out of scope, and this repo forbids leaking or copying Claude Code source. The mindset is reimplemented as original Cordis plugins.

**New headless profile template.** Rejected as more invasive than a `--patch` overlay plus mount-if-roster. `PROFILE_TEMPLATES` stays `web` and `headless`.

**New LLM adapter for Qwen.** Rejected: `dsh-llm-pi-ai` already exposes `compat.supportsDeveloperRole` and `compat.maxTokensField`. Documentation makes Qwen first-class without a second protocol.

**Live in-memory identity service.** Rejected: model-visible identities and hunts must be reconstructable from the session log.

## Consequences

Selecting `analyst` mounts a case-scoped filesystem and persistent shell, pcap/log tools, and a methodology section. Evidence writes fail at `tools/pre-execute` even if `write` remains in the catalog. Coding presets are unchanged. A headless run without the overlay still has no roster and does not require a preset. Operators must install tshark/capinfos (or point the Config bins) and configure a Qwen-compatible route when they do not use DeepSeek. The keyless `examples/analyst` pcap-case snapshot pins harvest, hunt issuance, and `case_report` on the assembled headless spine.
