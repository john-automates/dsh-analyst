# @deepseek-ai/dsh-investigation

English | [中文](README.zh.md)

Case-scoped investigation ledger. The plugin records unique labeled identities, auto-issues Kerberos then SAMR hunts, denies writes to evidence and work outside the case directory, and persists a 5W1H close packet. State is folded from the session log.

## Service: `Investigation` (ctx key: `investigation`)

`caseDir` is required and must be an absolute path. `evidenceReadOnly` and `autoHunt` default to true and remain Config fields.

- `identities(session)` / `hunts(session)` / `report(session)` fold the log.
- `recordIdentity` / `recordHunt` append only when kind+value (or kind+subject) is new.
- `recordReport` whole-value-replaces the 5W1H packet.
- `resolveInsideCase`, `isEvidence`, `isWritable`, and `contains` enforce the case directory.

`tools/pre-execute` denies writes to evidence and capture files, shell commands that leave the case, and malware runners (`wine`, `qemu`, captured `.exe`). `tools/post-execute` harvests IP, MAC, hostname, user, and full name from successful tool text, including UTF-16LE SAMR hex (`Becka Rolf`). A new IP or hostname issues `kerberos-cname` and `samr-userinfo` for that subject; a new user issues `samr-userinfo`.

The `investigation:policy` section states DINQ, 5W1H, evidence-first work, and the valid tshark 4.4.16 fields. `investigation:ledger` is a dynamic context listing recorded identities and hunts.

## Configuration

```yaml
- id: investigation
  name: '@deepseek-ai/dsh-investigation'
  config:
    caseDir: !!js process.env.DSH_CASE_DIR ?? process.cwd()
    evidenceReadOnly: true
    autoHunt: true
```

Unknown keys fail at load. Relative `caseDir` fails at load. Headless binds the same `DSH_CASE_DIR` chain as the session workspace, so glob, read, bash, and `{{cwd}}` see the case; `caseDir` still denies writes outside the case.

Design: [analyst investigation preset](../../../.agents/notes/implemented/feature/2026-08-20-analyst-investigation-preset.md).

## Model Experience

### Investigation policy system prompt

#### What the model sees

Every request includes the methodology section at prompt order 40.

##### Investigation methodology

```markdown
You are a network-security investigation analyst, not a coding agent. Define the Investigation Question (DINQ) before collecting more evidence. State who, what, when, where, why, and how (5W1H) as claims you can support with packets or logs. Work evidence-first and question-driven: every tool call answers a named question. Label unverified ideas as hunches and verify them in this case. Evidence under evidence/ and capture files (*.pcap, *.pcapng, *.cap, *.log) is read-only. Do not execute malware, run captured binaries, or operate on paths outside the case directory. Use pcap_info, pcap_filter, and logs. Valid tshark 4.4.16 fields include kerberos.CNameString, samr.samr_UserInfo21.account_name, and samr.samr_UserInfo21.full_name. Do not use ldap.sAMAccountName, ldap.displayName, kerberos.username, or samr.full_name — those fields are invalid. After a hostname or IP appears, hunt Kerberos CNameString, then SAMR QueryUserInfo for the display name. SAMR full_name is UTF-16 (for example Becka Rolf), not an LDAP displayName. Close with case_report using the 5W1H fields once the Investigation Question is answered.
```

#### Token effect

The section is a fixed paragraph on every request while the plugin is mounted.

#### KV Cache effect

The section is stable for the life of the mount.

### Identity ledger context

#### What the model sees

When the session log holds identities, hunts, or a report, `investigation:ledger` lists them as a dynamic context snapshot.

#### Token effect

Empty ledger adds no tokens; each new identity or hunt adds one list line.

#### KV Cache effect

A new identity or hunt changes the context after the reusable prompt prefix.

### Harvest and hunt notices

#### What the model sees

A successful tool result that yields a new identity appends a plugin-sourced notice naming the identity and, when `autoHunt` is true, the issued hunts and the valid tshark fields. The Kerberos notice tells the model to run SAMR QueryUserInfo without waiting for a username.

#### Token effect

One notice per harvesting call that recorded something new.

#### KV Cache effect

Notices append after the reusable request prefix.

### Denied tool calls

#### What the model sees

A denied write, escape, or malware-runner call returns an error result naming the case directory or the read-only evidence rule.

#### Token effect

The error stays in conversation history like any other failed call.

#### KV Cache effect

Denied calls extend the conversation normally.

## Known Limitations and Deferred Work

- Shell policy tokenizes commands; a crafted one-liner can still name an outside path in a way the scanner misses. Prefer `pcap_filter` and `logs` over free-form shell for evidence.
- Harvest is text-based. Structured tool values that never render as text are not recorded.
- There is no Web projection card for the ledger yet; UIs read `session/event` or fold the log.
