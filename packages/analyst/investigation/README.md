# @deepseek-ai/dsh-investigation

English | [中文](README.zh.md)

Case-scoped investigation ledger. The plugin records unique labeled identities, auto-issues MAC, name-service, Kerberos, then SAMR hunts after a new IP, auto-issues `other-end` when bind_relationship assigns a cue as victim, auto-issues `c2-domain` on a successful bind with a non-LAN C2, auto-runs those outstanding issued hunts through `pcap_filter`, denies writes to evidence and work outside the case directory, requires BindRelationship before `case_report`, denies write/edit of case-root `report.md` and similar close files, and persists a 5W1H close packet whose who/where project from the bound victim. A harvested C2 TLS SNI or DNS name persists as `c2_domain` on that packet. State is folded from the session log.

## Service: `Investigation` (ctx key: `investigation`)

`caseDir` is required and must be an absolute path. `evidenceReadOnly` and `autoHunt` default to true and remain Config fields.

- `identities(session)` / `hunts(session)` / `report(session)` / `bind(session)` fold the log.
- `recordIdentity` / `recordHunt` append only when kind+value (or kind+subject) is new, except `recordIdentity` may append a later `evidence_id` onto a first-seen row that lacks one, or overwrite a MAC DC/peer stamp when the later id is the bound victim or a C2-talking LAN IP.
- `recordBind` whole-value-replaces the live conversation bind. `recordReport` whole-value-replaces the 5W1H packet. After a live bind with a non-LAN C2, `c2-domain` issues for that C2 IPv4 and, when `autoHunt` is true, auto-runs TLS SNI / DNS on that IP. A harvested dotted DNS name with `evidence_id` of that C2 persists as `c2_domain` on the accepted packet; it does not fill who/where hostname and does not donate to the victim row. `case_report` is denied until a live bind has exactly one victim; `who` and `where` project from that victim entity row. A who/where `entity_id` that is a user, hostname, MAC, or full_name on that row is a handle; the persisted packet uses the bound victim address. After a live bind, a unique unaffiliated ledger identity (no `entity_id`, `evidence_id` does not point at a non-victim) donates to the bound victim when it is the only identity of that kind not affiliated with a different entity; two unaffiliated identities of the same kind donate neither. A MAC sourced from the bound victim IP on a tool-result line (`ip.src`, outbound `ip → peer`, or ARP `is at`) or restamped from a victim-IP-scoped field-only `eth.src` dump (`evidence_id` of that IP) donates even when a hunt-subject `evidence_id` names another IP, the first harvest had no `evidence_id`, and even when other MAC values exist. A hostname evidenced on the bound victim IP (hunt-subject `evidence_id`, or a name-service line scoped to that IP) donates even when other hostname values exist. A user or full_name evidenced on a Kerberos/SAMR conversation whose client is the bound victim (the LAN / non-DC end) donates even when a hunt-subject `evidence_id` names another IP and even when other domain accounts exist. The persisted who/where carry ip/mac/hostname/user/full_name from that projection. After deny/coerce, keys the model omitted (including `mac`) are filled from that projected victim row; omitted mac and user also persist from victim-IP evidence when a sticky DC donate or uniqueness left the row empty; a submitted user, hostname, or full_name is kept when the row has no donated value and that identity does not donate to a different entity; a submitted mac is kept unless that MAC only appears on DC/gateway frames (never as eth.src on the bound victim IP, and never in a victim-IP-scoped `eth.src` dump); a model-offered IP does not replace the bound victim ip. A JSON object string with `entity_id`, or after a live bind a string of victim-row handles, is coerced before the free-text check. A string that names the c2, a distractor, another IPv4, or unmatched prose stays unbound. An inverted victim/c2 close is refused. A cue/observation address cannot be victim. The cited conversation must include a cue/observation address; a both-LAN conversation is unbound. Role `c2` cannot be a LAN address. Tokens are not swapped. A both-LAN deny does not issue `other-end`. A JSON array string of endpoint objects, and a numeric string `dport` that is an integer 1-65535, are coerced before those bind checks. A string that is not a JSON array, a missing `dport`, or a `dport` outside 1-65535 stays denied. Names are not invented. `write` / `edit` of case-root `report.md` (and similar close files) is denied; `report.md` is not parsed into who/where. `c2TalkingLanVictim` affiliates a unique sourced `eth.src` MAC and does not rewrite slots.
- `resolveInsideCase`, `isEvidence`, `isWritable`, and `contains` enforce the case directory.

`tools/pre-execute` denies writes to evidence and capture files, write/edit of case-root close files, shell commands that leave the case, and malware runners (`wine`, `qemu`, captured `.exe`). `tools/post-execute` harvests IP, MAC, hostname, user, and full name from successful tool text, including UTF-16LE SAMR hex (`Becka Rolf`) and hostnames in NBNS, BROWSER, SMB, LLMNR, TLS SNI, and DNS tshark summaries. Workgroup and domain tokens distinguished as Domain/Workgroup Announcement, Local Master Announcement, or NBNS `<1b>`–`<1e>` are not recorded as hostname. A new IP issues `eth-src`, `name-service`, `kerberos-cname`, and `samr-userinfo` for that subject; a new hostname issues `kerberos-cname` and `samr-userinfo`; a new user issues `samr-userinfo`. After a LAN IP shares a line with a non-LAN unicast peer, those identity hunts issue only for that C2-talking IP; `eth-src` notices use `ip.src ==` that subject and MAC harvest records only `eth.src` sourced from that IP, not a far-side or idle-workstation NIC, and stamps that talking IP as `evidence_id` even when the dump's hunt subject is a different IPv4. A field-only `eth.src` dump with no talking IP stamps hunt-subject `scopeIp` (`ip.src` / `ip.addr ==` that IP); a later victim-IP-scoped dump restamps a first harvest that had no `evidence_id` or a DC/peer stamp. User and full_name harvest stamp the conversation client IPv4 as `evidence_id`, not a SAMR/CNameString hunt-subject DC. A field-only SAMR/CName dump with no IP on the line stamps the LAN / non-DC peer talking to that DC from prior tool text (`ip.src` or `LAN → DC`). Protocol field names and truncated dumps are not user or full_name identities. Other IP-subject notices use `ip.addr ==` that subject. When `autoHunt` is true, outstanding issued hunts run through `pcap_filter` with that same scoped `display_filter` and fields; the plugin does not wait for the model to call `pcap_filter`. A C2-talking LAN subject is preferred; a non-LAN / C2 IP subject does not auto-run, except `other-end` issued when bind assigns a cue as victim (`ip.dst ==` that cue, field `ip.src`) and `c2-domain` issued on a successful bind for that C2 IPv4 (`tls.handshake.extensions_server_name` / `dns.qry.name` / `dns.resp.name` and `ip.addr ==` that C2). `name-service` is `llmnr or nbns or browser`. SMB is not a hunt kind.

The `investigation:policy` section states DINQ, BindRelationship before Who/Where, 5W1H, evidence-first work, and the valid tshark 4.4.16 fields. `investigation:ledger` is a dynamic context listing the live roles card, recorded identities, and hunts. Design: [BindRelationship before Who/Where](../../../.agents/notes/implemented/feature/2026-08-21-bind-relationship.md), [refuse cue-as-victim](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-cue-as-victim.md), [other-end hunt on cue-as-victim](../../../.agents/notes/implemented/bug-fix/2026-08-21-other-end-hunt-on-cue-victim.md), [case_report victim-row entity_id](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-row-entity-id.md), [complete victim-row projection](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-victim-row-projection.md), [victim-IP-scoped donate](../../../.agents/notes/implemented/bug-fix/2026-08-21-donate-victim-ip-scoped-mac-hostname.md), [MAC talking-IP stamp](../../../.agents/notes/implemented/bug-fix/2026-08-21-stamp-mac-evidence-from-talking-ip.md), [restamp victim-IP-scoped eth.src](../../../.agents/notes/implemented/bug-fix/2026-08-21-restamp-victim-ip-scoped-eth-src.md), [overwrite DC MAC stamp](../../../.agents/notes/implemented/bug-fix/2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md), [user/full_name conversation-client stamp](../../../.agents/notes/implemented/bug-fix/2026-08-21-stamp-user-fullname-from-conversation-client.md), [field-only SAMR/CName client stamp](../../../.agents/notes/implemented/bug-fix/2026-08-21-reject-protocol-field-stamp-field-only-samr.md), [stringified who/where](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-stringified-who-where.md), [stringified bind endpoints and dport](../../../.agents/notes/implemented/bug-fix/2026-08-21-bind-relationship-stringified-args.md), [refuse both-LAN bind](../../../.agents/notes/implemented/bug-fix/2026-08-21-refuse-both-lan-bind.md), [persist omitted victim-row keys](../../../.agents/notes/implemented/bug-fix/2026-08-21-persist-projected-victim-slot.md), [keep submitted victim-row identities](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-row-identities.md), [keep submitted victim MAC unless DC-only](../../../.agents/notes/implemented/bug-fix/2026-08-21-keep-submitted-victim-mac-unless-dc-only.md), [complete omitted victim-row mac and user](../../../.agents/notes/implemented/bug-fix/2026-08-21-complete-omitted-victim-mac-user.md), [victim-row handle strings](../../../.agents/notes/implemented/bug-fix/2026-08-21-case-report-victim-handle-strings.md), [deny close-file writes](../../../.agents/notes/implemented/bug-fix/2026-08-21-deny-close-file-writes.md), and [C2-domain hunt after live bind](../../../.agents/notes/implemented/bug-fix/2026-08-21-c2-domain-hunt-after-live-bind.md).

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
You are a network-security investigation analyst, not a coding agent. Define the Investigation Question (DINQ) before collecting more evidence. Before Who/Where, bind the conversation. The detector’s IP is a hypothesis about the other end until the bind says otherwise. Use bind_relationship to assign victim vs c2 on the cited conversation. Exactly one victim. The cited conversation must include a cue/observation address. Role c2 cannot be a LAN address. Cue and observation addresses default to c2 and cannot be victim. State what, when, why, and how as claims you can support with packets or logs. who and where are projections of the bound victim. Work evidence-first and question-driven: every tool call answers a named question. Label unverified ideas as hunches and verify them in this case. Evidence under evidence/ and capture files (*.pcap, *.pcapng, *.cap, *.log) is read-only. Do not execute malware, run captured binaries, or operate on paths outside the case directory. Use pcap_info, pcap_filter, logs, and bind_relationship. Valid tshark 4.4.16 fields include kerberos.CNameString, samr.samr_UserInfo21.account_name, and samr.samr_UserInfo21.full_name. Do not use ldap.sAMAccountName, ldap.displayName, kerberos.username, or samr.full_name — those fields are invalid. After a hostname or IP appears, hunt Kerberos CNameString, then SAMR QueryUserInfo for the display name. SAMR full_name is UTF-16 (for example Becka Rolf), not an LDAP displayName. Close with case_report only after bind_relationship has assigned the victim.
```

#### Token effect

The section is a fixed paragraph on every request while the plugin is mounted.

#### KV Cache effect

The section is stable for the life of the mount.

### Identity ledger context

#### What the model sees

When the session log holds a bind, identities, hunts, or a report, `investigation:ledger` lists the roles card and those rows as a dynamic context snapshot. Identities on a live bind are labeled with their endpoint role.

#### Token effect

Empty ledger adds no tokens; each new identity or hunt adds one list line.

#### KV Cache effect

A new identity or hunt changes the context after the reusable prompt prefix.

### Harvest and hunt notices

#### What the model sees

A successful tool result that yields a new identity appends a plugin-sourced notice naming the identity and, when `autoHunt` is true, the issued hunts and the valid tshark 4.4.16 fields. An IP notice names `eth.src` and the `llmnr or nbns or browser` filters that produce DESKTOP-* / NBNS Registration / BROWSER Host Announcement lines. `eth-src` notices include `ip.src ==` that subject; other IP-subject notices include `ip.addr ==` that subject. Notices name the filter that already ran; they do not tell the model to run `pcap_filter` after auto-run. After a C2-talking LAN IP is seen, idle LAN workstations do not receive eth-src, Kerberos, or SAMR hunts, and MAC harvest does not record their NICs or the far-side NIC of a bidirectional dump. Outstanding issued hunts then execute with those filters; identities from the dump enter the ledger on the same tool result. The Kerberos notice tells the model to run SAMR QueryUserInfo without waiting for a username.

#### Token effect

One notice per harvesting call that recorded something new.

#### KV Cache effect

Notices append after the reusable request prefix.

### Denied tool calls

#### What the model sees

A denied write, escape, or malware-runner call returns an error result naming the case directory or the read-only evidence rule. write/edit of case-root `report.md` (or a similar close file) returns `close with case_report after BindRelationship.` An unbound, inverted, or free-text `case_report` (or any tool that sets `who`/`where`) returns `unbound: assign victim vs c2 on the cited conversation.` Assigning victim to a cue/observation address on `bind_relationship` returns `unbound: hunt LAN ip.src talking to <cue> (ip.dst == <cue>).` A both-LAN conversation returns `unbound: cite the LAN host talking to the cue/observation address, not a LAN DC/AD service.` Assigning `c2` to a LAN address returns `unbound: role c2 cannot be a LAN address.`

#### Token effect

The error stays in conversation history like any other failed call.

#### KV Cache effect

Denied calls extend the conversation normally.

## Known Limitations and Deferred Work

- Shell policy tokenizes commands; a crafted one-liner can still name an outside path in a way the scanner misses. Prefer `pcap_filter` and `logs` over free-form shell for evidence.
- Harvest is text-based. Structured tool values that never render as text are not recorded. Hostname from tshark summaries is limited to NBNS, BROWSER, SMB, and LLMNR host forms; distinguished workgroup and domain tokens are omitted. After a C2-talking IP, only a MAC sourced from that IP is recorded; a field-only `eth.src` dump with no IPv4 falls back to a strict majority, which can still be the far-side NIC.
- There is no Web projection card for the ledger yet; UIs read `session/event` or fold the log.
