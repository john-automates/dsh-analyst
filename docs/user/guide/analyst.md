# Investigate a pcap case

English | [中文](analyst.zh.md)

The `analyst` preset is an investigation agent, not a coding-agent skin. Standard, Minimal, Code, and Creator stay available. Select **Investigation mode** in the Web UI preset picker, or default to `analyst` from headless with the overlay below.

The case directory is `DSH_CASE_DIR`, then `DSH_CWD`, then the process working directory. When `DSH_CASE_DIR` is set, the session workspace, tool cwd, and persona case directory are that path, so glob and read see `TASK.md` and captures there. Containment still denies writes outside the case and keeps evidence read-only. Put captures under `evidence/` or as `*.pcap` / `*.pcapng` / `*.cap` / `*.log` in the case. Writable paths are `notes/`. `write` / `edit` of case-root `report.md` is denied; close with `case_report` after BindRelationship.

## Headless against a case directory

No DeepSeek API key is required. Configure a Qwen (or other) OpenAI-compatible route first; see [Configure models](./providers.md#qwen-openai-compatible).

```sh
# From the case directory:
cd /path/to/case
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString and SAMR display names in evidence/"

# Or from the checkout, bind the session workspace to the case:
export DSH_CASE_DIR=/path/to/case
# Optional: point at a Qwen-compatible gateway instead of DeepSeek
# export OPENAI_API_KEY=...
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString and SAMR display names in evidence/"
```

Install `tshark` and `capinfos` (Wireshark CLI) on the host, or set `tsharkBin` / `capinfosBin` on the `@deepseek-ai/dsh-analyst-tools` row.

After a hostname or IP appears, the ledger issues a Kerberos `CNameString` hunt, then a SAMR `QueryUserInfo` hunt for the display name. Valid tshark 4.4.16 fields include `kerberos.CNameString`, `samr.samr_UserInfo21.account_name`, and `samr.samr_UserInfo21.full_name`. `ldap.sAMAccountName`, `ldap.displayName`, `kerberos.username`, and `samr.full_name` are rejected. SAMR `full_name` is UTF-16 (Becka Rolf), not an LDAP displayName.

Close with `case_report` only after `bind_relationship` assigns victim versus c2 on the cited conversation. `who` and `where` project from the bound victim; they are not free-text fill.
