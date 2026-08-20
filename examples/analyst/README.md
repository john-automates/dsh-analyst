# analyst headless overlay

English | [中文](README.zh.md)

Patch layer that inserts the agent-preset roster and defaults it to `analyst`. Use it with the headless profile; it is not a standalone app leaf.

Run from the case directory, or set `DSH_CASE_DIR` so the session workspace, tool cwd, and persona case directory are that path. Containment still denies writes outside the case and keeps evidence read-only.

```sh
cd /path/to/case
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString in evidence/"

# Or from the checkout:
export DSH_CASE_DIR=/path/to/case
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString in evidence/"
```

See [Investigate a pcap case](../../docs/user/guide/analyst.md) and [Configure models](../../docs/user/guide/providers.md#qwen-openai-compatible).
