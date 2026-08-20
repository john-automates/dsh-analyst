# analyst headless overlay

English | [中文](README.zh.md)

Patch layer that inserts the agent-preset roster and defaults it to `analyst`. Use it with the headless profile; it is not a standalone app leaf.

```sh
cd /path/to/case
export DSH_CASE_DIR="$PWD"
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString in evidence/"
```

See [Investigate a pcap case](../../docs/user/guide/analyst.md) and [Configure models](../../docs/user/guide/providers.md#qwen-openai-compatible).
