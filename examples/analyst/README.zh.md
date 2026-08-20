# analyst headless overlay

[English](README.md) | 中文

该补丁层插入 agent-preset 花名册，并将其默认设为 `analyst`。与 headless profile 一起使用；它不是独立的应用叶节点。

```sh
cd /path/to/case
export DSH_CASE_DIR="$PWD"
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString in evidence/"
```

见[调查 pcap 案件](../../docs/user/guide/analyst.md)和[配置模型](../../docs/user/guide/providers.md#qwen-openai-compatible)。
