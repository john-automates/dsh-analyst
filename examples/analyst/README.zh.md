# analyst headless overlay

[English](README.md) | 中文

该补丁层插入 agent-preset 花名册，并将其默认设为 `analyst`。与 headless profile 一起使用；它不是独立的应用叶节点。

在案件目录中运行，或设置 `DSH_CASE_DIR`，使会话工作区、工具 cwd 和 persona 中的案件目录都指向该路径。隔离规则仍拒绝写入案件之外的路径，并保持证据只读。

```sh
cd /path/to/case
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString in evidence/"

# Or from the checkout:
export DSH_CASE_DIR=/path/to/case
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString in evidence/"
```

见[调查 pcap 案件](../../docs/user/guide/analyst.md)和[配置模型](../../docs/user/guide/providers.md#qwen-openai-compatible)。
