# Agent Note: 调查分析预设

Status: implemented

[English](2026-08-20-analyst-investigation-preset.md) | 中文

## 问题

SOC/NSM 分析师需要一套编码了调查思维的 harness 组合：先定义调查问题（DINQ），从数据包和日志收集 5W1H 主张，保持证据只读，并持久化身份。现有的标准、极简、Code 与创造模式都是编码 Agent 组合。只换人格提示词仍会暴露可任意写入的工具、网页抓取，以及缺乏 pcap 字段纪律。

John 既有的分析师工作流（Chris Sanders 调查方法；先 Kerberos `CNameString` 再 SAMR `QueryUserInfo` 取显示名，例如 Becka Rolf）位于本 fork 之外。上游 DeepSeek Harness 不接受外部 PR，因此工作必须作为插件和预设落在这里，而不是改写内核。

## 决策

新增第五个随部署提供的预设 `analyst`，以及 `packages/analyst/` 下的两个包。标准、极简、Code 与创造模式保持不变。该预设可在 Web 选择器中选用，并在 headless 打上 `examples/analyst/headless.cordis.yml` 时作为默认。

`@deepseek-ai/dsh-investigation` 是服务（`ctx.investigation`）。它把 `caseDir`（绝对路径）、`evidenceReadOnly` 和 `autoHunt` 作为 Config。身份、hunt 和 5W1H 报告是从日志折叠的 `SessionEventMap` 成员。`tools/pre-execute` 拒绝写入证据、越出案件目录，以及恶意软件运行器。`tools/post-execute` 收割唯一的带标签 IP、MAC、主机名、用户和全名——包括 UTF-16LE SAMR 十六进制——并在新的 IP/主机名后自动下发 `kerberos-cname`，在新用户后下发 `samr-userinfo`。

`@deepseek-ai/dsh-analyst-tools` 是函数插件。它注册 `pcap_info`、`pcap_filter`、`logs` 和 `case_report`。`pcap_filter` 在启动进程前拒绝 `ldap.sAMAccountName`、`ldap.displayName`、`kerberos.username` 和 `samr.full_name`。辅助进程用 `execFile`，cwd 为案件目录。

Qwen 被文档化为头等的自定义 OpenAI-completions 提供方（`supportsDeveloperRole: false`，`maxTokensField: max_tokens`）。Bedrock Qwen3 Coder 和本地 35B 使用同一适配器、不同路由。启动不要求 `DEEPSEEK_API_KEY`。当组合了花名册时，headless 会调用 `ctx.agentPresets.mount`。

## 备选方案

**用分析师人格替换标准或极简模式。** 否决，因为编码预设仍是默认产品；调查组合是不同的工具目录与策略，而不是提示词替换。

**克隆 Beldum/scout 或复制 Claude Code 的收割钩子。** 否决：那些树不在范围内，且本仓库禁止泄露或复制 Claude Code 源码。该思维以原创 Cordis 插件重实现。

**新增 headless profile 模板。** 否决，因为比 `--patch` overlay 加上“有花名册则挂载”更侵入。`PROFILE_TEMPLATES` 仍只有 `web` 和 `headless`。

**为 Qwen 写新的 LLM 适配器。** 否决：`dsh-llm-pi-ai` 已暴露 `compat.supportsDeveloperRole` 和 `compat.maxTokensField`。文档让 Qwen 成为一等公民，而不增加第二种协议。

**内存中的实时身份服务。** 否决：模型可见的身份与 hunt 必须能从会话日志重建。

## 后果

选择 `analyst` 会挂载案件范围的文件系统与持久 shell、pcap/日志工具，以及方法论章节。即使 `write` 仍在目录中，对证据的写入也会在 `tools/pre-execute` 失败。编码预设不变。不打 overlay 的 headless 运行仍然没有花名册，也不要求预设。操作者必须安装 tshark/capinfos（或指向 Config 中的二进制），并在不使用 DeepSeek 时配置 Qwen 兼容路由。`examples/analyst` 的无密钥 pcap-case 快照钉住组装后的 headless spine 上的身份收割、hunt 下发与 `case_report`。
