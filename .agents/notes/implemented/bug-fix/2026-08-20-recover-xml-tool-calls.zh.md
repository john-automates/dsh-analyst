# Agent Note: 在 OpenAI 兼容流上恢复 Hermes XML 工具转储

Status: implemented

[English](2026-08-20-recover-xml-tool-calls.md) | 中文

## 问题

Qwen 在 OpenAI-completions 适配器上有时会把 Hermes/MiniMax 风格的 XML 转储（`<function=name>` / `<parameter=…>` / `</function>`）写成 assistant 文本，而不是原生 `tool_calls`。循环把仅含文本的 `stop` 当作最终答案。现场 r4（`d83af44`，Bedrock 30B / `qwen.qwen3-coder-30b-a3b-v1:0`，Easy as 123）在 5 秒内得到 0/5，且没有任何工具事件：模型打印了格式完整的对 `TASK.md` 的 `read`，运行器随即结束该轮。同一代理与模型在 r3 使用了真实工具（4/5）。该次转储未触发主机名收割，因为运行从未开始 hunt。这是格式抖动，不是调查遗漏。

## 决策

`@deepseek-ai/dsh-llm-pi-ai` 包装已有的 `llm/stream` waterfall（瀑布式事件）。在已完成的、不含原生工具调用分片的 `stop` 之后，若 Hermes XML 转储格式完整且名称属于该请求已提供的工具，则追加为工具调用分片，并将结束原因改为 `tool-calls`。循环随后执行该调用并继续该轮。原生 `tool_calls`、辅助 `purpose` 调用（`compaction`、`session-title`）、未提供工具的请求、非 `stop` 结束、未知工具名，以及未闭合标签，仍保持为文本。agent loop（智能体循环）不变。

## 备选方案

**在 `agent-loop` 内解析该转储。** 否决：新行为应挂在已文档化的扩展点上；内核只负责轮次机械。

**当文本看起来像函数转储时对模型做 stall-reprompt。** 否决：那是 scout 的类比，且本次必须把已打印的调用恢复成真实执行，而不是再问一次。scout 不在范围内。

**从 investigation 插件挂接恢复。** 否决：抖动发生在 OpenAI 兼容适配器路径上，而不是案件账本。

**在同一次变更中发明评测或改主机名收割。** 否决：那些是另一组旋钮。r4 从未到达收割。

## 测试

`packages/llm/llm-pi-ai/tests/text-tool-calls.spec.ts` 喂入 r4 的原始 assistant 文本。`parseHermesXmlToolCalls` 必须得到 `read` 与 `{"file_path":"TASK.md"}`。经 `ctx.llm.stream()` 的已声明 `openai-completions` 路由必须以 `tool-calls` 结束，并包含该工具调用块。释放插件 fiber 后必须停止恢复。

## 后果

针对已提供工具的格式完整 XML 转储不再结束调查。格式不完整的转储，或名称未被提供的转储，仍是最终答案。请求已提供工具时，终端 `usage`/`finish` 分片会等到转储检查完成；内容分片仍会流式发出。恢复后的流省略回放元数据，因为合成的工具调用块不是提供方原生块。
