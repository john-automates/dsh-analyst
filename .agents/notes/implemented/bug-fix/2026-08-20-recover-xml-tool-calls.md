# Agent Note: Recover Hermes XML tool dumps on OpenAI-compatible streams

Status: implemented

English | [中文](2026-08-20-recover-xml-tool-calls.zh.md)

## Problem

Qwen on the OpenAI-completions adapter sometimes emits a Hermes/MiniMax-style XML dump (`<function=name>` / `<parameter=…>` / `</function>`) as assistant text instead of native `tool_calls`. The loop treats a text-only `stop` as the final answer. Live r4 (`d83af44`, Bedrock 30B / `qwen.qwen3-coder-30b-a3b-v1:0`, Easy as 123) scored 0/5 in 5s with zero tool events: the model printed a well-formed `read` of `TASK.md` and the runner completed the turn. The same proxy and model used real tools in r3 (4/5). Hostname harvest from that dump was untested because the run never hunted. This is a format flake, not an investigation miss.

## Decision

`@deepseek-ai/dsh-llm-pi-ai` wraps the existing `llm/stream` waterfall. After a completed `stop` with no native tool-call chunks, a well-formed Hermes XML dump whose name is among the tools offered on that request is appended as tool-call chunks and the finish becomes `tool-calls`. The loop then executes the call and continues the turn. Native `tool_calls`, auxiliary `purpose` calls (`compaction`, `session-title`), requests that offered no tools, non-`stop` finishes, unknown tool names, and unclosed tags stay text. The agent loop is unchanged.

## Alternatives considered

**Parse the dump inside `agent-loop`.** Rejected: new behavior attaches to a documented extension point; the loop remains the turn machine.

**Stall-reprompt the model when the text looks like a function dump.** Rejected: that is a scout analog, and this change must recover the printed call into a real execution rather than ask again. Scout is out of scope.

**Hook recovery from the investigation plugin.** Rejected: the flake is on the OpenAI-compatible adapter path, not the case ledger.

**Invent evals or change hostname harvest in the same change.** Rejected: those are separate knobs. r4 never reached harvest.

## Testing

`packages/llm/llm-pi-ai/tests/text-tool-calls.spec.ts` feeds the exact r4 assistant text. `parseHermesXmlToolCalls` must yield `read` with `{"file_path":"TASK.md"}`. A declared `openai-completions` route through `ctx.llm.stream()` must finish as `tool-calls` and include that tool-call block. Disposing the plugin fiber must stop recovery.

## Consequences

A well-formed XML dump for an offered tool no longer ends the investigation. A malformed dump or a name that was not offered is still a final answer. When tools were offered, terminal `usage`/`finish` chunks wait until the dump check runs; content chunks still stream. Recovered streams omit replay metadata because a synthesized tool-call block is not a provider-native block.
