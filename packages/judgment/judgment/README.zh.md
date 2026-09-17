# @deepseek-ai/dsh-judgment

[English](README.md) | 中文

抽象判断能力接缝（`ctx.judgment`）：面向 **System One** 模型的提供方注册表与选择式执行——这类模型不生成文本，而是用一个校准过的数值回答一个带类型的问题。

它自成一条接缝，而非 `ctx.llm` 的某种模式，因为两者的契约在每一处都不同：请求携带的是问题而非消息，回答携带的是概率而非内容，没有流式输出，没有工具循环，也没有需要解析的散文。消费方问一句*这个目的地是 CDN 吗？*，得到的是 `0.74`。

## 服务：`JudgmentRuntime`（ctx 键：`judgment`）

`register(provider)` 加入一个后端并返回其销毁函数；重复的 id 会以 `JUDGMENT_PROVIDER_DUPLICATE` 拒绝。`list()` 按注册顺序列出已注册的 id。

`ask(request, signal)` 是原语：一份 state、若干问题、一次往返。彼此独立的问题应当放进同一个请求——它们并行运行、互相看不到对方的答案，分开问既更贵，又会让先到的答案影响后来的答案。只有当某个答案是取得新证据或决定下一步选项的前提时，才值得发第二个请求。

`noul(state, instructions, signal)`、`choice(state, instructions, criteria, signal)` 与 `score(state, instructions, criteria, signal)` 是 `ask` 在单问题场景下的便捷封装。每一个都会核对提供方回答的是否为所问的那一类问题，否则抛出 `JUDGMENT_ANSWER_MISSING`，从而让畸形的回答绝不会以伪造的零值抵达消费方。

按答案的含义来挑选原语。`noul` 是某一个条件成立的概率——它没有独立的置信度，接近 0.5 表示「是」与「否」几乎同样可能，而不是「强度中等」；当多个标签可能同时成立时，每个标签各用一个。`choice` 从给定集合中挑一个并返回分布，因此它的 `probabilities` 用于比较互相竞争的选项。`score` 在若干各自描述了具体情形的有序档位上给出一个位置。

提供方的选择在执行时解析，绝不依赖注册顺序。配置中指定的 `provider` id 必须已注册（否则 `JUDGMENT_PROVIDER_CONFIGURED_MISSING`）且可用（否则 `JUDGMENT_PROVIDER_CONFIGURED_UNAVAILABLE`）。未配置 id 时，恰好有一个可用的提供方则自动选中；一个都没有是 `JUDGMENT_PROVIDER_UNAVAILABLE`，多于一个是 `JUDGMENT_PROVIDER_AMBIGUOUS`。

设计：[判断能力与 bind 校验器](../../../.agents/notes/implemented/feature/2026-09-17-judgment-capability.md)。

## 配置

```yaml
- id: judgment
  name: '@deepseek-ai/dsh-judgment'
  config:
    provider: typesafe   # optional; omit when exactly one provider is usable
```

## 模型体验

间接生效，经由真正提出问题的那些消费方——`dsh-investigation` 的 bind 校验器是第一个——而这个注册表本身不贡献任何提示词、模式或工具结果。

#### KV 缓存影响

不直接造成失效；请求前缀的任何变化由具名的消费方自己负责。

## 已知限制与暂缓事项

- **带类型的输出保证的是接口，不是真相。** 这类模型为校准过的决策而训练，但校准是领域相关的：在一份语料上划分干净的阈值并不会迁移到另一份。在据其路由之前，请在你自己的数据与后果上评估阈值，正如 `bench/typesafe-triage/` 为 bind 校验器所做的那样。
- **没有观测面**——既无提供方变更事件，也无能力状态查询。可用性只能通过调用 `ask` 并对抛出的 `JudgmentError` 代码分流来观察。
- **不跨 state 批处理。** `ask` 携带的是关于*同一份* state 的若干问题；判断多份 state 就是多次调用，需要并发的消费方自己负责池化。
