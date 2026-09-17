# @deepseek-ai/dsh-judgment-typesafe

[English](README.md) | 中文

[判断接缝](../judgment/README.md)的 TypeSafe System One 提供方。这是一个函数/命名空间式插件：它把 `/v1/systemone` 后端注册进 `ctx.judgment`，自身不拥有任何服务。

凭据是一个按请求解析的环境变量*引用*，绝不是内联的密钥。变量缺失或为空时，提供方会报告自己不可用，而不是在插件加载时失败，因此一个组合了这一行的 harness 在没有密钥时仍能启动，并由接缝的选择规则来报告这一缺失。

`429` 与 `529`——服务文档中标明可重试的那两个状态——会以指数退避重试，并遵从调用方的 `AbortSignal`；其余任何状态都立即以 `JUDGMENT_BACKEND_FAILED` 失败。形状与其所声明类型相矛盾的回答会被丢弃而非强制转换，因此接缝抛出的是 `JUDGMENT_ANSWER_MISSING`，而不会把一个伪造的 `0` 交给消费方。

每一个结果都会记录服务自报的、真正作答的模型。以 `jev-latest` 这类滚动别名发出的请求，实际由某个固定版本作答；只有记录下那个版本而非所请求的别名，一次评测才是可复现的。

因此 `model` 的默认值是一个固定版本，而不是别名。消费方的阈值是针对某一个版本的概率标度校准的，别名在其脚下移动会让每一道闸门失效，却不会让任何一个测试失败。改动这个默认值是一次重新校准事件：在发布新版本之前，请重跑消费方的评测。

设计：[判断能力与 bind 校验器](../../../.agents/notes/implemented/feature/2026-09-17-judgment-capability.md)。

## 配置

```yaml
- id: judgment-typesafe
  name: '@deepseek-ai/dsh-judgment-typesafe'
  config:
    apiKeyEnv: TYPESAFE_API_KEY                        # default
    baseURL: https://api.typesafe.ai/v1/systemone      # default
    model: jev-1.13.0                                  # default; pinned, not an alias
    maxRetries: 3                                      # default
```

四个字段全部属于 Config。未知的键会在加载时失败。

## 模型体验

间接生效，经由真正提出问题的那些消费方；这个提供方自身不注册任何提示词、模式或工具结果。

#### KV 缓存影响

不直接造成失效；请求前缀的任何变化由具名的消费方自己负责。

## 已知限制与暂缓事项

- **没有流式输出，也没有部分答案。** 一个请求要么产出一份完整结果，要么产出一个错误；问题集再长也无法报告进度。
- **重试仅基于状态码。** 在传输层失败的请求（DNS、TLS、套接字重置）会原样抛出底层 `fetch` 的拒绝而不重试，因为该次尝试是否已生效无从得知。
- **`available()` 只检查凭据是否存在。** 已吊销或格式错误的密钥会被报告为可用，并在调用时以 `JUDGMENT_BACKEND_FAILED` 失败。
