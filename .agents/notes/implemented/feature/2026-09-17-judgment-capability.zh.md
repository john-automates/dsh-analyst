# Agent Note：判断能力与 bind 校验器

Status: implemented

[English](2026-09-17-judgment-capability.md) | 中文

## 问题

`bind_relationship` 会拒绝那些 IPv4 落在已公布的 Cloudflare 或 Fastly anycast 前缀内的 C2。`ipIsCdnOrUpdate` 在查阅任何有证据支撑的主机名**之前**就先测试该前缀，于是一个被捕获流量明明白白命名为 `kernel-87.com` 的地址，会以「众所周知的 CDN 或更新目的地」为由被拒。`case_report` 因缺少生效的 bind 而被拒绝，`agent/turn-stopping` 也随之拒绝收尾。一个藏在 Cloudflare 后面的 C2 并不会产出一份更差的报告；它产出的是没有报告。

以 malware-traffic-analysis.net 七份捕获随附的 IOC 清单为准来评分，这条规则在两个方向上都是错的：bind 提案中判对 53%，16 个已公布的 C2 被拒，30 个良性目的地被放行。这 16 次拒绝无一例外都是 anycast 前缀造成的拒绝——横跨 7 份捕获中的 6 份、共 15 个不同的恶意域名。`harvest.ts` 记录着那些前缀表中「未列入实战案例的 gold IP」，也就是说夹具当初就是按这条路径永不触发来搭建的；因此逐文件 100% 的覆盖率从未真正走过它。

这条规则是一个语义主张——*这个目的地是某家的 CDN，还是攻击者的服务器？*——却被实现成一份 19 条可注册后缀的清单加两张 CIDR 表。同样的形状在这个插件里反复出现：AD SRV 定位记录与工作站名之别、机器 SAM 与自然人之别、域控与受害者之别。每一个都是关于某样东西*是什么*的判断，而每一个都是正则。

## 决定

新增一项能力，而不是重写一条规则。

`ctx.judgment` 是一个面向 **System One** 模型的 Service Definition：这类模型返回的是校准过的带类型答案，而非生成的文本。`judgment-typesafe` 是它的第一个提供方，接的是 TypeSafe 的 `/v1/systemone`。接缝的词汇表就是该契约暴露的三个原语——`noul`（某条件成立的概率）、`choice`（给定集合中的一个，附其分布）与 `score`（有序档位上的一个位置）——其原语操作是 `ask(state, questions)`，因为针对同一份 state 的若干独立问题会在一个请求中并行运行，且彼此看不到对方的答案。`noul()` / `choice()` / `score()` 是 `ask` 的便捷封装。

提供方的选择完全照搬 `ctx.web`：配置中指定、且已注册并可用的 id 胜出；未配置时，恰好只有一个可用的提供方则自动选中；歧义与缺失是两个不同的错误。选择在执行时解析，绝不依赖注册顺序。

`investigation` **可选地**消费这条接缝，方式是 `ctx.get('judgment')` 加一次 undefined 检查，这是本仓库的可选服务惯用法。`investigation` 的 `inject` 未作改动，因此在没有任何判断提供方时插件照样挂载，行为与今天完全一致。之所以把消费方放进 `investigation` 内部而不是做成 `tools/execute` 包装器，是因为 CDN 拒绝发生在 `bind.ts` 内、工具返回之前：一个环绕分发的包装器只会看到 `CDN_C2_REASON`，然后不得不绕过该检查重新分发这次 bind——那等于在另一个包里分叉了 `bind.ts`。

当提供方在场时，`ipIsCdnOrUpdate` 不再在前缀命中时直接返回 true，而是去问校验器。校验器采用的是 [SDE cascade cookbook](https://docs.typesafe.ai/cookbooks/sde_cascade.md) 给出的形状：一组狭窄的「是不是哪里不对？」问题，每种失效模式各一个，在同一道闸门后取最大值聚合，好让一个笃定的红旗不会被平均掉。本次改动只提问 `c2_is_benign_service` 这一个维度；`roles_inverted`、`victim_is_infrastructure`、`hostname_not_a_workstation` 与 `user_is_machine_account` 已在接缝上定义，但在各自拥有证据之前一律不消费。

anycast 前缀与后缀清单这两个谓词**没有被移除**。在没有提供方挂载时它们仍是答案，而它们的结果会作为 state 传给校验器——一个地址落在已公布的 Cloudflare 前缀内是实打实的证据，只是并不足以定论。

闸门是 `investigation` 的配置项，默认 `0.6`。在七份捕获的语料上，0.60 判对 76%，而线上规则是 53%，并且同时在两类错误上都更好：错拒 5 个对 16 个，错放 18 个对 30 个。它救回了 16 个被拒 C2 中的 15 个；仍被它拦下的那一个是 `reallyfreegeoip.org`，一个被恶意软件滥用的正当服务。cookbook 自己那个 0.7 是给另一项任务用的，不予照搬。

凭据经由 `ctx.credentials` 以环境变量引用的方式解析（`apiKeyEnv`，默认 `TYPESAFE_API_KEY`），与 `llm-deepseek` 的做法一致，而不是在模块作用域读 `process.env`。每个结果都会记录实际作答的模型 id，因为请求问的是 `jev-latest`，而服务是以某个固定版本作答的。

## 考虑过的替代方案

**调整 `ipIsCdnOrUpdate` 的顺序，让有证据的主机名压过前缀。** 这是最小的改动，而且它确实能修好这七份捕获。作为完整答案被否决：它不过是用一个正则裁决换掉另一个正则裁决，而把周边每一个判断——定位记录与主机名、机器与自然人——都留在字符串匹配里。它被保留为没有提供方挂载时的兜底路径。

**做成 `tools/execute` 环绕分发包装器。** 包的边界很干净，但它拦截的是一次拒绝而后重跑 bind，既复制了 `bind.ts` 的端点逻辑，又要在最大推理强度下多付一次往返。

**做成判断子智能体。** 按类别否决：`packages/subagent/` 下的每一个提供方都是对话式的，而 System One 模型既不生成文本也不调用工具。把它接成子智能体，等于丢掉延迟与成本这两项它全部的优势。

**移除 anycast 表。** 否决：它们是值得交给校验器的证据，并且在没有提供方挂载时它们就是正确行为。

## 后果

`investigation` 多了一项可选的运行时依赖和一个配置字段。没有提供方挂载时一切照旧。Harvest 过滤、死胡同检测以及面向模型的分诊工具都被刻意排除在范围之外，直到每一项都像这一项一样被评过分为止；为这一项评分的基准台是 `bench/typesafe-triage/`。
