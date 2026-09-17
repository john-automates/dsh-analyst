# 用 System One 模型给真实感染流量做分诊

[English](README.md) | 中文

这不是模拟。七份来自 [malware-traffic-analysis.net][mta] 的捕获会被下载下来，
由 `tshark` 把每一份归约为「每个出站目的地一条观察」，再让 TypeSafe 针对
`analyst` 插件今天所发布的手写启发式规则逐个目的地做判断。谁对谁错，由帖子自带的
notes 文件说了算。

```sh
node bench/typesafe-triage/fetch.mjs     # download + unzip the corpus
node bench/typesafe-triage/bench.mjs     # grade jev against the shipped rule
node bench/typesafe-triage/bench.mjs --case=2026-08-10
```

需要 `~/.config/typesafe/api_key`（或 `$TYPESAFE_API_KEY`）、`tshark`，以及
`pnpm run build`——基线是从构建产物里导入的真实谓词，绝不重新实现一遍。全程没有
LLM 参与：Jev 返回的是带类型的概率，其余部分只有 tshark 和纯函数。跑满七份捕获是
97 次调用、0.003 美元。

## 语料

只取感染类的分析文章；那些「七天扫描与探测」的帖子既没有受害者也没有 C2。每个案例
是一份捕获加一份 notes 文件，按站点公布的 `infected_YYYYMMDD` 方案解压（该方案在
其 about 页上以图片形式给出，因此并非抓取所得）。同一批页面上还挂着 `files-from-*`
与 `malware*` 压缩包，它们从不被下载——这里没有任何东西可能被误执行。

## 读流量

对一个目的地的判断，只依据数据包所展示的内容，别无其他。`observe.mjs` 走遍每一帧，
留下「局域网主机与局域网外某处通信」的那些配对，并把每个目的地归约为一份分桶的、
语义化的 state：

- **names**：来自 DNS 应答、TLS SNI 与 HTTP `Host`——最多四个。
- **体量与形态**：以桶表示（`a few KB`、`tens to hundreds of KB`），而非原始计数，
  这样判断就不会取决于一个模型无法校准的数字。
- **何时发生、持续多久**：相对于捕获起点。
- **HTTP 请求与 user agent**：在明文流量下截断后给出。

有两样东西被刻意排除在 state 之外：捕获的文件名——MTA 用恶意软件家族给捕获命名，
那等于直接把答案递过去——以及 notes 文件里的任何内容。

## 问模型什么

针对同一份 state、在同一个请求里问四个问题。它们彼此独立，因此并行运行，且看不到
对方的答案。

    attacker_infra     Noul     attacker-owned server or domain
    malware_used_it    Noul     malware drove this, legitimate host or not
    benign_background  Noul     CDN / update / telemetry / OCSP
    label              Choice   c2 | abused_service | cdn | update | distractor

这样拆分不是装饰。第一次运行只问了一个问题——「这是感染的一部分吗？」——结果
`accounts.google.com` 得 0.07、`ip-api.com` 得 0.08。对那个问题而言两个都是正确答案，
而两者又都被各自的帖子列了出来，因为恶意软件用到了它们。一份帖子的 IOC 清单是两样
不同东西的并集，所以它需要两个问题。`suspicion()` 在代码里把它们组合起来，这意味着
改一个阈值不需要任何推理开销。

## 基准真相

每篇帖子都会公布属于这次感染的域名与 IP。当捕获中某个目的地的 IP、或捕获为它解析出的
某个名字出现在那份清单里时，它就是正例。评分从捕获出发，因此那些 notes 提到、但捕获
从未联系过的主机——沙箱链接、`Received:` 头里的邮件中继——根本不会出现。

明说而非藏着：一个确实属于本次感染、但帖子没有列出的目的地，会被算作负例。藏在
Cloudflare 后面的域名会解析到若干地址，每个地址各计一次。`iocMatch` 还会在两个后缀
方向上匹配名字与 IOC，因此一个光秃秃的 `example.com` 会匹配上 `sub.example.com` 这条
IOC；本语料中没有任何东西触发它。

## 要击败的那位飞行员

`baseline.mjs` 从构建产物里导入 `isCdnOrUpdateName`、`isCloudflareIpv4`、
`isFastlyIpv4` 与 `isLanIpv4`。一个非局域网目的地就是 C2 候选，除非其中之一命中。这
就是该插件对一个目的地全部的语义理解——一份 19 条的后缀清单加两套已公布的 anycast
前缀集——而它看到的观察与模型完全相同，正是这一点让比较关乎判断而非证据。

## 这一跑说明了什么

97 个目的地，其中 37 个是已公布的 IOC：

    pilot                       precision   recall      F1     FP    FN
    shipped heuristic               41%        57%    0.48     30    16
    jev choice c2|abused            81%        46%    0.59      4    20

Noul 的标度是压缩的——几乎没有什么能越过 0.5——但校准是单调的（0.0-0.1 → 实测 17%，
0.2-0.3 → 63%，0.3+ → 100%），所以它是一个好的排序器，只是被放在错误的阈值上读。在
这份数据上扫一遍，它划出三个带：

- `>= 0.25`——13 个目的地，**精确率 100%**。直接进 Plan。
- `< 0.06`——97 个里的 34 个，**其下没有任何已公布的 IOC**。丢弃。
- 两者之间——答案真正所在之处，也正是慢层该读的东西。

## 那个发现

线上启发式判为良性、而 notes 判为 IOC 的那 16 个目的地，无一例外都是被
Cloudflare/Fastly 前缀规则丢掉的——横跨 7 份捕获中的 6 份、共 15 个不同的恶意域名，
其中包括 `kernel-87.com`、`newlycrack.com` 与 `beeflex.online`。

`bind.ts` 的 `ipIsCdnOrUpdate` 在查看主机名**之前**先测试 anycast 前缀，因此一个有
证据支撑、明显不是 CDN 的名字救不了这个地址。这不只是报告上的遗漏：
`uniqueC2IsCdnOrUpdate` 会把 `CDN_C2_REASON` 喂给
[`bind.ts:659`](../../packages/analyst/investigation/src/bind.ts)，于是
`bind_relationship` **拒绝这次 bind**，`case_report` 因缺少生效的 bind 而持续被拒，
`agent/turn-stopping` 也随之拒绝收尾。一个藏在 Cloudflare 后面的 C2 不会产出更差的
报告；它产出的是没有报告。

`harvest.ts` 记录着那些前缀表中「未列入实战案例的 gold IP」——夹具当初就是按这条
路径永不触发来搭建的，这正是逐文件 100% 覆盖率没能抓住它的原因。

## 校验器

`verify.mjs` 是梯级之间的那一档，采用的是 [SDE cascade cookbook][cascade] 给出的
形状：一组狭窄的「是不是哪里不对？」问题，每种失效模式各一个，在同一道闸门后取最大值
聚合，好让一个笃定的红旗不会被四个平静的答案平均掉。这些失效模式不是凭空编的——它们
就是 `bind.ts` 自己的拒绝理由。

精确的部分仍旧精确。`10.9.10.101` 是不是 RFC1918、是不是恰好有一个端点是受害者，这
都是算术；`exactDenial` 把它们留在代码里，它们永远不花一次调用。只有那些需要知道某样
东西*是什么*的判断才会被提问。没有证据的维度同样不会被问：第一次运行时，
`user_is_machine_account` 在那些根本没有记录任何账户的受害者上给出 0.39–0.44，而在
取最大值聚合之下，这点噪声成了被报告出来的最差维度。

    node bench/typesafe-triage/verify-bench.mjs

97 份 bind 提案，其中 37 份有 notes 背书，97 次调用，0.0036 美元：

    gate                        correct   wrongly rejected   wrongly accepted
    shipped ipIsCdnOrUpdate       53%                 16                 30
    verifier >= 0.60              76%                  5                 18

（`GATE` 默认是 0.7，即 cookbook 的数字——冷跑一次会打印 71%/4/24。0.60 是下面那轮
扫描在本语料上最好的一行。）

这里只有一个维度被评了分。`c2_is_benign_service` 在全部 97 份提案上都是最大值；
`roles_inverted`（0.07-0.17）与 `victim_is_infrastructure`（0.16-0.22）从未触发，因为
这份语料在受害者一侧没有给出可判断的证据，也不含任何角色颠倒的提案，而主机名与账户
那两个维度压根没被问。它们是设计出来的，不是测出来的。因此上面的数字是一个单维度结果，
仅凭 `c2_is_benign_service` 设闸就能原样复现它们。

校验器在**两类**错误上同时更好，这是不寻常之处——它不是在拿召回换精确，而是在替换
一条两个方向上都错的规则。线上闸门拒掉的 16 个 Cloudflare 前置 C2 中，有 15 个被放行；
它仍然拦下的那一个是 `reallyfreegeoip.org`（0.74），一个被恶意软件滥用的、货真价实的
正当服务。

扫一遍就会看到，这道闸门是一个在两种不同工作之间切换的旋钮：

    gate    correct   wrongly rejected   wrongly accepted
    0.35       75%                 23                  1
    0.60       76%                  5                 18
    0.70       71%                  4                 24

在 0.35，几乎没有良性目的地能通过，代价是标记了 23 个真实 C2——作为最终答案毫无用处，
作为**慢层的队列**却恰到好处。在 0.60，它是最好的独立闸门。cookbook 自己那个 0.7 是给
另一项任务用的，不该照搬；文档自己也是这么说的。

[cascade]: https://docs.typesafe.ai/cookbooks/sde_cascade.md
[mta]: https://www.malware-traffic-analysis.net/
