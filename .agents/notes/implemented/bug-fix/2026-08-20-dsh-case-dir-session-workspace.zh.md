# Agent Note: DSH_CASE_DIR 是会话工作区

Status: implemented

[English](2026-08-20-dsh-case-dir-session-workspace.md) | 中文

## 问题

`DSH_CASE_DIR` 配置了 investigation 的 `caseDir` 和 `fs-local` 的 `cwd`，因此案件之外的写入会被拒绝。headless 仍用 `meta.cwd: process.cwd()` 创建 Agent。glob、read、bash 以及分析师 persona 的 `{{cwd}}` 都跟随 `session.header.cwd`，并在缺失时回退到进程工作目录。从 git 检出目录启动（`pnpm --dir exec`）且 `DSH_CASE_DIR` 指向 pcap 案件时，因此永远列不出 `TASK.md` 或 `capture.pcap`。这是工作区绑定遗漏，不是 hunt 遗漏。[调查分析预设](../feature/2026-08-20-analyst-investigation-preset.md) 把该环境变量写成了案件目录，但没有绑定会话。

## 决策

`resolveHeadlessCwd` 是 `headless-runner` 唯一的会话工作区绑定。设置了 Config `cwd` 时用它，否则依次为 `DSH_CASE_DIR`、`DSH_CWD`、`process.cwd()`。空值跳过。相对路径会使本次运行失败。analyst overlay 在 `headless-runner` 行上设置同一条链。调查隔离不变：证据保持只读，案件之外的写入仍在 `tools/pre-execute` 失败。

## 备选方案

**继续要求操作者 `cd` 进案件目录。** 否决，因为 `pnpm --dir` 和其他从检出目录启动的方式会把 `process.cwd()` 留在仓库上。环境变量已经存在；还要求 cwd 与之相同，就只剩拒绝列表。

**对 `DSH_CASE_DIR` 调用 `chdir`。** 否决，因为它在配置加载后改写进程全局状态，并会把持久化根目录作为副作用一起搬走。

**让 investigation 改写 `session.header.cwd`。** 否决，因为该标头在创建后不可变。

**只在 analyst overlay 中绑定，runner 仍使用 `process.cwd()`。** 否决，因为现场一次性路径就是 runner。仅 overlay 提供的 `cwd` 仍需要 runner 读取 Config `cwd`。

## 测试

`packages/bundle/headless/tests/headless.spec.ts` 把 `DSH_CASE_DIR` 盖到会话标头上。`examples/analyst/tests/case-workspace.spec.ts` 对该工作区运行 glob 与 read，若它们列出启动检出目录则会失败。

## 后果

设置 `DSH_CASE_DIR` 后，即使进程 cwd 是检出目录，glob 与 read 也会列出案件。操作者可以从案件目录运行，也可以只设置该环境变量。通用 headless 遵循同一条链，因此残留的 `DSH_CASE_DIR` 会改写该会话工作区。Web 会话 cwd 仍是打开的工作区；本笔记不改变它。
