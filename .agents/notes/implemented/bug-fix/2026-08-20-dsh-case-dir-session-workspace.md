# Agent Note: DSH_CASE_DIR is the session workspace

Status: implemented

English | [中文](2026-08-20-dsh-case-dir-session-workspace.zh.md)

## Problem

`DSH_CASE_DIR` configured investigation `caseDir` and `fs-local` `cwd`, so writes outside the case were denied. Headless still created the Agent with `meta.cwd: process.cwd()`. glob, read, bash, and the analyst persona `{{cwd}}` follow `session.header.cwd`, which falls back to the process working directory. A launch from the git checkout (`pnpm --dir exec`) with `DSH_CASE_DIR` pointing at a pcap case therefore never listed `TASK.md` or `capture.pcap`. That is a workspace-binding miss, not a hunt miss. The [analyst investigation preset](../feature/2026-08-20-analyst-investigation-preset.md) documented the env var as the case directory without binding the session.

## Decision

`resolveHeadlessCwd` is the one session-workspace bind for `headless-runner`. Config `cwd` wins when set; otherwise `DSH_CASE_DIR`, then `DSH_CWD`, then `process.cwd()`. Empty values are skipped. A relative path fails the run. The analyst overlay id-patches the `headless-runner` row with that same chain. An id-targeted patch replaces the whole `config`, so the overlay restates the shipped bundle's required `task: !!js ctx.headlessStartup.task`. Investigation containment is unchanged: evidence stays read-only, and writes outside the case still fail at `tools/pre-execute`.

## Alternatives considered

**Leave operators to `cd` into the case.** Rejected because `pnpm --dir` and other checkout launches keep `process.cwd()` on the repo. The env var already existed; requiring a matching cwd made it a deny-list.

**`chdir` to `DSH_CASE_DIR`.** Rejected because it mutates process-global state after config load and would move persistence roots as a side effect.

**Have investigation rewrite `session.header.cwd`.** Rejected because the header is immutable after create.

**Bind only in the analyst overlay, leave the runner on `process.cwd()`.** Rejected because the live one-shot path is the runner. An overlay-only `cwd` still needs the runner to read Config `cwd`.

**Stamp only `cwd` on the overlay `headless-runner` row.** Rejected because an id-targeted patch replaces the whole `config`. That drops required `task` and fails boot with `$.task missing required value`.

## Testing

`packages/bundle/headless/tests/headless.spec.ts` stamps `DSH_CASE_DIR` on the session header. `examples/analyst/tests/case-workspace.spec.ts` composes the shipped headless bundle patch with the overlay and fails if the patched runner config is missing `task`; it also runs glob and read against that workspace and fails if they list the launch checkout.

## Consequences

Setting `DSH_CASE_DIR` makes glob and read list the case even when the process cwd is the checkout. Operators may run from the case directory or set the env var. Generic headless honors the same chain, so a leftover `DSH_CASE_DIR` relocates that session workspace. Web session cwd is still the opened workspace; this note does not change it.
