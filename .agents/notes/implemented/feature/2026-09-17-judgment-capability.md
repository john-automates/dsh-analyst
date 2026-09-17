# Agent Note: judgment capability and the bind verifier

Status: implemented

English | [中文](2026-09-17-judgment-capability.zh.md)

## Problem

`bind_relationship` refuses a C2 whose IPv4 sits in a published Cloudflare or Fastly anycast prefix. `ipIsCdnOrUpdate` tests that prefix **before** it consults any evidenced hostname, so an address the capture plainly names `kernel-87.com` is refused as "a well-known CDN or update destination". `case_report` is denied for want of a live bind, and `agent/turn-stopping` refuses the close. A Cloudflare-fronted C2 does not produce a worse report; it produces no report.

Graded against the IOC lists published with seven malware-traffic-analysis.net captures, that rule is wrong in both directions: 53% of bind proposals decided correctly, 16 published C2s refused, 30 benign destinations allowed. Every one of the 16 refusals is an anycast-prefix refusal — 15 distinct malicious domains across 6 of the 7 captures. `harvest.ts` records that "live-case gold IPs are not listed" in those prefix tables, so the fixtures were built such that this path never fires; per-file 100% coverage therefore never exercised it.

The rule is a semantic claim — *is this destination someone's CDN, or the attacker's server?* — implemented as a 19-entry registrable-suffix list and two CIDR tables. The same shape recurs across the plugin: an AD SRV locator versus a workstation name, a machine SAM versus a person, a DC versus a victim. Each is a judgment about what a thing *is*, and each is a regex.

## Decision

A new capability, not a rule rewrite.

`ctx.judgment` is a Service Definition over **System One** models: models that return calibrated typed answers rather than generated text. `judgment-typesafe` is its first provider, over TypeSafe's `/v1/systemone`. The seam's vocabulary is the three primitives that contract exposes — `noul` (probability a condition holds), `choice` (one of a defined set, with its distribution), and `score` (a position on ordered levels) — and its primitive operation is `ask(state, questions)`, because independent questions over one state run in parallel in a single request and cannot see one another's answers. `noul()` / `choice()` / `score()` are conveniences over `ask`.

Provider selection copies `ctx.web` exactly: a configured id that is registered and available wins; with none configured, exactly one usable provider auto-selects; ambiguity and absence are distinct errors. Selection resolves at execution time and never depends on registration order.

`investigation` consumes the seam **optionally**, through `ctx.get('judgment')` with an undefined check, which is this repo's optional-service idiom. `investigation`'s `inject` is unchanged, so the plugin still mounts with no judgment provider present and behaves exactly as it does today. This is a consumer inside `investigation` rather than a `tools/execute` wrapper because the CDN refusal happens inside `bind.ts` before the tool returns: an around-dispatch wrapper would see `CDN_C2_REASON` and have to re-dispatch the bind with the check bypassed, which is a fork of `bind.ts` in another package.

When a provider is present, `ipIsCdnOrUpdate` asks the verifier instead of returning true on the prefix test. The verifier is the shape the [SDE cascade cookbook](https://docs.typesafe.ai/cookbooks/sde_cascade.md) gives: narrow "is something wrong?" questions, one per failure mode, max-aggregated behind one gate so a single confident red flag cannot be averaged away. `c2_is_benign_service` is the only dimension this change asks; `roles_inverted`, `victim_is_infrastructure`, `hostname_not_a_workstation` and `user_is_machine_account` are defined on the seam and left unconsumed until each has evidence of its own.

The anycast-prefix and suffix-list predicates are **not removed**. They remain the answer when no provider is mounted, and their results are passed to the verifier as state — that an address is in a published Cloudflare prefix is real evidence, it is simply not conclusive.

The gate is `investigation` config, default `0.6`. On the seven-capture corpus, 0.60 decided 76% correctly against the shipped rule's 53%, and was better on both error types at once: 5 wrongly refused against 16, and 18 wrongly allowed against 30. It rescues 15 of the 16 refused C2s; the one it still stops is `reallyfreegeoip.org`, a legitimate service the malware was abusing. The cookbook's own 0.7 is for a different task and is not borrowed.

Credentials resolve through `ctx.credentials` by environment-variable reference (`apiKeyEnv`, default `TYPESAFE_API_KEY`), as `llm-deepseek` does, not `process.env` at module scope. The served model id is recorded on every result, because the request asks for `jev-latest` and the service answers as a pinned version.

## Alternatives considered

**Reorder `ipIsCdnOrUpdate` so evidenced hostnames outrank the prefix.** The smallest change, and it fixes the seven captures. Rejected as the whole answer: it replaces one regex verdict with another, and leaves every neighbouring judgment — locator versus hostname, machine versus person — as string matching. Kept as the fallback path when no provider is mounted.

**A `tools/execute` around-dispatch wrapper.** Clean package separation, but it intercepts a refusal and re-runs the bind, duplicating `bind.ts`'s endpoint logic and costing a second round-trip at max reasoning effort.

**A judgment subagent.** Rejected on category: every provider under `packages/subagent/` is conversational, and a System One model generates no text and calls no tools. Wiring it as a subagent discards the latency and cost that are its entire advantage.

**Removing the anycast tables.** Rejected: they are evidence worth giving the verifier, and they are the correct behavior with no provider mounted.

## Consequences

`investigation` gains an optional runtime dependency and one config field. With no provider mounted nothing changes. Harvest filtering, dead-end detection, and a model-facing triage tool are deliberately out of scope until each is graded the way this one was; the bench that graded it is `bench/typesafe-triage/`.
