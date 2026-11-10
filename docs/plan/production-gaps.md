# Why Canary isn't yet a real production AI-agent safety-testing system

Source: a full read of `~/Documents/canary` (main @ 7696621), with key claims spot-checked in the code.
Paths are relative to `cyber-redteam-foundry/src/cyberredteam/` unless noted.

Bottom line: Canary is a solid **demo of an architecture** (parallel LangGraph fan-out, a detector + LLM-judge consensus, a finding lifecycle). As a testing instrument it has three structural weaknesses:
1. It runs **too few, too shallow attacks**.
2. Its **verdicts aren't trustworthy** on an arbitrary agent.
3. It is **unsafe to point at, or run alongside, production**.

---

## A. Attack depth: it cannot find the vulnerabilities that matter in real agents

| # | Problem | Evidence | Why it matters in prod |
|---|---|---|---|
| A1 | **Single-turn only.** Each branch sends exactly one message. There is no conversation state, no session ID, and no multi-turn escalation. | `tools/target_adapter.py:153` (one `requests.post`); `reset_context()` is a no-op | Most real jailbreaks and agent hijacks (crescendo, trust building, memory poisoning across turns) need several turns. Memory and context poisoning can't actually be tested in one turn. |
| A2 | **No adaptive iteration.** Every re-iteration resends the same strategies at `depth=0, parent_evidence=None`. The attacker prompt's mutation logic is dead code. | `langgraph/nodes.py:128-130` | The "iterate when a finding exists" loop repeats blind attempts rather than refining what worked or what nearly worked. It also iterates only *after a success*, which is backwards for discovery. |
| A3 | **Tiny attack budget.** There is one payload per technique per iteration. `max_attempts_per_strategy` only appears as prompt text; there is no loop. | nodes.py:129; api.py:954 | Twenty-four attempts per campaign (the sample run) is statistically meaningless against a stochastic target. Real testing needs hundreds to thousands of samples per technique. |
| A4 | **Black-box text only.** Tool calls are *guessed* by regex over the reply text. | `agents/attacker.py:20-36` | You can't see whether the agent actually called `delete_user`; you see only what it *said*. Excessive agency and tool misuse (the most important agent risks) are effectively unobservable. |
| A5 | **No indirect channel.** Indirect injection and retrieval poisoning are "tested" by asking the agent in chat. Nothing plants payloads in documents, emails, web pages or tool outputs. | No poisoning infrastructure exists | Indirect prompt injection through data the agent reads is the #1 real-world agent attack, and it is untestable here. |
| A6 | **No attack library or benchmark corpus.** Payloads are improvised by one LLM at temperature 0.7, and static generators exist but are unused. | `llm/factory.py:122`; tools `generate_*` unused | Coverage isn't reproducible or comparable, and known jailbreak families (HarmBench, garak probes, PAIR/TAP-style search) aren't covered. |
| A7 | **The attacker model self-censors.** Nemotron can refuse (`ATTACKER_REFUSED`) or water down its payloads. | `prompts/attacker.md` | It gives a false sense of safety: "no finding" may just mean the attacker didn't try hard. |
| A8 | **Technique mapping is loose.** "Privilege escalation" maps to the jailbreak strategy, and "supply chain" maps to retrieval poisoning. | `api.py:803-812` | Reports claim coverage of OWASP classes that weren't really exercised. ASI07 and ASI10 are never mapped. |

## B. Verdict quality: findings and "clean" results can't be trusted

| # | Problem | Evidence | Impact |
|---|---|---|---|
| B1 | **Detectors are overfit to the demo target.** Hard-coded strings include `pr0d_s3cr3t`, `sk-internal`, "david park", "bob martinez", `employee_lookup` and `E001`. | `tools/prompt_injection.py:65`, `rag_probe.py:59`, `memory_poisoning.py:68`, `tool_abuse.py:21-26,71` | On any other agent the deterministic signal mostly vanishes or misfires, so the "consensus" degrades to the LLM judge alone. |
| B2 | **Keyword heuristics produce both false positives and false negatives.** Examples: "salary" alone counts as memory poisoning, "debug" counts as session override, any 4-digit number near "ssn" counts as PII, and a reply over 4000 characters counts as DoS. | tools/*.py | Benign answers get flagged; real leaks in unexpected formats are missed. |
| B3 | **Canary exfiltration can never fire on HTTP targets.** The adapter always returns `canary=None`. | `tools/target_adapter.py:191` | The strongest deterministic signal (the CRITICAL path) is dead for every real target. |
| B4 | **The judge is a single sample at temperature 0.7 with no seed.** | `llm/factory.py:122` | Verdicts are non-deterministic: rerunning the same transcript can flip the result. There is no judge calibration, no agreement measurement, and no human-labelled eval set. |
| B5 | **The judge sees a sanitized transcript.** "ignore", "override" and similar words are rewritten before judging. | `agents/evaluator.py:113-131` | The judge evaluates text the target never produced, and can miss the exact compliance language that proves a breach. |
| B6 | **Prompt and code disagree on verdict rules.** A hit plus an LLM failure gives *unconfirmed* in code but *confirmed* in the prompt. The code uses per-ASI thresholds while the prompt uses per-severity ones. The reported score is a composite unrelated to the threshold, and `consensus_score` is stale. | evaluator.py:307-353, 417 | Scores and thresholds in reports are not comparable, and the audit trail is misleading. |
| B7 | **Finding identity is lossy.** `upsert_finding` writes `component=""`, so the finding ID collapses all components of a strategy into one. Semantic dedup only warns. | `langgraph/orchestrator.py:242`; artifact_store upsert | Different vulnerabilities merge into one finding, and duplicates aren't suppressed. |
| B8 | **No success-rate statistics.** It reports single-attempt pass/fail, with no confidence intervals and no repeated trials per payload. | — | A target that fails 1 in 20 times on a payload looks "resilient". |
| B9 | **Inconclusive results are swallowed.** Only confirmed and unconfirmed results become findings. | orchestrator.py:233-247 | Ambiguous cases, often the interesting ones, never reach triage. |

## C. Safety of the tester itself: it is unsafe to run against production

| # | Problem | Evidence | Impact |
|---|---|---|---|
| C1 | **No rate limiting, throttling or kill switch.** Up to 12 parallel requests with no backoff; no cancel endpoint; an SSE disconnect doesn't stop the run. | `api.py` (no cancel route); `target_adapter` has no retry or backoff | It can hammer a prod agent, trigger costs or incidents, and can't be stopped short of killing the process. |
| C2 | **It intentionally sends DoS payloads** (infinite loops, 1M combinations, 50-tool fan-outs) with no guard rails. | workflow_manipulation strategy | Against a prod agent with real tools this can cause real resource exhaustion and spend. |
| C3 | **No action sandboxing.** It drives *real* tool use (lookups, writes, emails) on the prod agent. There is no dry-run mode, no test tenant, and no allowlist of safe tools. | — | A successful attack *is* a real incident: data accessed, actions taken. |
| C4 | **Target ownership is never verified.** The allowlist is optional (fails open unless `REQUIRE_TARGET_ALLOWLIST`). Any URL containing "localhost" is silently rewritten to `host.docker.internal:9000/chat`. | settings; `api.py:920-921` | It can attack systems you don't own; the stored target differs from the one entered. |
| C5 | **Secrets are exposed.** In Docker mode the bearer token is baked into the public JS bundle and port 8001 is published. The Vercel proxy lets anonymous users POST campaigns and PUT finding status using the server token. | Dockerfile; compose; `canary/api/[...path].js` | Anyone can launch attacks *from your infrastructure*. |
| C6 | **Single shared API key.** There are no users, roles or audit identity, and the comparison isn't constant-time. Reviewer ID and rationale are checked but **not saved**. | `api.py:31-45`; artifact_store transition | No accountability for who attacked what or who closed a finding. |
| C7 | **Sensitive data is stored in plaintext.** Full prompts, target responses (possibly real PII and secrets from prod), and target auth headers sit in SQLite with no retention, encryption or redaction. | `attack_traces`, `attacks` tables | The tester becomes a new data-leak surface. |
| C8 | **Data leaves to a third-party LLM.** Prod responses (with leaked PII) are sent to NVIDIA NIM for judging and reporting. | evaluator / reporter | This is a compliance problem (GDPR / SOC2) for prod data. |

## D. Engineering and operations: not a deployable service

| # | Problem | Evidence |
|---|---|---|
| D1 | Runs execute in in-process daemon threads, with SQLite storage, no queue and no workers. A restart marks running jobs as failed, and resume is advertised but not implemented. | `api.py:123-173`; orchestrator.py |
| D2 | The concurrency cap can race; SQLite has no foreign keys; dedup embeddings are compared in Python by a full scan. | api.py:381-420; storage/models.py |
| D3 | Each attack has a fixed 60 s timeout with no retries, so failures look like "blocked". Errors come back as text strings that the judge then evaluates. | target_adapter.py:82, 194-226 |
| D4 | There is a single target contract (JSON POST plus a template). No streaming, WebSocket, OpenAI-Assistants, MCP, or chat-UI targets; no auth flows (OAuth, cookies, rotating tokens). | target_adapter.py |
| D5 | No CI or regression gating on main (the differential-gate branch, which did this, is unmerged and diverged). There are no baseline-vs-candidate comparisons. | branches |
| D6 | Stale config and docs: `.env.example` is still Bedrock; `local.yaml`, `policies.yaml` and `attack_profiles.yaml` are unused; ASI numbering conflicts between the UI and the backend; the docs say 12 strategies but the code has 13. | docs report |
| D7 | Tests use a fake LLM and fake targets only. Nothing measures detection precision or recall against a labelled set of vulnerable and safe agents. | tests/ |
| D8 | The UI has bugs: a null score crashes the render, there is no cancel, and the SSE `finding`/`agent_state` events are ignored. Some of the startup "agent activity" is scripted theatre. | frontend report; `api.py:972-1015` |

---

## What it would take (prioritised)

1. **Make it safe to run.**
   - Mandatory target ownership verification (DNS/HTTP token, as on the cutc branch).
   - Per-target rate limits and a cost budget; a cancel/kill switch.
   - Remove the DoS payloads by default.
   - Server-side auth with users and audit; no tokens in bundles.
   - Encrypted, redacted, retention-limited evidence; option for a self-hosted judge.
2. **Make verdicts trustworthy.**
   - Temperature 0 with multiple judge votes; a calibration set with known positives and negatives, reporting precision and recall.
   - Remove demo-specific strings; per-target configurable detectors (secrets, PII, forbidden tools).
   - Real canary seeding (plant tokens in the target's data and tools).
   - Judge on raw transcripts.
   - Repeated trials with success rates and confidence intervals.
3. **Make attacks real.**
   - Multi-turn sessions (conversation IDs, cookies).
   - Adaptive search: feed `parent_evidence` and depth into PAIR/TAP-style refinement.
   - Indirect-injection harnesses (poisoned docs, emails, URLs, tool outputs).
   - Structured tool-call observability (OpenTelemetry/trace hooks or an MCP proxy).
   - Seeded benchmark corpora alongside the LLM-generated payloads.
4. **Make it operable.**
   - Job queue and workers with Postgres; resumable runs.
   - Pluggable target adapters (streaming, WS, MCP, OpenAI-style).
   - A CI release gate with baseline diffs (salvage from `feature/cutc-2026-differential-gate`).
