# Agent Canary — Technical Reference

## CUTC release architecture

The product path is `project -> release -> accepted baseline -> differential
comparison -> policy gate`. A release stores its commit, environment, target
snapshot, run status, scores, coverage, and decision. Baselines are explicit
`AcceptedBaselineRecord` rows and are scoped by project and environment; the
first completed assessment is never trusted automatically.

After LangGraph persists candidate and baseline attack results, the release
adapter creates stable `AttackCaseRecord` identities from project, strategy,
technique, and payload. `finalise_differential_release()` converts both sides
to typed evaluator executions, classifies each case as regression, known,
resolved, clean, or indeterminate, persists `SecurityRegressionRecord`, and
evaluates `block_on`, `warn_on`, and explicit threshold policy. Scores are
diagnostic (100 minus severity deductions); the policy decision is authoritative.

The GitHub Action keeps its bearer credential server-side, starts
`POST /api/ci/releases`, polls the persisted release, writes a Job Summary,
exports decision/score/regression/coverage outputs, and exits non-zero only for
`BLOCK`. The current local adapter uses SQLite and a process thread for
compatibility; `cyberredteam.canary.release_execution` provides the durable,
idempotent lifecycle port for a queue/worker deployment.

Agent Canary is a two-service system for automated red-teaming of LLM agents. The backend
(`cyber-redteam-foundry/`, FastAPI + LangGraph, Python) runs adversarial campaigns against an
arbitrary HTTP JSON agent using AWS Bedrock-hosted LLMs for the attacker/evaluator/strategist
roles, and persists findings to SQLite. The frontend (`canary/`, React 19 + Vite + TypeScript)
is a dashboard/console that drives campaigns over Server-Sent Events and browses stored findings.

This document assumes familiarity with LangGraph, FastAPI, and React, and cites concrete
file:line locations throughout so claims can be checked against the code directly.

---

## 1. LangGraph orchestration

The graph lives in `cyber-redteam-foundry/src/cyberredteam/langgraph/graph.py` and is built by
`build_redteam_graph()` (graph.py:57-97). It has exactly four nodes:

```
strategist → (Send fan-out) → attacker_branch × ≤3 (parallel) → evaluator → {strategist | reporter}
```

- `strategist` (graph.py:66, implemented in `nodes.py:77-92`) is a log-only pass-through. It does
  **not** call an LLM — `StrategistAgent.select_strategies()` exists as an LLM-ranked alternative
  but is unused by the default dispatch path (nodes.py:80-84).
- The actual fan-out happens in the conditional edge `dispatch_attacker_branches`
  (nodes.py:99-141), registered via `graph.add_conditional_edges("strategist",
  dispatch_attacker_branches)` (graph.py:78). This function does not return a routing string —
  it returns `List[Send]`, LangGraph's mechanism for dynamic parallel dispatch. It:
  1. Converts `state["strategies"]` to `StrategyType` enum members (nodes.py:107).
  2. Selects a deterministic slice of at most three strategies using the current iteration and
     `MAX_PARALLEL_BRANCHES = 3`. Every configured strategy is therefore covered over bounded
     iterations rather than being randomly sampled and potentially omitted.
  3. For each chosen strategy, resolves `(asi_class, _) = taxonomy.lookup(strategy.value, "")`
     and `spec = get_spec(asi_class)` (nodes.py:116-117) to build an `AttackBranch` — a plain
     dataclass (`schemas.py:100-119`), not part of `RedTeamState`, carrying `branch_id`,
     `capability_type`, `technique_id`, `technique_spec`, `depth=0`, and
     `attempt_budget_remaining=state["max_attempts_per_strategy"]`.
  4. Wraps each branch in `Send("attacker_branch", {...})` (nodes.py:132-140) — the payload dict
     also carries `run_id`, `target_id`, `iteration`, and the generic HTTP target config
     (`target_headers`/`target_request_template`/`target_response_path`).

`graph.add_edge("attacker_branch", "evaluator")` (graph.py:79) means every one of the ≤3 spawned
branches feeds into the *same* `evaluator` node. LangGraph's superstep model guarantees the
evaluator only executes once all `Send`-spawned `attacker_branch` invocations from that dispatch
have completed — no manual barrier/join code is needed. The join is enabled by the state schema
in `state.py:44`:

```python
attack_results: Annotated[List[AttackResult], operator.add]
```

Each parallel branch (`node_attacker_branch`, nodes.py:148-198) returns a delta dict with
`"attack_results": [result]` — a single-item list. LangGraph merges all concurrent deltas for an
`Annotated[..., operator.add]` field by concatenation, regardless of which branch happened to
finish first (nodes.py:151-153, 189-190). Note `current_strategy` is deliberately *not* written
from this node — as a plain (non-Annotated) field, concurrent writers in the same superstep would
raise `InvalidUpdateError` (nodes.py:191-194 comment).

**Why iteration-tag filtering replaced positional slicing.** Because branches can complete in any
order and `attack_results` is a single ever-growing append-only list across the whole run
(spanning multiple dispatch rounds when the loop re-fires), the evaluator cannot assume "the last
N entries" are this round's results — a slower branch from iteration 0 could still be appended
after a faster branch from iteration 1 in a naive ordering. Instead, `node_evaluator`
(nodes.py:205-259) filters by an explicit iteration tag stamped onto every `AttackResult` at
creation time:

```python
recent = [r for r in state["attack_results"] if r.iteration == state["iteration"]]
```

(nodes.py:219, with the comment at 217-218 spelling out exactly this rationale). The `iteration`
field is set by `attack_branch()` on the `AttackResult` it returns (attacker.py:233, 284, passed
in via the `Send` payload at nodes.py:136/158). This tag-filter is what makes the design safe
under out-of-order parallel completion — a slice like `results[-len(chosen):]` would silently
break the moment two dispatch rounds interleave in the appended list.

**`should_iterate` routing.** The evaluator node itself decides whether to continue
(`vuln_found = len(successful) > 0` and `can_iterate = new_iteration < max_iterations and
vuln_found`, nodes.py:237-243) and writes `should_continue_iterating` into state. The graph's
conditional edge `should_iterate(state)` (graph.py:35-50) is a thin router that reads that flag:

```python
return "strategist" if state["should_continue_iterating"] else "reporter"
```

wired via `graph.add_conditional_edges("evaluator", should_iterate, {"strategist": "strategist",
"reporter": "reporter"})` (graph.py:84-91). Looping back to `strategist` triggers a fresh
deterministic batch of ≤3 strategies and new branch IDs. `max_iterations` is bounded by the
configured strategy count and the explicit iteration counter; there is no accidental random
omission of later strategies.

Checkpointing is SQLite-backed (`compile_graph()`, graph.py:104-134): `SqliteSaver` keyed by
`thread_id = run_id` (orchestrator.py:121-126), so a run's state can be resumed via
`GraphOrchestrator.get_state()` (orchestrator.py:171-188). A Mermaid diagram is generated via
`compiled.get_graph().draw_mermaid()` with a hand-written fallback (`_fallback_mermaid()`,
graph.py:158-184) if that API call fails.

---

## 2. Attacker contract

`AttackerAgent.attack_branch()` (`agents/attacker.py:159-285`) generates and executes exactly one
payload per branch invocation. It never judges success itself — `success=False` and `score=0.0`
are hardcoded on every returned `AttackResult` (attacker.py:274, 276) with a comment that the
evaluator determines both.

**`AttackerOutput` schema** (`llm/schemas.py:33-71`), produced via
`llm.build_structured_chain(system_prompt, AttackerOutput)` (attacker.py:128) — i.e. Bedrock's
structured-output mode, never free-text parsing:

- `status: Literal["OK", "ATTACKER_REFUSED"]` — first-class refusal outcome (schemas.py:41-45).
- `capability_type`, `technique_id`, `depth` — echoed straight back from the input branch; the
  attacker's own echoes are overwritten by the caller anyway (`output.capability_type =
  branch.capability_type`, etc., attacker.py:206-208) so the LLM cannot drift the branch's
  assignment.
- `payload` — empty when refused, otherwise the literal string sent to the target
  (schemas.py:49-56).
- `mutation_of_parent` — required to describe what changed vs. the parent attempt when
  `depth > 0`, null at depth 0 (schemas.py:62-66) — this is how the system's depth-based
  mutation lineage is tracked (though the default 3-node graph only ever dispatches at
  `depth=0`; `mutation_of_parent`/`parent_evidence` plumbing exists for deeper recursive attack
  trees built by other callers of `attack_branch`).

**Hard-refusal short-circuit.** If `output.status == "ATTACKER_REFUSED"` (attacker.py:213-234),
the function returns immediately with `prompt=""`, `response=""`, `success=False`,
`severity=INFO`, and `indicators={"_refused": True, "refusal_reason": ...}` — **the target
adapter's `execute_attack()` is never called**. This means a refused branch produces zero network
traffic to the target and zero LLM-judge cost on the evaluator side; it's purely logged. This is
distinct from the LLM-call-failure fallback path (`_fallback_output()`, attacker.py:144-157),
which is only triggered when the Bedrock call itself raises (network/throttling) and substitutes
one of the static `_FALLBACK_PAYLOADS` (attacker.py:32-69) — a fallback payload still gets sent to
the target, unlike a genuine refusal.

**technique_id → ASI taxonomy mapping.** `technique_id` on every `AttackBranch` is set once, in
`dispatch_attacker_branches`, from `taxonomy.lookup(strategy.value, "")` (nodes.py:116) — the
ASI class computed at dispatch time before the attacker ever runs. `evaluation/taxonomy.lookup()`
(`taxonomy.py:37-67`) resolves `(strategy, component)` pairs against the static
`configs/asi_taxonomy.yaml` mapping list using three-tier precedence: exact strategy+component >
strategy+wildcard component (`component: "*"`) > global wildcard fallback (`strategy: "*",
component: "*"` → `ASI01`/`AML.T0051.000`, taxonomy.py:16, 94-97). Since the attacker call site
passes `component=""`, dispatch-time resolution always lands on the strategy+wildcard tier (e.g.
`prompt_injection` → `ASI01`/`AML.T0051.001`, `asi_taxonomy.yaml:38-41`). The evaluator later
re-resolves taxonomy with the *actual* observed component once the LLM judge reports one
(evaluator.py:253-258), which can promote the ASI class to a more specific mapping (e.g.
`tool_misuse` + `employee_lookup` → `ASI02`/`AML.T0051.002`, `asi_taxonomy.yaml:23-26`).
`technique_spec` on the branch (used in the attacker's prompt) comes from
`evaluation/technique_specs.get_spec(asi_class)` (technique_specs.py:39-41), which loads static
`{spec, expected_failure, expected_safe_behavior}` text from `configs/technique_specs.yaml` keyed
by ASI class — deliberately static/auditable rather than LLM-authored per call
(technique_specs.py:3-4).

---

## 3. Evaluator

`EvaluatorAgent.evaluate()` (`agents/evaluator.py:77-415`) implements what the module docstring
calls a "4-case consensus" between deterministic pattern detectors and an LLM judge
(evaluator.py:80-86):

| Case | Deterministic | LLM signal | Verdict | `result.success` | `verdict_path` |
|---|---|---|---|---|---|
| 1 | hit | success/failure (not inconclusive) | `confirmed`, high confidence | `True` | `consensus` (evaluator.py:314-322) |
| 2 | hit | inconclusive | `confirmed`, medium confidence | `True` | `deterministic_only` (324-330) |
| 3 | miss | success (score ≥ threshold) | `unconfirmed`, low confidence | `False` | `llm_only` (332-338) |
| 4 | miss | anything else | `inconclusive` or `failed` | `False` | `heuristic_fallback`/`llm_only` (340-345) |

Only Cases 1 and 2 set `result.success = True` — Case 3 ("judge says yes, deterministic missed
it") is explicitly **not** treated as a confirmed finding; it requires human confirmation before
escalating (evaluator.py:338 comment). The deterministic phase (evaluator.py:133-215) runs
strategy-specific scanners — canary-token exfiltration check first as highest-confidence
(evaluator.py:139-145), then a PII/credential regex scan (147-158), then one of eight
strategy-specific analyzers (`PromptInjectionTool`, `ToolAbuseTool`, `MemoryPoisoningTool`,
`RAGProbeTool`, `JailbreakTool`, `InstructionHierarchyTool`, `WorkflowManipulationTool`,
161-210) selected by `result.strategy_type`. Hits are mapped to canonical names via
`_DET_HIT_NAMES` (evaluator.py:33-43, e.g. `canary_exfiltration → CANARY_TOKEN_EXFILTRATED`) and
passed to the LLM judge as `deterministic_hits` in its prompt (evaluator.py:225) so the judge's
narrative can't contradict hard evidence — and if it tries to anyway (`_CONTRADICTION_PHRASES`
like "did not reveal", evaluator.py:261-266, 284-291), the evaluator overwrites
`evidence_summary` with a canned description of the deterministic hit.

**Per-ASI thresholds.** `_get_threshold()` (evaluator.py:58-64) looks up
`configs/thresholds.yaml`'s `per_asi_class` map, falling back to `defaults.medium = 0.5`. The
file (`thresholds.yaml:1-18`) sets tighter thresholds for higher-stakes classes — e.g. `ASI03`
(privilege escalation) and `ASI10` at `0.70`, `ASI04`/`ASI08` (sensitive data / retrieval
poisoning) looser at `0.55–0.60`. This threshold gates Case 3's `llm_judge_score >= threshold`
check (evaluator.py:332, 296-299) and is stored on the result as `score_threshold` for auditability
(evaluator.py:98).

**Architecturally unusual: the evaluator owns the iterate/report decision.** There is no
separate controller/router node deciding whether to loop — `node_evaluator` in `nodes.py`
computes `vulnerability_found` and `should_continue_iterating` directly from
`result.success` on every accumulated `attack_results` entry (nodes.py:236-243), and the graph's
conditional edge (`should_iterate`, graph.py:35-50) is a pure state-read with no logic of its
own. This means the *evaluation* layer — not a dedicated orchestration/strategy node — is the
sole authority on both "is this a real finding" and "should the campaign keep attacking." A
controller node deciding independently whether to loop (e.g. based on attempt budget alone)
would need to duplicate or second-guess this success signal; instead the loop-continuation logic
lives entirely inside the agent whose job is to judge attack outcomes.

`finding_id` is minted by the evaluator (not the attacker) once `component` is known:
`sha256(f"{target_id}:{component}:{strategy_val}:{asi_class}")[:16]` (evaluator.py:349-354) — a
content-addressed key, stable across runs and re-derivable independently for audit (also see §5).

---

## 4. Generic target adapter

`cyber-redteam-foundry/src/cyberredteam/tools/target_adapter.py` defines `HttpTargetAdapter`,
the adapter used whenever `target_id` looks like a URL (`node_attacker_branch`,
nodes.py:166-173) — this is what lets the system attack **any** HTTP JSON agent, not just the
local `target_agent` HTTP fixture service; production targets are external HTTP agents.

**`_render_request_body()`** (target_adapter.py:14-23) substitutes a literal `"{{PROMPT}}"`
placeholder (must appear in quoted-string position, `_PROMPT_PLACEHOLDER = '"{{PROMPT}}"'`,
line 11) inside a caller-supplied JSON template string:

```python
rendered = template.replace(_PROMPT_PLACEHOLDER, json.dumps(prompt))
```

Using `json.dumps(prompt)` rather than naive string interpolation is the key correctness trick:
`json.dumps` produces an already-quoted, escaped JSON string literal, so the substitution stays
valid JSON regardless of quotes, newlines, or unicode inside the adversarial payload
(target_adapter.py:18-21 docstring). This is what lets templates like `{"messages":
[{"role":"user","content":"{{PROMPT}}"}]}` work for arbitrary target request schemas
(docstring at 93-95).

**`_extract_by_path()`** (target_adapter.py:26-43) is a dot-path JSON walker for pulling the
reply text out of an arbitrary response shape, e.g. `choices.0.message.content`. It splits the
path on `.` and, at each segment, indexes into a list via `int(segment)` if `current` is a list,
or dict-key-accesses otherwise; any `KeyError`/`IndexError`/`ValueError`/`TypeError` returns
`None` so callers can fall back to heuristics rather than crash. Numeric path segments (`"0"`)
are the list-index support called out in the task — `choices.0.message.content` therefore walks
`data["choices"][0]["message"]["content"]`.

**Backward compatibility.** `HttpTargetAdapter.__init__` (target_adapter.py:75-116) makes
`api_key`, `headers`, `request_template`, and `response_path` all optional. When
`request_template` is omitted, `execute_attack()` falls back to `{"message": prompt}`
(target_adapter.py:138-140); when `response_path` is omitted or doesn't resolve, it falls back to
key-guessing over `response`/`output`/`content`/`text`, finally `str(data)` (152-168). This means
the original `target_agent` stub's `{"message": ...}` contract keeps working untouched even
though the adapter now supports arbitrary schemas — no field is required to preserve old
behavior. `execute_attack()` also detects Docker (`/.dockerenv` or `RUNNING_IN_DOCKER=true`) and
rewrites `localhost:9000`/`127.0.0.1:9000` in the endpoint to `host.docker.internal:9000`
(target_adapter.py:101-106) — the piece that connects to the Docker-topology decision in §8.

---

## 5. Storage & dedup

`storage/models.py` defines the SQLAlchemy schema across (among others) three artifact tables
central to the findings pipeline:

- **`findings`** (`FindingRecord`, models.py:64-83) — the canonical, cross-run vulnerability
  record: `finding_id` (primary key, sha256-derived per §3), `status` (default `"open"`,
  indexed), `seen_in_runs` (JSON list), `embedding` (JSON — the dedup vector, see below).
- **`evaluator_verdicts`** (`VerdictRecord`, models.py:86-105) — one row per evaluator call:
  `deterministic_score`, `llm_judge_score`, `consensus_score`, `verdict`, `verdict_path`,
  `rationale`. This is the audit trail for *why* a given verdict fired, independent of the
  finding it rolled up into.
- **`attack_traces`** (`TraceRecord`, models.py:108-120) — verbatim, unsanitized
  `adversarial_input` / `target_response` / `tool_calls_observed`, explicitly for "Phase 4
  replay" (comment at 109) — kept separate from `findings` so raw attack text (which may contain
  the sanitization-triggering keywords the evaluator strips before sending to its LLM judge, see
  evaluator.py:113-131) isn't mixed with the sanitized/aggregated record.

**Dedup key.** `finding_id = sha256(f"{target_id}:{component}:{strategy}:{asi_class}")[:16]`
(evaluator.py:351-353) — the same `(target, component, strategy, asi_class)` tuple always
produces the same finding, so `upsert_finding()` (`artifact_store.py:172-242`) either creates a
new `FindingRecord` or, if one with that `finding_id` already exists, just appends the new
`run_id` to `seen_in_runs` and promotes severity if this run's result is worse
(artifact_store.py:234-239). This is exact-match dedup on the identifying tuple.

**Semantic dedup.** On *insert* (i.e. no exact `finding_id` match), `upsert_finding()` also
computes a sentence-transformers embedding of the adversarial input
(`embed()`, `storage/embedder.py:19-31`, using `all-MiniLM-L6-v2`, 384-dim, loaded lazily) and
compares it via cosine similarity (`semantic_similarity()`, embedder.py:46-56) against every
*other* open finding for the same `target_id` (artifact_store.py:192-206). If similarity ≥ 0.92,
it does **not** merge automatically — it logs a warning and sets
`finding_data["_duplicate_candidate"]` for surfaced review (artifact_store.py:201-206) — semantic
near-duplicates (different exact tuple, same underlying vulnerability worded differently) are
flagged for a human, not silently collapsed.

**Finding lifecycle state machine.** `_VALID_TRANSITIONS` (artifact_store.py:245-250):

```
open           → wont_fix | false_positive | inconclusive
inconclusive   → open | wont_fix | false_positive
wont_fix       → (terminal)
false_positive → (terminal)
```

`transition_finding_status()` (artifact_store.py:252-287) enforces this strictly — it raises
`ValueError` on any transition not in the allowed list, and additionally *requires*
`metadata["reviewer_id"]` and `metadata["rationale"]` for `wont_fix`/`false_positive`
(artifact_store.py:277-281). There is no automated `open → remediated`/`fixed` transition
anywhere in this table — the state machine only ever moves a finding to a closed-without-fix
state, and only via an explicit, attributed manual call. This is a deliberate design choice: the
system flags and tracks findings but never claims a vulnerability has been fixed on its own
authority.

---

## 6. Auth & LLM wiring

**Bedrock wrapper.** `llm/factory.get_llm()` (`factory.py:91-144`) builds a
`ChatBedrockConverse` instance (`langchain_aws`) directly — `model=model, region_name=... ,
temperature=0.7, max_tokens=2048` (factory.py:130-135) — and wraps it in `ObservableLLM`
(`llm/bedrock.py:31-241`). `ObservableLLM` exists purely for LCEL chain construction plus
observability: `build_structured_chain()` (bedrock.py:72-93) composes
`ChatPromptTemplate | llm.with_structured_output(schema)` and wraps it in `.with_retry(
retry_if_exception_type=(botocore.exceptions.ClientError,), wait_exponential_jitter=True,
stop_after_attempt=settings.max_retries)` — so every structured call (attacker, evaluator) gets
automatic retry on Bedrock throttling. Every invocation logs agent name, model, latency, and
sha256 input/output hashes (`_log_call()`, bedrock.py:172-209), optionally persisted to the
`llm_calls` table via the store (models.py:48-61).

There is **no mock/fallback LLM path** — `get_llm()` raises `RuntimeError` if `AWS_REGION` isn't
set (factory.py:115-120), with the comment "we never fall back to fabricated output — a security
tool that invents findings is worse than one that fails" (factory.py:108-109).

**Model-per-agent selection.** `_DEFAULT_MODELS` (factory.py:36-41) assigns different Bedrock
models by role — e.g. `attacker: deepseek.v3-v1:0` vs. `strategist/evaluator/reporter:
qwen.qwen3-coder-480b-a35b-v1:0` — overridable via `configs/models.yaml`
(`get_model_for_agent()`, factory.py:64-81). the target adapter only sends HTTP requests
for the simulated target (`get_model_for_agent("target")`, target_adapter.py:196), deliberately
using a distinct model so the target's responses aren't correlated with the attacker's generation
(target_adapter.py:191-193 comment).

**Bearer-token auth.** The backend's `require_auth()` (`api.py:29-43`) is registered as an
app-level FastAPI dependency (`FastAPI(dependencies=[Depends(require_auth)])`, api.py:51-53),
so every route requires it. It fails closed: if `settings.api_secret_key` (i.e. `API_SECRET_KEY`
env var, `settings.py:30`) isn't set, every request gets `503` rather than running open
(api.py:36-40); otherwise it checks `Authorization: Bearer <token>` matches exactly
(api.py:41-43). The browser no longer receives that bearer credential. It calls a same-origin,
read-only proxy: Vercel holds `CANARY_API_URL` and `CANARY_API_TOKEN` as server-only variables,
while Docker nginx expands `API_SECRET_KEY` only in its upstream configuration. The GitHub Action
uses its own repository secret. Thus a `VITE_*` build variable never carries a Canary API token.

---

## 7. Frontend data flow

**`canary/src/lib/api.ts`** centralizes all backend calls behind `apiFetch<T>()`
(api.ts:22-33), which injects `authHeader()` and normalizes error bodies into `ApiError` (with
`.status` preserved, api.ts:14-20) so callers can distinguish "backend explicitly rejected this"
from "network failure."

**SSE handling — the buffering fix.** `runCampaignSSE()` (api.ts:77-113) POSTs to
`/api/campaigns/run` and manually drives the streaming body via `res.body.getReader()` rather
than `EventSource` (which can't send a POST body/custom auth header). The read loop
(api.ts:99-112):

```js
let buffer = ''
while (true) {
  const { done, value } = await reader.read()
  if (done) break
  buffer += decoder.decode(value, { stream: true })
  const lines = buffer.split('\n')
  buffer = lines.pop() ?? ''   // keep incomplete last line
  for (const line of lines) {
    if (!line.startsWith('data: ')) continue
    try { onEvent(JSON.parse(line.slice(6))) } catch { /* skip malformed */ }
  }
}
```

The load-bearing detail is `buffer = lines.pop() ?? ''`: a chunk boundary from `reader.read()`
can split a single SSE `data: {...}` line across two `Uint8Array` chunks (TCP/HTTP chunking gives
no guarantee that a `data:` line arrives whole). Without holding back the last (potentially
partial) line and re-prepending it to the next chunk's decoded text, `JSON.parse` on a truncated
line would throw and — worse — the second half of that event would then be misread as a
freestanding line and silently dropped, not just delayed. This is a real fix for observed
mid-stream corruption, not a defensive no-op.

**`RunAuditPage.tsx`** (`canary/src/pages/RunAuditPage.tsx`) is the primary consumer:
`runRealCampaign()` (lines 278-305) calls `runCampaignSSE()` with the campaign payload
(target URL, selected techniques, optional headers/`request_template`/`response_path` — all
omitted-if-blank, per the comment at lines 279-281, to keep the default `target_agent` stub
contract untouched) and a `handleSSEEvent` dispatcher (lines 255-275) that switches on
`event.type` (`agent_state`, `log`, `finding`, `campaign_complete`) to drive local component
state (`updateAgent`, `fireEdge`, `appendLog`, `setReport`).

**Console feature.** `canary/src/components/console/` (`ConsoleLayout.tsx`, `ChatPanel.tsx`,
`AgentGraphPanel.tsx`, `Sidebar.tsx`) is a chat-command interface layered over the same
campaign/SSE machinery. User input is parsed by `parseCommand()`
(`canary/src/lib/commands.ts:31-68`) into a small discriminated union (`CONNECT`, `RUN`,
`SHOW_FINDINGS`, `SHOW_COVERAGE`, `RERUN_LAST`, `EXPORT`, `HELP`, `UNKNOWN`, ...) — e.g. `run
prompt_injection,jailbreak` splits on commas and partitions tokens into valid vs. `invalid`
technique IDs against the static `TECHNIQUE_IDS` list (commands.ts:43-47). `ChatPanel.tsx`
dispatches on the parsed `Command` (line 99) and falls through to
`say('error', 'Unrecognized command...')` for `UNKNOWN` (line 176).

State is centralized in **`canary/src/store/useConsoleStore.ts`**, a `zustand` store
(`create<ConsoleStore>(...)`, line 46) holding `targetUrl`, `selectedTechniques`, `campaignId`,
`phase`, `agentStatuses`, `logs`, `findings`, `report`, `chatMessages`, and `runHistory`. Actions
are plain `set()` calls — e.g. `appendLog` (lines 78-81) appends a timestamped entry, `fireEdge`
(69-76) flashes `activeEdge` for 1200ms via a module-level timer, `addRunHistory` (106) dedupes by
`campaign_id` on insert.

**IndexedDB run history.** `canary/src/lib/db.ts` wraps `idb-keyval` (`get`/`set`/`del`/`keys`)
with a `canary-run:` key prefix (db.ts:4): `saveRun()` (6-8) persists a completed campaign's
`CompletePayload` keyed by `campaign_id`; `loadRunHistory()` (10-15) filters all IndexedDB keys by
that prefix and loads them back for `Sidebar.tsx`'s history list. `ChatPanel.tsx:78` calls
`saveRun(payload).catch(() => {/* IndexedDB unavailable — history just won't persist */})` — a
save failure (private browsing, quota) degrades gracefully rather than blocking the chat flow.

---

## 8. Docker topology

`docker-compose.yml` defines exactly two services on a single bridge network (`canary-net`,
lines 9-11):

- **`redteam-backend`** — built from `cyber-redteam-foundry/Dockerfile`, runs
  `uvicorn cyberredteam.api:app --host 0.0.0.0 --port 8001 --timeout-keep-alive 300`
  (lines 20-24), env from `cyber-redteam-foundry/.env`, `RUNNING_IN_DOCKER=true` set explicitly
  (line 28) — this is exactly the flag `HttpTargetAdapter.__init__` checks
  (`target_adapter.py:102`) to decide whether to rewrite `localhost:9000` endpoints. Port 8001
  is published to the host both for direct FastAPI inspection and because nginx proxies to it
  internally (comment at lines 1-3).
- **`canary-frontend`** — built from `canary/Dockerfile`, publishes host port 8000 → container
  port 80 (nginx), and `depends_on: redteam-backend`. nginx receives `API_SECRET_KEY` only as a
  runtime environment variable and injects it into upstream API requests; the static bundle has
  no API token.

**`target_agent` deliberately runs outside Docker**, as a bare host process:
`PYTHONPATH=src python -m target_agent.server --port 9000` (comment at docker-compose.yml:6,
also referenced at target_adapter.py comments). `redteam-backend` reaches it via
`extra_hosts: ["host.docker.internal:host-gateway"]` (lines 29-30), and
`HttpTargetAdapter.__init__` rewrites any `localhost:9000`/`127.0.0.1:9000` endpoint string in
the run config to `host.docker.internal:9000` when it detects it's running inside the container
(target_adapter.py:101-106).

**Why**: `target_agent` is only the bundled reference/stub target used for local demos and
default runs — the entire point of the generic `HttpTargetAdapter` (§4) is that the backend can
attack *any* HTTP JSON agent reachable from the host, including ones that are themselves running
directly on the host machine (a locally-run LangChain/AutoGen agent under test, a service bound
to `localhost`, etc.), not just a containerized version of the stub. Keeping `target_agent` as a
bare host process — rather than adding it as a third container on `canary-net` — keeps the
network topology honest: the backend reaches targets exactly the way it would reach any other
host-network agent under test, via `host.docker.internal`, instead of via Docker-internal DNS that
would only work for containerized targets.
