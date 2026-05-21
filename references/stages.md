# Stage Detail Reference

Detailed design and implementation guidance for each pipeline stage.
Load this when implementing or debugging a specific stage.

See also: `implementation.md` (code sketches), `schemas.md` (data formats).

---

## Stage 1 — Ingestor

**Goal:** convert a repo into a flat, typed snippet database that fits agents
into budget-bounded context windows, enriched with historical context.

See `stages/ingestor.py` for the implementation.

### Chunking rules

- Unit: **function** for C/C++/Rust/Go; **method** for Python/Java/TS.
  Fall back to fixed 200-line windows for languages without reliable function
  boundaries.
- Hard cap: **800 tokens per snippet** (leaves budget for ~250 snippets per
  pack at 85% context window). Use `tiktoken` with `cl100k_base` encoding.
- Large functions: split at logical boundaries, emit `continuation: true` on
  subsequent pieces so the chainer can reconstruct.
- Cross-file context: embed 3-line caller/callee stubs inline — agents need
  the call signature without fetching another snippet.

### Snippet IDs

Use short sha256 IDs for readability: `sha256:{h[:6]}:{h[-6:]}` (e.g.
`sha256:e812b9:ab0d84`). Full sha256 is unnecessarily verbose in logs and
finding references.

### Security tags

| Tag | Triggers |
|---|---|
| `memory` | `malloc`, `free`, `memcpy`, `ptr`, raw buffer ops |
| `external-input` | arg from network/file/env touching this function |
| `auth` | password, token, session, credential, permission |
| `crypto` | cipher, hash, key, IV, nonce, signature |
| `ipc` | socket, pipe, shm, mmap |
| `unsafe` | `unsafe` block (Rust), `reinterpret_cast` (C++) |
| `format-string` | `printf`-family with non-literal format arg |
| `integer-arith` | ops on sizes/lengths/indices without bounds check |

### Tag inflation warning (from zlib run)

Simple keyword matching for `external-input` is **too aggressive for compiled
libraries.** The keywords `buf`, `arg`, `len`, `src` appear in nearly every C
function signature. On zlib, this tagged 607/608 functions (99.9%) with
`external-input`.

**Mitigation:** for library targets, either:
1. Remove `external-input` from all domain tag filters EXCEPT `data-flow`, or
2. Use a smarter heuristic for `data-flow`: detect actual I/O syscall wrappers
   (`read()`, `recv()`, `fgets()`, `fread()`) rather than parameter names.

Same applies to `integer-arith`: `len`, `size`, `count` match every
buffer-processing function. Narrow to operations on untrusted lengths only.

### Directory filtering (from zlib run)

Contrib, examples, and test directories contain unmaintained or harness code
that inflates snippet counts without representing the real attack surface.
On zlib, ~200 of 608 snippets came from these directories.

**Recommendation:** before building packs, filter the snippet DB to remove:
- `contrib/` — third-party, unmaintained, or single-use code
- `examples/` — demo/illustration code, not production
- `test/` — test harnesses and fixtures
- Any directory matching `^\.` — hidden/system directories

### Historical Context Mining (Recon Enhancement)

Enhance the Ingestor stage by mining git history for past security patches:
- Search git log for security-related commits: `git log --grep='CVE\|security\|vuln\|sec:\|fix.*auth\|fix.*injection\|sanitize\|escape\|bypass' --oneline -50`
- For each relevant commit, identify the fixed pattern and grep the codebase for similar idioms
- Seed initial hunt tasks against unpatched copies of vulnerable patterns (sibling files)
- This adds zero cost on repositories without security history but catches cross-component bugs when present

---

## Stage 2 — Recon

**Goal:** map the repo before hunting — identify subsystems, build system,
entry points, and generate structured hunt tasks with concrete file targets
per attack class. Without this stage, the Coordinator builds packs from the
entire snippet DB with no prioritization, wasting context on irrelevant code.

### Recon Agent Mission

Analyze the repository and produce a prioritized list of hunt tasks:

1. **Identify subsystems** — top-level directories, module boundaries,
   core vs. test vs. example code. Output a subsystem map.
2. **Detect build system** — `Makefile`, `CMakeLists.txt`, `Cargo.toml`,
   `pyproject.toml`, `go.mod`. This tells you which code is actually compiled.
3. **Locate entry points** — `main()`, exported symbols, signal handlers,
   inbound API routes, plugin interfaces, callback registrations.
4. **Generate hunt tasks** — for each attack class, list which files to
   target and why.

### Recon Output Schema

```json
[
  {
    "task_id": "t_core_mem-safety_1",
    "domain": "mem-safety",
    "attack_class": "buffer-overflow",
    "target_files": ["src/decompress.c", "src/stream.c"],
    "rationale": "Decompression reads untrusted input into fixed buffers",
    "priority": "high"
  }
]
```

The Recon output is consumed by the Coordinator, which filters snippets to
only the `target_files` before building domain packs.

### What Recon Prevents

- **Inflated packs** — without target file filtering, the Coordinator includes
  every function from the snippet DB. Recon narrows each pack to the relevant
  subsystem, typically cutting pack size by 40-60%.
- **Wasted context** — test harness code, contrib/ code, and unrelated modules
  are excluded before hunters ever see them.
- **Missing entry points** — without explicit entry-point identification,
  hunters miss attack surface (e.g., signal handlers, callback exports).

---

## Stage 3 — Coordinator

**Goal:** build per-agent **context packs** — curated snippet subsets scoped to
one security domain — so each agent can be cold-started with no repo access.

See `stages/coordinator.py` for the implementation.

### Agent domains (11-domain set)

| Agent | Tags selected | Exclusive | Focus |
|---|---|---|---|
| `mem-safety` | `memory`, `integer-arith`, `unsafe` | Yes | Buffer overflow, OOB R/W, UAF, integer wrap |
| `auth` | `auth` | No | Bypass, privilege escalation, session fixation |
| `crypto` | `crypto` | Yes | Weak primitives, IV reuse, padding oracle, key mgmt |
| `ipc` | `ipc` | No | TOCTOU, injection via pipes/sockets |
| `data-flow` | `external-input` | No | Untrusted data reaching sinks |
| `format-str` | `format-string` | Yes | Format string exploits |
| `injection` | `external-input` | No | Command injection, argument injection through untrusted data |
| `path-traversal` | `memory` | No | File path traversal, symlink attacks through buffer ops |
| `concurrency` | `memory` | No | Race conditions, TOCTOU, signal safety, double-fetch |
| `resource` | `memory`, `integer-arith` | No | Resource exhaustion, memory leak, file descriptor leak |
| `secrets` | `crypto` | Yes | Hardcoded secrets, credential exposure, improper secret handling |

**Exclusive domains** (`mem-safety`, `crypto`, `format-str`, `secrets`): only
get snippets whose tags match their domain tag list. Non-exclusive domains get
snippets matching their tags AND any snippet from the full DB that lacks any
targeted tag — ensuring coverage of untagged code.

**`DOMAIN_ORDER`**: `["mem-safety", "data-flow", "crypto", "format-str",
"injection", "path-traversal", "concurrency", "resource", "secrets",
"auth", "ipc"]` — dependency-ordered so memory/crypto are processed before
derivative domains.

Embed a `SECURITY_CONTEXT.md` per repo in every pack: entry points, trust
boundaries, known-unsafe modules, memory allocator in use, sanitizer flags.

### Scope Notes Integration

Incorporate scope notes to exclude specific components or attack classes:
- Accept verbatim scope notes from operator
- Append scope notes verbatim to every stage's user_input
- Have agents honor exclusions listed in scope notes during processing

### Budget enforcement

Each pack must not exceed **85% of the model's context window** (the remaining
15% is reserved for the model's output). For example, a 100k-context model
allows an 85k pack budget. If a domain exceeds budget, split into sub-packs
by directory prefix and run multiple instances in parallel.

### Pack size observations

Expected relative sizes for a compiled-language library with ~350 functions:

| Domain | Relative pack size | Notes |
|---|---|---|
| `mem-safety` | Largest | Most C/C++ functions touch memory |
| `ipc` | Large | `external-input` tag overlap inflates it |
| `auth` | Large | Same inflation from `external-input` overlap |
| `data-flow` | Large | Single tag, still large |
| `crypto` | Medium | Sparse unless crypto-specific code |
| `format-str` | Small | Very few printf-family calls in most codebases |

**Key takeaway:** `external-input` tag overlap inflates ipc/auth packs. In a
pure C library, mem-safety dominates. Some domains will produce honest coverage
gaps (auth, crypto, ipc) — this is normal for libraries with a narrow
functional scope. The gapfill stage should re-queue these with narrowed scope.

---

## Stage 4 — Hunter Cluster

Each agent receives its context pack and a domain-scoped system prompt.

Run agents in parallel. See `stages/runtime.py` for the implementation.

### Model Selection

Use your highest-capability model for `mem-safety`, `data-flow`, and
`crypto` — these require deep reasoning. A faster/cheaper model tier is
acceptable for `format-str` and `ipc`, which are more pattern-driven.

See `stages/runtime.py` for the `MODEL_BY_DOMAIN` dict.

### Model Fallback Chain (Important: Free-Tier Reality)

OpenRouter free-tier models are **frequently rate-limited (HTTP 429)**.
A single model per domain is not enough. You must implement a fallback
chain: try models in order of context length (descending), skipping
to the next on 429 or API error.

Implementation pattern:
1. Fetch all free models from `GET /v1/models` at startup.
2. Filter to `:free` suffix, sort by `context_length` descending.
3. Run a **parallel health check** against all models (8 workers).
4. Remove DEAD models from the chain so the pipeline does not waste
   time on them. Cache the health check result.
5. Start at the preferred model index; on 429, advance to next model.
6. 2 attempts per model before advancing (handles transient errors).
7. Retry on 502/503/504 too — these are transient provider overloads,
   not permanent failures.

With multi-provider, the model list is defined in config/defaults.json.

**Key observation:** Out of 24 free models on OpenRouter, only ~6 are
reliably available at any moment. The rest return 429 or empty responses.
Health check at startup removes the dead ones before any work begins.
The fallback chain is not optional — it is required for completion.

### Sync > Async (Practical Lesson)

Use **sync urllib**, not async httpx. Key reasons:
- Rate-limit handling is simpler in sync flow (no asyncio coordination)
- OpenRouter free-tier has hidden per-connection rate limits that
  async parallelism triggers more readily
- `ThreadPoolExecutor` with 3-4 workers provides sufficient parallelism
  without hitting rate limits
- No dependency on `httpx` or `aiohttp`

### Provider-Specific Notes

#### OpenRouter

- **`openrouter/openrouter/free` is NOT a valid model ID.** Use concrete
  model IDs like `deepseek/deepseek-v4-flash:free`. Fetch the full list
  from `GET /v1/models` and filter by `:free` suffix.
- **Model fallback chain is mandatory.** Free tier returns HTTP 429 on most
  models most of the time. Without the fallback, the pipeline stalls.
- **Reasoning models** put output in `message.reasoning`, not `message.content`.
- **Some models return empty response bodies.** Detect these and skip to
  the next model immediately. About 1/3 of free models exhibit this.
- **API errors without `choices`**: Always guard against `KeyError`.
- **Proxy support**: Set `https_proxy` env var; urllib respects it natively.
- **`max_tokens` must be 8192 minimum** — reasoning models consume large
  output budgets for chain-of-thought. 4096 causes truncation.
- **Auth**: Read API key from script-relative `auth.json` first, then
  `~/.local/share/opencode/auth.json`, then the corresponding `*_API_KEY`
  env var (`OPENROUTER_API_KEY`, `GROQ_API_KEY`, `CEREBRAS_API_KEY`,
  `GOOGLE_API_KEY`, `ZEN_API_KEY`).
- **Retry on 502/503/504** — these are upstream provider overload, not
  permanent failures. Use exponential backoff.

#### Groq

- Requires `GROQ_API_KEY` in auth.json or env var.
- Base URL: `https://api.groq.com/openai/v1/chat/completions`
- Limited model selection but reliable uptime.
- Known to return HTTP 403 from non-US IP addresses (geo-blocking).
  Set `--proxy` to a US-based proxy if needed.
- No free-tier rate limits in practice.

#### Cerebras

- Requires `CEREBRAS_API_KEY` in auth.json or env var.
- Base URL: `https://api.cerebras.ai/v1/chat/completions`
- Smallest model selection.
- Also geo-blocked to US from some regions.
- Best for low-latency inference on smaller models.

#### Google (Gemini via OpenAI-compatible endpoint)

- Requires `GOOGLE_API_KEY` in auth.json or env var.
- Base URL: `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`
- Provides access to Gemini 2.5 Pro, Gemini 2.5 Flash, and Gemma models.
- Free tier: 1,500 RPM for Gemini Flash, generous rate limits.
- Uses the OpenAI-compatible v1beta endpoint — same chat completions format as all other providers.

#### Zen (opencode)

- Requires `ZEN_API_KEY` in auth.json or env var.
- Base URL: `https://opencode.ai/zen/v1/chat/completions`
- Also exposes non-standard endpoints at `https://opencode.ai/zen/v1/messages` (Anthropic-compatible) and `https://opencode.ai/zen/v1/responses`.
- **Free models** (no token cost, all use `zen:` prefix):
  - `zen:big-pickle` — stealth model, free for a limited time
  - `zen:deepseek-v4-flash-free` — DeepSeek V4 Flash, free for a limited time
  - `zen:minimax-m2.5-free` — MiniMax M2.5, free for a limited time
  - `zen:nemotron-3-super-free` — Nemotron 3 Super (NVIDIA), free for a limited time
- **Paid models** (per-token billing):
  - `zen:opus-4-2025-05`, `zen:sonnet-4-2025-05`, etc.

### Output Parser Robustness

Models produce wildly inconsistent JSON. The parser must handle:
1. **JSON arrays** at top level: `[{...}, {...}]` (valid JSON, unwrap)
2. **Wrapper objects**: `{"finding": {...}}` (unwrap the inner object)
3. **Free-text contamination**: text before/after the JSON (strip)
4. **Sentinel objects**: trailing `{"done": true}` or `{"coverage_gap": ...}`
   — match by field presence, not position
5. **Multiple JSON objects** on one line: split by `}\n{`
6. **Truncated output** from `max_tokens`: detect missing closing `]` or `}`
7. **Line-by-line JSONL** fallback: try parsing each line independently

Every finding must include `status: "raw"` and `poc_confirmed: false` as
defaults — the Validate stage updates these. If the model omits them, the
parser should inject them.

See `stages/runtime.py` for the `parse_findings()` implementation.

### Per-Domain System Prompts

Domain guidance should be injected as a `guidance` field in the context pack:

| Domain | Focus |
|---|---|
| `mem-safety` | Buffer overflow, OOB R/W, UAF, integer wrap → allocation |
| `auth` | Bypass, privilege escalation, session fixation |
| `crypto` | Weak primitives, IV reuse, padding oracle, key management |
| `ipc` | TOCTOU, injection via pipes/sockets/shared-memory |
| `data-flow` | Untrusted data reaching dangerous sinks |
| `format-str` | Format string exploits with non-literal format arg |

### Parallelism and Debugging

- Use `ThreadPoolExecutor` with 3-4 workers (default: 3). Higher concurrency
  increases rate-limit risk on free-tier API providers.
- Implement `--max-run N` flag: process only the first N packs. Invaluable
  for debugging a single domain.
- Implement `--model MODEL` + `--validate-model MODEL` as separate flags.
- Progress bar via `\r` updates to stderr.
- Print all status/log to **stderr**, findings JSONL to **stdout**.

### Narrow Scope Principle

Each hunter agent must adhere to strict scoping:
- **One attack class per task**: Focus exclusively on the assigned attack class
- **Concrete target files**: Every finding must reference specific, verified files
- **Precise scope hint**: Must name the trust boundary above the sink
- **No generic catch-alls**: Use specific attack class names from the approved list
- **Logic chains exception**: Only multi-component chains may span multiple primitives, and only one chain per task

### Severity Assignment Guidelines

- **Critical**: Unauthenticated RCE, full auth bypass, arbitrary file read of secrets, fully-controlled SSRF reaching cloud-metadata/internal services
- **High**: Authenticated RCE, SQLi or path-traversal on reachable route, IDOR with sensitive data, auth-protected file overwrite
- **Medium**: Information disclosure of non-secrets, availability-degrading DoS, hardening flaws with real-but-narrow attack path
- **Low**: Defense-in-depth weaknesses not worth exploiting unless chained
- **Informational**: Notable patterns/code smells with no exploit path

### Prompt Design Patterns

| Pattern | Example |
|---|---|
| Narrow scope | `"Look for UAF in alloc_buffer() only"` |
| Trust boundaries | `"Attacker input enters at X, trust boundary at Y"` |
| Prior coverage | `"Area Z was audited in run N, skip it"` |
| Adversarial framing | `"Your job is to disprove this finding, not find new ones"` |
| Separate questions | Agent A: exploitable? Agent B: reachable from outside? |
| Historical context | `"Similar pattern was patched in commit ABC123; check unpatched siblings"` |
| Live target bias | `"Prefer techniques verifiable against http://target:8080"` |

### Validation Requirements

- All finding file paths must be repo-relative and verified to exist
- Zero findings with honest `gaps_observed` is valid output
- Never invent findings to fill queue; be conservative with severity
- Attempt PoC confirmation: if live_target provided, reproduce against service; otherwise compile/run locally
- If PoC fails, lower severity by at least one step or drop finding

---

## Stage 5 — Validate + Gapfill (inner loop)

### Validate (Adversarial Re-read)

The Validate stage employs an independent agent with different prompt and
model to attempt to *disprove* each finding:

- **Different model requirement**: Use a different LLM model than the Hunt
  stage to reduce correlated biases.
- **Role separation critical**: Validate agent has **no ability to generate
  new findings** — only assess existing ones.
- **Deliberate disagreement**: Two agents in disagreement >> one agent
  self-reviewing for accuracy.
- **Output format**: Add `status` field (`confirmed` / `rejected` /
  `needs-more-info`) and `validate_reason` to each finding.
- **Adversarial framing**: "Your job is to DISPROVE findings, not find new ones"
- **Include actual source code in the prompt**: Models cannot verify findings
  from descriptions alone. Look up the code snippet by `snippet_id` from the
  snippet DB and include it verbatim in the validate prompt. Without this, the
  validate model hallucinates confirmation of false positives. With code context,
  the same model correctly rejects the finding.

See `stages/validate.py` for the implementation.

### Output persistence

Validated findings must be written to `output/validated.jsonl` alongside the
main `findings.jsonl`. This enables `--validate-only` / `--resume` mode to
replay validation without re-running the Hunt stage.

### Gapfill (Coverage-Driven Re-queueing)

Hunters' `coverage_gap` records are re-queued as new scoped Hunt tasks.
A simple retry with the same model and prompt produces the same empty output.
The gapfill loop rotates models and rephrases prompts to break symmetry:

- **Sentinel-only vs genuine coverage**: `{"done": true}` with no findings
  (sentinel-only) is distinguishable from "analyzed and found nothing."
  Sentinel-only means the model skipped analysis entirely — always retry.
- **Model rotation**: Each gapfill iteration uses a different model from the
  hunt pool (round-robin offset). Never retry with the same model that
  produced empty output.
- **Rephrased prompt**: Append meta-instruction: "The previous model produced
  no findings for this scope. Double-check each function carefully..."
- **Max 2 iterations**: Two different models with two differently phrased
  prompts. If both produce empty output, the gap is genuine.

See `stages/gapfill.py` for the implementation.

- **Coverage gaps** should specify: `{"coverage_gap":"<reason>","reason":"<detailed explanation>"}`
- Valid gap reasons: file size/complexity, lack of necessary context, time constraints
- Invalid gap reasons: laziness, disagreement with findings, desire to skip work
- Mark retried gaps with `gapfill_retried: true` to avoid infinite loops

---

## Stage 6 — Dedupe

Collapse findings sharing the same root cause to a single record.

### Root Cause Deduplication

- **Root cause focus**: Collapse findings sharing the same root cause to a single record
- **Not symptom-based**: The same UAF reported from 3 call paths is one bug, not three
- **Normalized key**: Embed `snippet_id` and `class` in a normalised key for comparison
- **Cluster identification**: Group findings with identical keys before surfacing to Report stage
- **Audit-specific enhancement**: Consider call stack similarity and taint propagation patterns

### Deduplication Criteria

Findings are considered duplicates when they share:
1. Same vulnerability class (e.g., `buffer-overflow`)
2. Same vulnerable function/snippet (same `snippet_id`)
3. Similar root cause context (equivalent taint propagation paths)
4. Same trust boundary crossing pattern

### Composite Key

In practice, dedup on `(snippet_id, class)` works well — it collapses
reports of the same bug class in the same function from different hunters.

Keep the highest-severity variant when collapsing duplicates.

For deeper dedup, extend the key to `(file, class, source_lines_start)` to
catch cases where different snippet continuations report the same issue.

---

## Stage 6b — Shield (Call Graph + Hallucination + Reachability)

**Goal:** apply three quality gates before findings reach the chainer:
call-path verification, hallucination detection, and static reachability
filtering.

See `stages/shield.py` for the implementation.

### Call-graph construction

Build a directed graph from snippet callee lists. Keys are lowercase function names.
This is the graph used by both the chainer and the shield.

### Call-path verification

**call_path must be normalized at parse time** (in `parse_findings()`), not in
the shield. Models return string-typed paths ~30% of the time (`"a -> b -> c"`
instead of `["a", "b", "c"]`). If the shield iterates the string character-by-
character, verification produces garbage — every path fails because `' '` and
`'-'` are not function names in the graph. By the time findings reach the
shield, `call_path` is already `list[str]` or the parse layer has a bug.

### Hallucination detection

Check that the finding's description references actual identifiers from the
snippet content. Use function-name presence + identifier overlap with a
60% threshold on description tokens and 70% on call-path names.

**Observation:** This filter caught 7/7 findings from one run — all were
generic security prose ("buffer overflow possible in memory copy operation")
mentioning none of the actual function names or variables in the snippet.
This is a cheap signal (regex + set intersection, no LLM call) that catches
vague/generic findings before they reach the chainer. If a specific model
consistently produces hallucinated findings (≥50% hallucination rate across
a run), demote it in the model pool.

### Static reachability filter (filter_unreachable)

BFS from `entry_points` (e.g., `["main", "sshd_main", "ssh_main"]`) through
the call graph to determine which findings are statically reachable.

**Critical: `snippet_db` parameter.** Findings reference snippet IDs, not
function names. `filter_unreachable()` must resolve `snippet_id → function
name` before doing BFS, or all findings will appear unreachable.

---

## Stage 7 — Chainer

**Goal:** detect clusters where multiple low/medium findings compose into a
higher-severity exploit chain.

See `stages/chains.py` for the implementation.

### Critical: graph key resolution

The call graph is keyed on **lowercase function names**, but findings reference
**snippet IDs** (e.g., `sha256:aee28b:65e614`). The chainer MUST resolve before
BFS traversal. Without this resolution, the BFS searches for `sha256:...` keys
that don't exist in the graph, producing **zero chains** even when the call
graph is valid. This is the single most common chainer bug.

### Call-graph Algorithm

1. Build call graph from `callees` in the snippet DB.
2. Resolve snippet IDs → function names for all finding pairs.
3. For each pair `(A, B)` where A is reachable from B in ≤ 4 hops (via BFS),
   emit a candidate chain.
4. Score candidates:
   - +2 if chain crosses a trust boundary (`external-input` → sink)
   - +1 per MEDIUM / +2 per HIGH / +3 per CRITICAL finding in chain
   - +1 if chain involves recently modified files (per `git log --oneline -20`)
   - -1 if chain involves well-tested or hardened areas
5. Submit top-N chains to a **chain reasoning agent** for detailed analysis.

### Logic Chain Definition

- **Normal case**: One attack class per task (one primitive vulnerability)
- **Exception**: Logic chains (multi-component attack sequences) are allowed as ONE task
- **Chain format**: `attack_class: logic_chain` with `scope_hint` naming the specific chain
- **Target files**: May span 2-3 files for a single logic chain task
- **Limitation**: Only one chain per task

### PoC Confirmation Loop (Isolation Requirements)

A finding with a PoC is actionable. A finding without one is speculation.

- **Isolation**: Run PoCs in isolated scratch environment with no production access
- **Live target preference**: When `--target-url` provided, reproduce against live service
- **Local fallback**: Otherwise compile/run in `$scratch_dir` using available interpreters/compilers
- **Validation**: If bug doesn't reproduce against live target, drop finding
- **Evidence capture**: Log raw request/response into `poc.code`/`poc.run_output`
- **Severity adjustment**: If PoC fails, lower severity by at least one step or drop finding
- **No external calls**: Bash usage limited to `$scratch_dir`; no network calls to external hosts (except live_target)

---

## Stage 8 — PoC Confirmation (Compile + Run)

**Goal:** disprove or confirm each finding by compiling and running a targeted
C program under AddressSanitizer. This is the strongest evidence level — a
compiler+ASan verdict beats any LLM opinion.

See `stages/poc.py` for the implementation.

### Why it matters

AI hunters produce ~60-80% false positive rates on audited codebases. Validate
catches some via adversarial prompting, but the gold standard is a concrete
execution: if the alleged buffer overflow does not crash under ASan, it does
not exist as described.

### Workflow

1. **Generate** — for each finding, auto-generate a C source file with test
   cases targeting the specific class and code path.
2. **Compile** — build with `gcc -fsanitize=address -g -O0`
3. **Run** — execute under ASan, capture exit code and stderr
4. **Compare** — expected (crash + ASan errors) vs actual (exit 0, no errors)
5. **Verdict** — `confirmed` if ASan errors, `rejected` if clean exit 0,
   `needs-more-info` if build failed or unexpected crash

### Output

Each PoC produces two files in `output/pocs/`:
```
poc-<snippet_id>-<class>.json   # Schema-valid PoC JSON
poc-<snippet_id>-<class>.c      # Compilable C source
```

### CLI integration

```
--poc <finding_id|all>    # Generate + compile + run during pipeline
--poc-only                 # Skip all API stages, just PoC cached findings
```

### Auto-detection of target context

The generator inspects the snippet content for library signatures:
- `z_streamp`, `inflate`, `zlib.h` → links `-lz`, generates inflate tests
- `SSL_CTX`, `SSL_new` → links `-lssl -lcrypto`
- No library signature → standalone C with `calloc`/`memset` bounds test

---

## Stage 9 — Trace

For confirmed findings in **shared libraries**: fan out one tracer agent per
consumer repository to determine reachability from each consumer's external
attack surface.

### Trace Agent Mission

- **Reachability proof**: Determine if attacker-controlled input can reach the vulnerable sink
- **Call path validation**: If reachable, provide the exact call path from entry point to sink
- **Consumer-specific analysis**: Analyze each consumer repo independently
- **Prioritization**: Unreachable findings → deprioritize; Reachable findings → escalate to Feedback stage

### Trace Agent Inputs

Tracer agent receives:
- The confirmed finding (with PoC and call path from original hunt)
- The consumer repository's snippet database
- A `SECURITY_CONTEXT.md` for the consumer
- Optional: live target URL and credentials for reproduction validation

### Trace Agent Output

Output: `reachable: true/false` with supporting evidence:
- If `reachable: true`: Include call path from consumer's external attack surface to the vulnerable sink
- If `reachable: false`: Provide reasoning why the path is blocked
- When possible, validate reachability against live target using provided credentials

### Safety Constraints

- Network egress restricted to live target host + `127.0.0.1` when `--target-url` is set
- No calls to external hosts beyond the specified target
- Findings that don't reproduce against live target are dropped or rejected
- Credentials flow into relevant stages as needed for live validation

---

## Stage 10 — Feedback

Reachable traces become new Hunt tasks in consumer repos, closing the cross-repo
propagation loop.

See `stages/feedback.py` for the implementation.

### Feedback Mechanism

- **Trace-to-task conversion**: Each reachable trace from the Trace stage generates new Hunt tasks in consumer repositories
- **Structural identity**: Feedback tasks are structurally identical to Stage 4 hunter tasks (same format, validation rules)
- **Known entry pre-loading**: The originating finding is pre-loaded in the context pack as a `known_entry` rather than discovered during hunting
- **Cross-repo propagation**: This closes the loop for vulnerability discovery across related codebases

### Feedback Task Composition

Each feedback task includes:
- `task_id`: `t_<subsystem>_<attack_class>_<n>`
- `attack_class`: Specific vulnerability class to hunt
- `scope_hint`: Trust boundary description from the validated trace
- `target_files`: Verified files from consumer repo where the vulnerability may exist
- `known_entry`: The validated trace finding that seeded this hunt
- `evidence_basis`: Reference to the original trace that proved reachability

### Propagation Rules

- **Reachability required**: Only traces proven reachable (`reachable: true`) generate feedback tasks
- **No fabrication**: Findings that don't reproduce against live targets are not propagated
- **Credential propagation**: When live targets are used, credentials flow into feedback tasks
- **Scope inheritance**: Feedback tasks inherit scope notes and exclusions from the original investigation

---

## Stage 11 — Report

See `stages/report.py` for the implementation.

### Structured bucket rationale

Every finding in the report must include a `bucket_rationale` field that
explains why it landed in its triage bucket. This makes triage decisions
transparent and auditable.

The report root should also include a `bucket_definitions` dictionary that
documents the criteria for each bucket.

### Triage buckets

| Bucket | Criteria |
|---|---|
| **Fix now** | CRITICAL individual; feasible chain score ≥ 5; HIGH + `external-input` reachable |
| **Backlog** | HIGH without external-input path; MEDIUM isolated; INFORMATIONAL design notes |
| **False positive** | No plausible call path; theoretical-only; sandbox/test-only code |

### Gap persistence

Gaps emitted by Hunt agents are persisted to `output/gaps.jsonl` alongside
`output/findings.jsonl`. This enables `--validate-only` to replay gaps into
the final report without re-running the Hunt stage.

### Validate-only mode

`--validate-only` skips the Hunt stage entirely and loads cached findings
from `output/findings.jsonl` (with gaps from `output/gaps.jsonl`). Useful for:
- Re-running Validate with a different model pool after a failed run
- Adjusting the validate prompt and re-validating existing findings
- Iterating on the report generation logic without burning API calls

The reporting agent validates its output against the schema and fixes errors
before emitting. Every `fix_now` finding must have a confirmed call path from
a known entry point (main, exported symbol, HTTP handler).
