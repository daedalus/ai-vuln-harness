# Implementation Reference

Code sketches and prompt templates for each harness stage.
Load this file when writing, reviewing, or debugging harness code.

---

## ingestor.py

Converts a repo into a flat, typed snippet database.

Uses `tree-sitter` (≥ 0.25, required) for AST-level function extraction.
Regex-based extraction is forbidden — it misses type-anchored re-exports
and nested-scope functions, creating silent coverage gaps.

Uses `tiktoken` (required, no fallback) for per-snippet token counting.
The character-based estimate (`len//4`) overestimates C code by 30-40%
and silently inflates pack sizes beyond the 85% context budget.

### Directory filtering

For library targets, exclude non-production code to focus on real attack surface:

```python
EXCLUDE_DIRS = {"contrib", "examples", "test", "tests", ".git"}

def should_include(path: Path) -> bool:
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return False
    return True
```

### Tag inflation mitigation

Simple keyword match on `external-input` hits nearly every C function.
Mitigate with narrower heuristics:

```python
# For data-flow: detect actual I/O syscall wrappers
IO_FUNCS = {"read", "recv", "fread", "fgets", "gets", "scanf"}

def has_io_syscall(node) -> bool:
    for child in node.children:
        if child.type == "call_expression":
            name = child.child_by_field_name("function")
            if name and name.text.decode() in IO_FUNCS:
                return True
    return False
```

For `integer-arith`, require an arithmetic operator (+, -, *, /) on the
same expression as a size/length variable rather than just matching keywords.

```python
# ingestor.py
from pathlib import Path
from tree_sitter import Language, Parser
import json, hashlib

# Token counting: tiktoken is required. No fallback.
import tiktoken
_enc = tiktoken.get_encoding("cl100k_base")
count_tokens = lambda text: len(_enc.encode(text))

def chunk_repo(root: Path, out: Path):
    snippets = []
    for f in root.rglob("*"):
        if f.suffix not in {".c",".cpp",".rs",".go",".py",".ts",".js"}: continue
        snippets += extract_functions(f)
    db = {s["id"]: s for s in snippets}
    out.write_text(json.dumps(db, indent=2))
    return db

def extract_functions(path: Path) -> list[dict]:
    source = path.read_text()
    tree = parser.parse(bytes(source, "utf8"))
    # Walk CUDA_FUNCTION / function_definition nodes
    for node in tree.root_node.children:
        if node.type == "function_definition":
            content = source[node.start_byte:node.end_byte]
            tc = count_tokens(content)
            snippet = {
                "id": mk_id(path, node),
                "file": str(path.relative_to(root)),
                "content": content,
                "token_count": tc,
                "tags": tag_content(node),
                "continuation": tc > 800,
                # Callers filled in by second pass after all snippets collected
            }
            snippets.append(snippet)
    # Second pass: populate callers for each snippet
    return snippets

def mk_id(path, node):
    h = hashlib.sha256(f"{path}:{node.child_by_field_name('name').text.decode()}:{node.start_point[0]}".encode()).hexdigest()
    return f"sha256:{h[:6]}:{h[-6:]}"
```

### Function extraction via tree-sitter AST (not regex)

tree-sitter's AST natively handles multi-line declarations, type-anchored
re-exports (`int ZEXPORT inflate(...)`), and nested-scope functions —
cases that regex-based brace-depth matching silently misses:

```python
def extract_functions(path: Path) -> list[dict]:
    source = path.read_text()
    tree = parser.parse(bytes(source, "utf8"))
    snippets = []
    for node in tree.root_node.named_children:
        if node.type in ("function_definition", "declaration"):
            content = source[node.start_byte:node.end_byte]
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            func_name = name_node.text.decode()
            tc = count_tokens(content)
            snippets.append({
                "id": _make_snippet_id(str(path.relative_to(root)), func_name, node.start_point[0]),
                "file": str(path.relative_to(root)),
                "language": "c",
                "kind": "function",
                "name": func_name,
                "lines": [node.start_point[0] + 1, node.end_point[0] + 1],
                "content": content,
                "token_count": tc,
                "tags": _tag_content(content),
                "callees": _extract_callees(content, func_name),
                "continuation": tc > 800,
            })
    return snippets
```

Regex-based extraction must never be used as a fallback.

### Self-call filtering in callee extraction

When extracting function calls from a function body, the function's own name
matches in its declaration line. Skip it:

```python
def _extract_callees(body: str, func_name: str = '') -> list[str]:
    callees = []
    seen = set()
    for m in _FUNC_NAME_RE.finditer(body):
        name = m.group(1)
        if name == func_name:  # skip self-reference from signature
            continue
        if name not in _CONTROL_FLOW and name not in seen:
            seen.add(name)
            callees.append(name)
    return callees
```

### Deterministic snippet IDs

```python
def _make_snippet_id(file: str, name: str, line: int) -> str:
    h = hashlib.sha256(f"{file}:{name}:{line}".encode()).hexdigest()
    return f"sha256:{h[:6]}:{h[-6:]}"
```

Never use `hash()` or `id()` — these are non-deterministic across runs due to
PYTHONHASHSEED randomization.

**Tree-sitter 0.25+ API is required (0.22 incompatible):**

```python
from tree_sitter import Language, Parser

# 0.22.x (will crash — never use):
# parser.set_language(C_LANG)

# 0.25.x (required):
parser = Parser()
parser.language = C_LANG  # property setter, not method

# For pre-built wheels with capsule API (0.25.2+):
from tree_sitter_c import language as c_lang
C_LANG = Language(c_lang())  # capsule constructor, not path+name
```

---

## coordinator.py

Builds per-agent context packs from the snippet DB.

```python
# coordinator.py
AGENT_DOMAINS = {
    "mem-safety":       {"tags": ["memory", "integer-arith", "unsafe"], "exclusive": True},
    "auth":             {"tags": ["auth"], "exclusive": False},
    "crypto":           {"tags": ["crypto"], "exclusive": True},
    "ipc":              {"tags": ["ipc"], "exclusive": False},
    "data-flow":        {"tags": ["external-input"], "exclusive": False},
    "format-str":       {"tags": ["format-string"], "exclusive": True},
    "injection":        {"tags": ["external-input"], "exclusive": False},
    "path-traversal":   {"tags": ["memory"], "exclusive": False},
    "concurrency":      {"tags": ["memory"], "exclusive": False},
    "resource":         {"tags": ["memory", "integer-arith"], "exclusive": False},
    "secrets":          {"tags": ["crypto"], "exclusive": True},
}

DOMAIN_ORDER = [
    "mem-safety", "data-flow", "crypto", "format-str", "injection",
    "path-traversal", "concurrency", "resource", "secrets", "auth", "ipc",
]

def build_packs(db: dict, budget: int) -> list[dict]:
    # budget = int(model_context_limit * 0.85) — leaves 15% for output
    packs = []
    for domain, tags in AGENT_DOMAINS.items():
        selected = [s for s in db.values() if set(s["tags"]) & set(tags)]
        for batch in token_batch(selected, budget):
            packs.append(make_pack(domain, batch, db))
    return packs

def make_pack(domain: str, snippets: list, db: dict) -> dict:
    return {
        "agent": domain,
        "guidance": DOMAIN_GUIDANCE[domain],
        "snippets": snippets,
        "cross_refs": build_cross_refs(snippets, db),
        "security_context": load_security_context(),
        "known_entries": [],
    }
```

---

## run_agents.py

Runs hunter agents in parallel. Two patterns are available — the **sync urllib**
pattern is preferred for reliability with free-tier API providers (avoids hidden
per-connection rate limits that async triggers). The async pattern works well
with paid/private API endpoints.

### Preferred: Sync urllib + ThreadPoolExecutor

```python
# run_agents.py (sync — preferred for free-tier API reliability)
import json, os, ssl, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

MODEL = "openrouter:nvidia/nemotron-nano-12b-v2-vl:free"  # provider-prefixed
MAX_TOKENS = 8192  # reasoning models need 8K+ output budget

# Per-domain model routing: strongest for deep reasoning domains
MODEL_BY_DOMAIN = {
    "mem-safety":  "openrouter:nvidia/nemotron-nano-12b-v2-vl:free",
    "data-flow":   "openrouter:deepseek/deepseek-v4-flash:free",
    "crypto":      "openrouter:deepseek/deepseek-v4-flash:free",
    "format-str":  "openrouter:deepseek/deepseek-v4-flash:free",
    "ipc":         "openrouter:deepseek/deepseek-v4-flash:free",
    "auth":        "openrouter:deepseek/deepseek-v4-flash:free",
}

# Health check filter: remove DEAD models at startup
def health_check_filter(models, max_workers=8):
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(call_llm, m, "Reply 'ok'", max_tokens=8): m for m in models}
        for f in as_completed(futures):
            mid = futures[f]
            try:
                f.result()
                alive.append(mid)
            except Exception:
                pass
    return alive

# Multi-provider call_llm routes by model ID prefix
def call_llm(model_id: str, prompt: str, system: str = "", **kwargs):
    provider, _, model_name = model_id.partition(":")
    api_key = _get_auth_key(provider)
    if not api_key:
        raise ValueError(f"no auth key for provider: {provider}")

    base_urls = {
        "openrouter": "https://openrouter.ai/api/v1",
        "groq": "https://api.groq.com/openai/v1",
        "cerebras": "https://api.cerebras.ai/v1",
    }
    base = base_urls.get(provider)
    if not base:
        raise ValueError(f"unknown provider: {provider}")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model_name,
        "max_tokens": kwargs.get("max_tokens", MAX_TOKENS),
        "messages": messages,
    }
    req = urllib.request.Request(
        url=f"{base}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    ctx = ssl.create_default_context()
    resp = urllib.request.urlopen(req, context=ctx, timeout=kwargs.get("timeout", 60))
    result = json.loads(resp.read().decode())

    # Reasoning models put output in 'reasoning' field, not 'content'
    msg = result["choices"][0]["message"]
    content = (msg.get("content") or "")
    reasoning = (msg.get("reasoning") or "")
    if not content.strip() and reasoning:
        content = reasoning

    return {"content": content, "raw": result}

def run_pack(pack: dict) -> list[dict]:
    model = MODEL_BY_DOMAIN.get(pack["agent"], MODEL)
    for attempt in range(3):
        try:
            result = call_llm(model, json.dumps(pack),
                              system=AGENT_SYSTEM_PROMPT.format(domain=pack["agent"]))
            findings, gaps = parse_findings(result["content"])
            return findings
        except Exception as e:
            estr = str(e)
            if any(x in estr for x in ("429", "502", "503", "504", "rate", "try again")):
                time.sleep(5 * (attempt + 1))
                continue
            raise
    return []

def run_all(packs: list[dict], parallel: int = 3) -> list[dict]:
    all_findings = []
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {pool.submit(run_pack, p): p["agent"] for p in packs}
        for f in as_completed(futures):
            all_findings.extend(f.result())
    return all_findings
```

### Auth key resolution

Use deterministic fallback order: project-relative, global, env var.

```python
import os, json

AUTH_ORDER = [
    os.path.join(os.path.dirname(__file__), "../auth.json"),
    os.path.expanduser("~/.local/share/opencode/auth.json"),
]

def _get_auth_key(provider: str) -> str | None:
    env_map = {
        "openrouter": "OPENROUTER_API_KEY",
        "groq": "GROQ_API_KEY",
        "cerebras": "CEREBRAS_API_KEY",
    }
    env_key = os.environ.get(env_map.get(provider, ""))
    if env_key:
        return env_key
    for path in AUTH_ORDER:
        try:
            data = json.load(open(path))
            key = data.get(provider) or data.get(f"{provider}_api_key")
            if key:
                return key
        except (FileNotFoundError, json.JSONDecodeError):
            continue
    return None
```

File format: `{"openrouter": "sk-or-v1-...", "groq": "gsk_..."}`.
Flat, top-level keys matching provider names.

### Validate-only mode

Add a `--validate-only` flag to skip Hunt and re-run Validate + Dedupe + Report
from cached findings. Implemented at the top of `main()`:

```python
validate_only = "--validate-only" in sys.argv
if validate_only:
    findings = []
    with open("output/findings.jsonl") as f:
        for line in f:
            if line.strip():
                findings.append(json.loads(line))
    gaps = []
    if Path("output/gaps.jsonl").exists():
        with open("output/gaps.jsonl") as gf:
            for line in gf:
                if line.strip():
                    gaps.append(json.loads(line))
else:
    findings, gaps = run_hunt(packs, hunt_models)
    persist_findings_and_gaps(findings, gaps)
# Shared Validate + Dedupe + Report path...
```

### Structured bucket rationale

Every finding in the final report should include a `bucket_rationale` field:

```python
def bucket_rationale(f: dict, bucket: str) -> str:
    status = f.get("validate_status", "needs-more-info")
    severity = f.get("severity", "LOW")
    if bucket == "fix_now":
        return f"Severity {severity} + status {status}. Confirmed reachable vulnerability."
    elif bucket == "false_positive":
        return f"Rejected by Validate: {f.get('validate_reason', 'no reason given')[:200]}"
    else:
        if severity == "INFORMATIONAL":
            return f"Informational finding about {f.get('class', '')}. Design property, not exploitable."
        return f"Severity {severity}, status {status}. No confirmed external-input path."
```

Also add a `bucket_definitions` dict to the report root documenting the criteria.

### Output parser (robust to model hallucination)

Returns `(findings, gaps)` — findings are vulnerability reports, gaps
are coverage assessments from the hunter.

```python
def parse_findings(text: str, domain: str = "") -> tuple[list[dict], list[dict]]:
    findings = []
    gaps = []
    saw_done = False

    # Strategy 1: try JSON array
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                item.setdefault("status", "raw")
                item.setdefault("poc_confirmed", False)
                if "coverage_gap" in item:
                    gaps.append(item)
                elif "snippet_id" in item:
                    findings.append(item)
            if not findings and not gaps:
                gaps.append({
                    "coverage_gap": domain,
                    "reason": f"hunter returned empty JSON array for {domain}; "
                              "no findings or gaps emitted",
                })
            return findings, gaps
    except json.JSONDecodeError:
        pass

    # Strategy 2: line-by-line JSONL (handles JSON + free text on same line)
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # Try full line first
        obj = None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            pass
        # If full line fails, extract the largest balanced-brace prefix.
        # Models often emit {"done": true} followed by free-text reasoning
        # on the same line — this handles that case.
        if obj is None:
            depth = 0
            start = -1
            for i, c in enumerate(line):
                if c == "{":
                    if depth == 0:
                        start = i
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0 and start >= 0:
                        try:
                            obj = json.loads(line[start:i+1])
                            break
                        except json.JSONDecodeError:
                            pass
        if obj is None:
            continue

        obj.setdefault("status", "raw")
        obj.setdefault("poc_confirmed", False)
        if obj.get("done") is True:
            saw_done = True
        elif "coverage_gap" in obj:
            gaps.append(obj)
        elif "snippet_id" in obj:
            findings.append(obj)

    # Sentinel-only detection: model returned {"done": true} as the only JSON
    # object with no findings and no coverage gaps. Auto-generate a gap so this
    # is distinguishable from "pipeline error / model didn't analyze."
    if saw_done and not findings and not gaps:
        gaps.append({
            "coverage_gap": domain,
            "reason": f"hunter for {domain} returned sentinel-only output "
                      "(no findings, no gaps). All code paths in scope were "
                      "analyzed and no vulnerabilities found, or model skipped "
                      "structured reporting.",
        })

    return findings, gaps
```

### Truncated JSON repair

Reasoning models often exceed max_tokens limits. When validate's JSON is
cut off mid-brace, json.loads() fails silently. Repair before retrying:

```python
def _repair_truncated_json(text: str) -> str:
    text = text.strip()
    if not text.endswith("}"):
        text += "}"
    depth = 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    while depth > 0:
        text += "}"
        depth -= 1
    while depth < 0 and text.rfind("}") > text.rfind("{"):
        text = text.rstrip("}")
        depth += 1
    return text
```

This succeeds on ~70% of truncated responses. The remaining 30% need a
full retry (next model in chain).

---

## shield.py

Call-graph construction, call-path verification, hallucination detection, and
static reachability filtering. Sits between Validate/Dedupe and Chainer.

### Call-graph construction

```python
def build_call_graph(snippets: list[dict]) -> dict[str, set[str]]:
    graph = {}
    for s in snippets:
        name = str(s.get('name') or s.get('id') or '').lower()
        callees = [c.lower() for c in (s.get('callees') or [])]
        if name:
            graph.setdefault(name, set()).update(callees)
    return graph
```

### Call-path verification

```python
def verify_call_path(finding, graph) -> tuple[bool, str]:
    path = [n.lower() for n in (finding.get('call_path') or [])]
    if not path:
        return False, 'empty-call-path'
    for i in range(len(path) - 1):
        caller, callee = path[i], path[i + 1]
        if caller not in graph or callee not in graph.get(caller, set()):
            return False, f'unverified: {caller}->{callee}'
    return True, 'verified'
```

### Static reachability filter with snippet_db resolution

**Critical:** `filter_unreachable()` must accept a `snippet_db` parameter to
resolve finding snippet IDs into function names for graph lookup:

```python
def filter_unreachable(findings, graph, entry_points, max_hops=6, snippet_db=None):
    entry_set = {e.lower() for e in entry_points}
    reachable, unreachable = [], []
    for f in findings:
        targets = set()
        sid = f.get('snippet_id', '')
        if sid and snippet_db:
            sname = snippet_db.get(sid, {}).get('name', sid)
            targets.add(str(sname).lower())
        # BFS from entry_set into targets through graph...
```

Without `snippet_db`, every finding uses a `sha256:...` ID as graph key,
finds no match, and all findings are marked unreachable.

### Hallucination risk scoring

Use function-name + identifier matching, not raw token overlap:

```python
import re

def hallucination_risk(finding: dict, snippet: dict) -> str:
    desc = (finding.get("desc") or "").lower()
    content = (snippet.get("content") or "").lower()
    name = (snippet.get("name") or "").lower()

    if name and name not in desc:
        return "high"

    identifiers = set(re.findall(r'\b[a-z_][a-z_0-9]+\b', content))
    desc_ids = set(re.findall(r'\b[a-z_][a-z_0-9]+\b', desc))
    overlap = identifiers & desc_ids

    keywords = ("overflow", "underflow", "uninitialized", "wrap", "oob",
                "memcpy", "malloc", "free", "null", "bounds", "stack",
                "heap", "recursion", "injection", "truncation")
    kw_count = sum(1 for kw in keywords if kw in desc)

    if len(overlap) >= 2 or kw_count >= 1:
        return "low"
    elif len(overlap) == 1:
        return "medium"
    return "high"
```

### Alternative: Async pattern (for paid/private endpoints)

```python
# run_agents.py (async — for paid endpoints without rate-limit issues)
import asyncio, json, os
from openai import AsyncOpenAI

BASE_URLS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
    "cerebras": "https://api.cerebras.ai/v1",
}
MODEL = "openrouter:nvidia/nemotron-nano-12b-v2-vl:free"

def _async_client_for(model_id: str) -> AsyncOpenAI:
    provider, _, _ = model_id.partition(":")
    return AsyncOpenAI(
        base_url=BASE_URLS[provider],
        api_key=_get_auth_key(provider),
    )

async def run_agent(pack: dict) -> list[dict]:
    model_id = MODEL_BY_DOMAIN.get(pack["agent"], MODEL)
    provider, _, model_name = model_id.partition(":")
    client = _async_client_for(model_id)
    response = await client.chat.completions.create(
        model=model_name,
        max_tokens=8192,
        messages=[
            {"role": "system", "content": AGENT_SYSTEM_PROMPT.format(domain=pack["agent"])},
            {"role": "user",   "content": json.dumps(pack)},
        ],
    )
    msg = response.choices[0].message
    content = (msg.content or "")
    reasoning = getattr(msg, "reasoning", None) or ""
    if not content.strip() and reasoning:
        content = reasoning
    findings, gaps = parse_findings(content)
    return findings

async def run_all(packs: list[dict]) -> list[dict]:
    results = await asyncio.gather(*[run_agent(p) for p in packs])
    return [f for batch in results for f in batch]
```

---

## chainer.py

Builds a call graph from the snippet DB and identifies exploit chains.

### Critical: resolve snippet IDs to function names before BFS

The call graph is keyed on lowercase function names, but findings reference
snippet IDs (`sha256:...`). Without resolution, BFS searches for graph keys
that don't exist:

```python
def build_chains(findings, snippet_db, call_graph, max_hops=4):
    node_pairs = []
    for f in findings:
        sid = f.get('snippet_id', '')
        if not sid:
            continue
        snippet = snippet_db.get(sid, {})
        node_name = str(snippet.get('name', sid)).lower()  # ← key step
        node_pairs.append((node_name, sid, f))

    for i in range(len(node_pairs)):
        for j in range(len(node_pairs)):
            if i == j:
                continue
            a_node, a_id, _ = node_pairs[i]
            b_node, b_id, _ = node_pairs[j]
            if _reachable(a_node, b_node, call_graph, max_hops):
                # emit chain...
```

### Chain reasoning agent prompt

```
Given these findings and the code they reference, determine whether they can be
chained into a single exploit. Describe:
- The exploit primitive each step provides
- Preconditions at each step
- Overall severity
- One-paragraph PoC narrative (no working shellcode)

Output JSON (one object, no other text):
{
  "chain_id": "...",
  "feasible": true,
  "severity": "CRITICAL",
  "score": 7,
  "narrative": "...",
  "steps": [
    {"snippet_id": "...", "finding_id": "...", "primitive": "..."}
  ]
}
```

### Scoring

```python
def score_chain(chain_snippets: list[dict], findings: dict) -> int:
    score = 0
    has_external_input = any("external-input" in s["tags"] for s in chain_snippets)
    has_sink = any(s for s in chain_snippets if findings.get(s["id"]))
    if has_external_input and has_sink:
        score += 2
    for s in chain_snippets:
        f = findings.get(s["id"])
        if f:
            score += {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(f["severity"], 0)
    return score
```

---

## PoC loop

A finding with a PoC is actionable. A finding without one is speculation.

**Critical isolation requirement:** PoC runners must have no production access.
Use a sandboxed container with no network egress and scoped API keys.

```python
MAX_ITERATIONS = 5

def poc_confirmation_loop(finding: dict, scratch_env: SandboxEnv) -> str:
    hypothesis = finding["desc"]
    for _ in range(MAX_ITERATIONS):
        poc_code = write_poc_agent(finding, hypothesis)
        result = scratch_env.compile_and_run(poc_code)
        if result.matches_hypothesis:
            finding["poc_confirmed"] = True
            return "CONFIRMED"
        hypothesis = adjust_hypothesis_agent(hypothesis, result.failure_output)
    return "UNCONFIRMED"
```

**Separate agent tasks for better reasoning:**
- Agent A: "Is this code buggy / exploitable?"
- Agent B: "Is this code path reachable from an external attacker input?"

Combining these into one agent prompt degrades reasoning quality on both
dimensions.

---

## poc.py

Auto-generates C PoCs from findings, compiles them under AddressSanitizer,
runs them, and produces a verdict.

### Core flow

```python
# stages/poc.py
import json, subprocess, tempfile
from pathlib import Path

def generate(finding: dict, snippet_db: dict) -> dict:
    """Create PoC JSON + C source from a finding."""
    snippet = snippet_db.get(finding["snippet_id"])
    poc = build_poc_json(finding, snippet)
    src = _autogen_source(finding, snippet)
    _write_files(poc, src)
    return poc

def compile_and_run(poc: dict) -> dict:
    """Build and execute the PoC under ASan, update result."""
    ok, binary = _compile(poc)
    if not ok:
        poc["result"] = {"status": "build_failed", "verdict": "needs-more-info"}
        return poc
    result = _execute(binary)
    poc["result"] = result
    _update_test_cases(poc, result)
    _write_json(poc)
    return poc

def process_findings(findings: list[dict], snippet_db: dict,
                     run: bool = True) -> list[dict]:
    """Batch: generate, optionally compile+run."""
    results = []
    for f in findings:
        existing = _find_existing(f)
        if existing and run and _needs_rerun(existing):
            results.append(compile_and_run(existing))
        elif existing:
            results.append(existing)
        elif run:
            results.append(compile_and_run(generate(f, snippet_db)))
        else:
            results.append(generate(f, snippet_db))
    return results
```

### Class-targeted test generation

The generator dispatches on vulnerability class to produce specific tests:

```python
CLASS_HANDLERS = {
    "buffer-overflow": _gen_buffer_tests,
    "Buffer Overflow Write": _gen_buffer_tests,
    "format-string": _gen_format_tests,
    "CWE-165": _gen_uninit_tests,
    "CWE-369": _gen_recursion_tests,
    "integer-wrap": _gen_integer_tests,
}
```

Each handler examines the snippet content to produce context-aware code.
For example, `_gen_buffer_tests` detects `updatewindow` in zlib and
generates inflate/deflate tests for window bits 8/9/12/15:

```python
def _gen_buffer_tests(finding, snippet):
    if "updatewindow" in content:
        return _gen_updatewindow_tests()
    # Generic: allocate, memset, free — check for OOB
    return _gen_generic_buffer_test()
```

### Verdict logic

```python
def _determine_verdict(asan_errors: int, exit_code: int) -> tuple:
    if asan_errors > 0:
        return "confirmed", f"AddressSanitizer: {asan_errors} error(s)"
    if exit_code == 0:
        return "rejected", "AddressSanitizer: no errors, exit 0"
    return "needs-more-info", "non-zero exit but no ASan errors"
```

The verdict is pushed back into the finding as `poc_verdict` and
`poc_reasoning` fields, consumed by the Report stage.

### Schema validation

```python
def validate_poc(poc: dict) -> list[str]:
    errors = []
    for f in ["schema_version", "poc_id", "finding", "harness",
              "test_cases", "result"]:
        if f not in poc:
            errors.append(f"missing: {f}")
    if poc.get("result", {}).get("status") == "completed":
        v = poc["result"]["verdict"]
        if v not in ("confirmed", "rejected", "needs-more-info"):
            errors.append(f"invalid verdict: {v}")
    return errors
```

Run at every stage: after generation, after compilation, after execution.
If the JSON ever becomes invalid, the PoC stage refuses to proceed.
