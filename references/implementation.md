# Implementation Reference

Code sketches and prompt templates for each harness stage.
Load this file when writing, reviewing, or debugging harness code.

---

## ingestor.py

Converts a repo into a flat, typed snippet database.

Uses `tree-sitter` (v0.25+, not 0.22 — API is incompatible) for function
extraction. Short sha256 IDs (`sha256:{h[:6]}:{h[-6:]}`) for readability.

Any tokenizer that matches your model's encoding works for token counting —
`tiktoken` (OpenAI/Anthropic cl100k), `transformers` `AutoTokenizer`, or a
simple character-based estimate (÷4) as a fallback.

```python
# ingestor.py
from pathlib import Path
from tree_sitter import Language, Parser
import json, hashlib

# Token counting: use whichever tokenizer matches your model.
# tiktoken (cl100k) works for OpenAI + Anthropic models.
# transformers AutoTokenizer works for local/HuggingFace models.
# Fallback: len(text) // 4 (character estimate, good enough for budgeting).
try:
    import tiktoken
    _enc = tiktoken.get_encoding("cl100k_base")
    count_tokens = lambda text: len(_enc.encode(text))
except ImportError:
    count_tokens = lambda text: len(text) // 4

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
            snippet = {
                "id": mk_id(path, node),
                "file": str(path.relative_to(root)),
                "content": source[node.start_byte:node.end_byte],
                "token_count": count_tokens(...),
                "tags": tag_content(node),
                "continuation": token_count > 800,
                # Callers filled in by second pass after all snippets collected
            }
            snippets.append(snippet)
    # Second pass: populate callers for each snippet
    return snippets

def mk_id(path, node):
    h = hashlib.sha256(f"{path}:{node.child_by_field_name('name').text.decode()}:{node.start_point[0]}".encode()).hexdigest()
    return f"sha256:{h[:6]}:{h[-6:]}"
```

**Tree-sitter 0.25+ API notes (not backwards compatible):**

```python
from tree_sitter import Language, Parser

# 0.22.x (old):
# parser.set_language(C_LANG)

# 0.25.x (current):
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
    "mem-safety":  ["memory", "integer-arith", "unsafe"],
    "auth":        ["auth", "external-input"],
    "crypto":      ["crypto"],
    "ipc":         ["ipc", "external-input"],
    "data-flow":   ["external-input"],
    "format-str":  ["format-string"],
}

def build_packs(db: dict, budget: int = 180_000) -> list[dict]:
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

API_KEY = json.load(open(os.path.expanduser("~/.local/share/opencode/auth.json"))).get("openrouter", "")
MODEL = "openrouter/openrouter/free"  # routing alias, auto-selects
MAX_TOKENS = 8192  # reasoning models need 8K+ output budget

# Per-domain model routing: strongest for deep reasoning domains
MODEL_BY_DOMAIN = {
    "mem-safety":  "openrouter/openrouter/free",
    "data-flow":   "openrouter/openrouter/free",
    "crypto":      "openrouter/openrouter/free",
    "format-str":  "openrouter/openrouter/free",
    "ipc":         "openrouter/openrouter/free",
    "auth":        "openrouter/openrouter/free",
}

def run_pack(pack: dict) -> list[dict]:
    model = MODEL_BY_DOMAIN.get(pack["agent"], MODEL)
    payload = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "messages": [
            {"role": "system", "content": AGENT_SYSTEM_PROMPT.format(domain=pack["agent"])},
            {"role": "user",   "content": json.dumps(pack)},
        ],
    }
    req = urllib.request.Request(
        url="https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
    )
    ctx = ssl.create_default_context()
    resp = urllib.request.urlopen(req, context=ctx)
    result = json.loads(resp.read().decode())
    # Reasoning models put output in 'reasoning' field, not 'content'
    msg = result["choices"][0]["message"]
    content = (msg.get("content") or "") + " " + (msg.get("reasoning") or "")
    return parse_findings(content)

def run_all(packs: list[dict], parallel: int = 3) -> list[dict]:
    all_findings = []
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {pool.submit(run_pack, p): p["agent"] for p in packs}
        for f in as_completed(futures):
            all_findings.extend(f.result())
    return all_findings
```

### Output parser (robust to model hallucination)

```python
def parse_findings(text: str) -> list[dict]:
    findings = []
    # Strategy 1: try JSON array
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if "snippet_id" in item:
                    item.setdefault("status", "raw")
                    item.setdefault("poc_confirmed", False)
                    findings.append(item)
            return findings
    except json.JSONDecodeError:
        pass
    # Strategy 2: line-by-line JSONL
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "snippet_id" in obj:
            obj.setdefault("status", "raw")
            obj.setdefault("poc_confirmed", False)
            findings.append(obj)
    return findings
```

### Alternative: Async pattern (for paid/private endpoints)

```python
# run_agents.py (async — for paid endpoints without rate-limit issues)
import asyncio, json, os
from openai import AsyncOpenAI

client = AsyncOpenAI(
    base_url=os.environ.get("LLM_BASE_URL", "https://openrouter.ai/api/v1"),
    api_key=os.environ.get("LLM_API_KEY", ""),
)
MODEL = os.environ.get("LLM_MODEL", "openrouter/openrouter/free")

async def run_agent(pack: dict) -> list[dict]:
    model = MODEL_BY_DOMAIN.get(pack["agent"], MODEL)
    response = await client.chat.completions.create(
        model=model,
        max_tokens=8192,  # reasoning models need 8K, not 4K
        messages=[
            {"role": "system", "content": AGENT_SYSTEM_PROMPT.format(domain=pack["agent"])},
            {"role": "user",   "content": json.dumps(pack)},
        ],
    )
    msg = response.choices[0].message
    content = (msg.content or "") + " " + (getattr(msg, "reasoning", None) or "")
    return parse_findings(content)

async def run_all(packs: list[dict]) -> list[dict]:
    results = await asyncio.gather(*[run_agent(p) for p in packs])
    return [f for batch in results for f in batch]
```

---

## chainer.py

Builds a call graph from the snippet DB and identifies exploit chains.

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
