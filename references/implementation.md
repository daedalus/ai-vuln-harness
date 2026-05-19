# Implementation Reference

Code sketches and prompt templates for each harness stage.
Load this file when writing, reviewing, or debugging harness code.

---

## ingestor.py

Converts a repo into a flat, typed snippet database.

Uses `tree-sitter` for function extraction. For Rust use `cargo-ast`; for C use
`libclang` bindings. Any tokenizer that matches your model's encoding works for
token counting — `tiktoken` (OpenAI/Anthropic cl100k), `transformers`
`AutoTokenizer`, or a simple character-based estimate (÷4) as a fallback.

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
    # tree-sitter parse → walk function_definition nodes
    # compute sha256 of (file, name, lines) for stable IDs
    # tag based on content regexes (see security tag table in SKILL.md)
    # embed 3-line caller/callee stubs inline
    # split functions > 800 tokens with continuation: true
    ...
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

Runs hunter agents in parallel using asyncio. The example uses the OpenAI-compatible
`/v1/chat/completions` interface, which is supported by Anthropic, OpenAI, Mistral,
Together, vLLM, LiteLLM, and most hosted or self-hosted providers. Swap
`base_url` and `api_key` for your provider; adjust `model` to match.

```python
# run_agents.py
import asyncio, json, os
from openai import AsyncOpenAI

# Works with any OpenAI-compatible endpoint:
#   Anthropic:  base_url="https://api.anthropic.com/v1", model="claude-sonnet-4-6"
#   OpenAI:     base_url="https://api.openai.com/v1",   model="gpt-4o"
#   Together:   base_url="https://api.together.xyz/v1", model="meta-llama/..."
#   Local vLLM: base_url="http://localhost:8000/v1",    model="..."
client = AsyncOpenAI(
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
)
MODEL = os.environ["LLM_MODEL"]  # set externally; no defaults baked in

# Override per domain if you want cheap/fast models on simpler domains:
MODEL_BY_DOMAIN = {}  # e.g. {"format-str": "mistral-7b", "ipc": "mistral-7b"}

AGENT_SYSTEM_PROMPT = """
You are a security auditor specialized in {domain}.
Rules:
1. Report only real vulnerabilities with a plausible trigger path.
2. Each finding: one JSON line:
   {{"snippet_id":"...","severity":"HIGH","class":"buffer-overflow","desc":"...","call_path":[...],"status":"raw","poc_confirmed":false}}
3. Coverage gaps: {{"coverage_gap":"...","reason":"..."}}
4. No other output. End with {{"done":true}}.
"""

async def run_agent(pack: dict) -> list[dict]:
    model = MODEL_BY_DOMAIN.get(pack["agent"], MODEL)
    response = await client.chat.completions.create(
        model=model,
        max_tokens=4096,
        messages=[
            {"role": "system", "content": AGENT_SYSTEM_PROMPT.format(domain=pack["agent"])},
            {"role": "user",   "content": json.dumps(pack)},
        ],
    )
    return parse_jsonl_findings(response.choices[0].message.content)

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
