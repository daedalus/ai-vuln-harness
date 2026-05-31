# Schemas Reference

All canonical data schemas for the AI vulnerability research harness.
These are the reference specs. See `schemas/*.json` for machine-readable
versions and each stage docstring for the field-level rationale.

---

## Snippet schema

Emitted by the Ingestor; consumed by Coordinator and Chainer.

```json
{
  "id": "sha256:...",
  "file": "src/crypto/rsa.c",
  "language": "c",
  "kind": "function",
  "name": "rsa_decrypt",
  "lines": [120, 198],
  "content": "...",
  "imports": ["openssl/rsa.h"],
  "callees": ["BN_CTX_new", "RSA_private_decrypt"],
  "callers": ["session_handshake"],
  "tags": ["memory", "crypto", "external-input"],
  "token_count": 412,
  "continuation": false
}
```

`continuation: true` marks a function split across snippets.
The Chainer reconstructs by ordering on `lines[0]` within same `file` + `name`.

---

## Context pack schema

Emitted by the Coordinator; consumed by Hunter agents.

```json
{
  "agent": "mem-safety",
  "guidance": "Focus on buffer overflows...",
  "snippets": [],
  "cross_refs": {},
  "security_context": {},
  "known_entries": []
}
```

`known_entries` is populated in the Feedback stage.

---

## Finding schema (JSONL, one object per line)

Emitted by Hunter agents; confirmed/rejected by Validate.

```json
{
  "snippet_id": "sha256:...",
  "severity": "HIGH",
  "class": "buffer-overflow",
  "desc": "rsa_decrypt passes attacker-controlled length to memcpy with no bounds check.",
  "call_path": ["http_handler", "session_handshake", "rsa_decrypt"],
  "status": "confirmed",
  "poc_confirmed": false
}
```

`status` values: `raw` → `confirmed` / `rejected` / `needs-more-info`.

Coverage gap records (inline by hunters):
```json
{"coverage_gap": "ipc handlers under src/mq/ not covered", "reason": "no snippets tagged ipc"}
```

Sentinel:
```json
{"done": true}
```

---

## Chain schema

Emitted by the Chainer.

```json
{
  "chain_id": "chain-0001",
  "feasible": true,
  "severity": "CRITICAL",
  "score": 7,
  "narrative": "...",
  "steps": [
    {"snippet_id": "...", "finding_id": "...", "primitive": "attacker-controlled length input"},
    {"snippet_id": "...", "finding_id": "...", "primitive": "heap overflow write"},
    {"snippet_id": "...", "finding_id": null, "primitive": "heap metadata corruption → RIP control"}
  ]
}
```

---

## Report schema

Final output of Stage 15. Self-validating against schema before emission.

```json
{
  "repo": "git@github.com:org/repo.git",
  "scan_date": "2026-05-18T00:00:00Z",
  "bucket_definitions": {
    "fix_now": "CRITICAL/HIGH finding with confirmed validation and reachable external-input path",
    "backlog": "HIGH without confirmed external-input path; MEDIUM/LOW/INFORMATIONAL isolated finding; honest coverage analysis",
    "false_positive": "Rejected by Validate — no plausible call path, theoretical-only, API-by-design, or misread by hunter"
  },
  "summary": {"fix_now": 3, "backlog": 17, "false_positive": 42, "chains_feasible": 1},
  "findings": [],
  "chains": [],
  "gaps": []
}
```

### Triage bucket criteria

| Bucket | Criteria |
|---|---|
| `fix_now` | CRITICAL individual; feasible chain score ≥ 5; HIGH + `external-input` confirmed reachable |
| `backlog` | HIGH without confirmed external-input path; MEDIUM isolated; INFORMATIONAL design notes |
| `false_positive` | No plausible call path; theoretical-only; sandbox/test-only code |
