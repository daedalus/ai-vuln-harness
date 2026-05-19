# Schemas Reference

All canonical data schemas for the AI vulnerability research harness.
Load this file when specifying output formats, validating agent output,
or integrating harness stages.

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

`continuation: true` marks a snippet that is a split continuation of a
function too large to fit in one snippet. The Chainer reconstructs these
by ordering on `lines[0]` within the same `file` + `name`.

---

## Context pack schema

Emitted by the Coordinator; consumed by Hunter agents.

```json
{
  "agent": "mem-safety",
  "guidance": "Focus on buffer overflows, OOB reads/writes, integer wraps leading to allocations, and use-after-free. Report ONLY findings with a plausible call path from an external input. For each finding emit: snippet_id, severity (CRITICAL/HIGH/MEDIUM/LOW), class, description <100 words, call_path list.",
  "snippets": [],
  "cross_refs": {},
  "security_context": {},
  "known_entries": []
}
```

`known_entries` is populated in the Feedback stage (Stage 9 in the
10-stage pipeline) to pre-load the originating finding from a shared
library into the new hunt task's context pack.

---

## Finding schema (JSONL, one object per line)

Emitted by Hunter agents and confirmed/rejected by the Validate agent.

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

`status` values: `raw` (from hunter), `confirmed`, `rejected`,
`needs-more-info` (from Validate agent).

Coverage gap records (also emitted inline by hunters, not findings):

```json
{"coverage_gap": "ipc handlers under src/mq/ not covered", "reason": "no snippets tagged ipc in this pack"}
```

Sentinel emitted at end of each hunter's output:

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
  "narrative": "Attacker-controlled length from http_handler propagates through session_handshake into rsa_decrypt's memcpy, enabling heap overflow. The adjacent heap metadata allows control-flow hijack.",
  "steps": [
    {"snippet_id": "sha256:...", "finding_id": "...", "primitive": "attacker-controlled length input"},
    {"snippet_id": "sha256:...", "finding_id": "...", "primitive": "heap overflow write"},
    {"snippet_id": "sha256:...", "finding_id": null, "primitive": "heap metadata corruption → RIP control"}
  ]
}
```

---

## Report schema

Final output of Stage 10. The reporting agent validates its own output against
this schema before emitting; it must fix structural errors before returning.

```json
{
  "repo": "git@github.com:org/repo.git",
  "scan_date": "2026-05-18T00:00:00Z",
  "summary": {
    "fix_now": 3,
    "backlog": 17,
    "false_positive": 42,
    "chains_feasible": 1
  },
  "findings": [
    {
      "id": "finding-0001",
      "bucket": "fix_now",
      "severity": "CRITICAL",
      "class": "buffer-overflow",
      "file": "src/tls.c",
      "lines": [88, 102],
      "desc": "...",
      "call_path": ["http_handler", "tls_read", "unsafe_copy"],
      "poc_confirmed": true,
      "chain": "chain-0001"
    }
  ],
  "chains": [
    {
      "chain_id": "chain-0001",
      "severity": "CRITICAL",
      "feasible": true,
      "narrative": "...",
      "steps": []
    }
  ]
}
```

### Triage bucket criteria

| Bucket | Criteria |
|---|---|
| `fix_now` | CRITICAL individual finding; feasible chain score ≥ 5; HIGH + `external-input` confirmed reachable |
| `backlog` | HIGH without confirmed external-input path; MEDIUM isolated |
| `false_positive` | No plausible call path; theoretical-only; sandbox/test-only code |
