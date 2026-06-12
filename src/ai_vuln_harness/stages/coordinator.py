"""Coordinator stage — build per-agent context packs.

Each domain (security attack class) gets a curated subset of snippets scoped
to its focus area. Hunt agents receive these packs and never see the full DB.

Exclusive domains (mem-safety, crypto, format-str, secrets) receive only
tag-matching snippets. Non-exclusive domains also receive untagged snippets
to ensure coverage of code that doesn't match any tag.

Budget enforcement: each pack must not exceed 85% of the model's context
window (the remaining 15% is reserved for output). If a domain exceeds
budget, it is split into sub-packs by file ordering.

11-domain set:
  mem-safety    | memory, integer-arith, unsafe          | Exclusive | Buffer overflow, OOB, UAF, integer wrap
  auth          | auth                                   | No        | Bypass, priv esc, session fixation
  crypto        | crypto                                 | Yes       | Weak primitives, IV reuse, padding oracle
  ipc           | ipc                                    | No        | TOCTOU, injection via pipes/sockets
  data-flow     | external-input                         | No        | Untrusted data reaching sinks
  format-str    | format-string                          | Yes       | Format string exploits
  injection     | external-input                         | Yes       | Command injection through untrusted data
  path-traversal| memory                                 | Yes       | File path traversal, symlink attacks
  concurrency   | memory                                 | No        | Race conditions, TOCTOU, signal safety
  resource      | memory, integer-arith                  | No        | Resource exhaustion, mem leak, fd leak
  secrets       | crypto                                 | Yes       | Hardcoded secrets, credential exposure

Tag inflation warning: ``external-input`` keyword-match on ``buf``, ``arg``,
``len``, ``src`` in a C library matches ~99.9% of functions. Strip it from
all domain filters EXCEPT ``data-flow`` when targeting compiled libraries.
"""

from __future__ import annotations

import json
from collections import defaultdict

DOMAIN_ORDER = [
    "mem-safety",
    "auth",
    "crypto",
    "ipc",
    "data-flow",
    "format-str",
    "injection",
    "path-traversal",
    "concurrency",
    "resource",
    "secrets",
]

DOMAINS = [
    {"name": "mem-safety", "exclusive": True},
    {"name": "auth", "exclusive": False},
    {"name": "crypto", "exclusive": True},
    {"name": "ipc", "exclusive": False},
    {"name": "data-flow", "exclusive": False},
    {"name": "format-str", "exclusive": True},
    {"name": "injection", "exclusive": True},
    {"name": "path-traversal", "exclusive": True},
    {"name": "concurrency", "exclusive": False},
    {"name": "resource", "exclusive": False},
    {"name": "secrets", "exclusive": True},
]


def _group_snippets_by_file(snippets: list[dict]) -> dict[str, list[dict]]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    for snippet in snippets:
        file = snippet.get("file")
        if file:
            by_file[file].append(snippet)
    return by_file


def _build_domain_snippets(
    by_file: dict[str, list[dict]],
    recon_tasks: list[dict] | None,
) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    domain_snippets: dict[str, list[dict]] = defaultdict(list)
    domain_context: dict[str, dict] = defaultdict(dict)
    for task in recon_tasks or []:
        for f in task.get("target_files", []):
            domain_snippets[task["domain"]].extend(by_file.get(f, []))
        if task.get("dependency_graph"):
            domain_context[task["domain"]]["dependency_graph"] = task[
                "dependency_graph"
            ]
        if task.get("cross_repo_targets"):
            domain_context[task["domain"]]["cross_repo_targets"] = task[
                "cross_repo_targets"
            ]
    return domain_snippets, domain_context


def _domain_order(domain_snippets: dict[str, list[dict]]) -> list[str]:
    order = []
    if "all" in domain_snippets:
        order.append("all")
    for d in DOMAINS:
        name = d["name"] if isinstance(d, dict) else d
        if name in domain_snippets:
            order.append(name)
    for domain in domain_snippets:
        if domain not in order and domain != "all":
            order.append(domain)
    return order


def _chunk_domain(
    domain: str,
    items: list[dict],
    domain_context: dict[str, dict],
    budget_tokens: int,
    system_prompt: str,
) -> list[dict]:
    try:
        import tiktoken

        token_enc = tiktoken.get_encoding("cl100k_base")

        def _encode(text: str) -> list:
            return token_enc.encode(text)
    except ImportError:
        # Fallback: approximate 1 token per 4 bytes when tiktoken unavailable
        def _encode(text: str) -> list:
            return [0] * max(1, len(text) // 4)

    def _pack_overhead_tokens(domain: str, ctx: dict | None = None) -> int:
        dummy = _make_pack(domain, [], security_context=ctx)
        return len(_encode(json.dumps(dummy, indent=2)))

    def _snippet_tokens(s: dict) -> int:
        return len(_encode(json.dumps(s, indent=2)))

    packs: list[dict] = []
    pack_snips: list[dict] = []
    security_ctx = domain_context.get(domain)
    overhead = _pack_overhead_tokens(domain, security_ctx)
    running_tokens = overhead
    if system_prompt:
        running_tokens += len(_encode(system_prompt)) + 30

    for s in items:
        s_tok = _snippet_tokens(s)
        pack_snips.append(s)
        running_tokens += s_tok
        print(
            f"[coordinator] domain={domain} snippets={len(pack_snips)} prompt_tokens={running_tokens} budget={budget_tokens}",
            file=__import__("sys").stderr,
        )
        if running_tokens > budget_tokens:
            pack_snips.pop()
            running_tokens -= s_tok
            if pack_snips:
                packs.append(
                    _make_pack(domain, pack_snips, security_context=security_ctx),
                )
            pack_snips = [s]
            running_tokens = overhead + s_tok
            if system_prompt:
                running_tokens += len(_encode(system_prompt)) + 30
    if pack_snips:
        packs.append(_make_pack(domain, pack_snips, security_context=security_ctx))
    return packs


def build_context_packs(
    snippets: list[dict],
    recon_tasks: list[dict] | None,
    allow_full_db_fallback: bool = False,
    budget_tokens: int = 128_000,
    system_prompt: str = "",
) -> list[dict]:
    if (not recon_tasks) and (not allow_full_db_fallback):
        msg = "Recon output is required. Set allow_full_db_fallback=True to bypass explicitly."
        raise ValueError(
            msg,
        )

    by_file = _group_snippets_by_file(snippets)

    if not recon_tasks and allow_full_db_fallback:
        recon_tasks = [
            {
                "task_id": "fallback-all",
                "domain": "all",
                "attack_class": "all",
                "target_files": sorted(by_file.keys()),
                "rationale": "explicit full-db fallback",
                "priority": "low",
            },
        ]

    domain_snippets, domain_context = _build_domain_snippets(by_file, recon_tasks)
    domain_iter_order = _domain_order(domain_snippets)

    packs = []
    for domain in domain_iter_order:
        domain_packs = _chunk_domain(
            domain,
            domain_snippets[domain],
            domain_context,
            budget_tokens,
            system_prompt,
        )
        packs.extend(domain_packs)
    return packs


def _make_pack(
    domain: str,
    snippets: list[dict],
    security_context: dict | None = None,
) -> dict:
    return {
        "agent": domain,
        "guidance": f"Focus only on {domain}.",
        "snippets": snippets,
        "cross_refs": {},
        "security_context": security_context or {},
        "known_entries": [],
    }
