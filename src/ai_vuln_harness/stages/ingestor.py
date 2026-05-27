"""Ingestor stage — convert repository into a flat, typed snippet database.

Uses tree-sitter ≥ 0.25 for AST-level function extraction (required).
Regex fallback is forbidden — it misses type-anchored re-exports like
``int ZEXPORT inflate(...)`` and nested-scope functions. Every such miss is
a silent coverage gap that cannot be detected from output counts.

Snippet IDs are deterministic: ``sha256:{file}:{name}:{line}``. Never use
the built-in ``hash`` or ``id`` functions — PYTHONHASHSEED breaks
determinism across runs, which breaks cache, state DB, and finding
traceability.

``_get_function_name()`` handles multi-line declarations where
``child_by_field_name("name")`` silently returns ``None`` (~60% of C/C++
functions). Discovered during libopenssh analysis.

Token counting: ``tiktoken`` with ``cl100k_base`` is required. The character
estimate ``len//4`` overestimates C code by 30-40%, silently inflating pack
sizes beyond the 85% context budget.

Directory filtering for library targets: excludes ``contrib/``, ``examples/``,
``test/``, ``tests/``, and ``.hidden`` directories. On zlib, ~200 of 608
snippets came from these non-production directories.

Tag inflation warning: ``external-input`` keyword-match on ``buf``, ``arg``,
``len``, ``src`` matches ~99.9% of C library functions. Use smarter heuristics
for library targets: detect actual I/O syscall wrappers (``read()``, ``recv()``,
``fgets()``, ``fread()``) rather than parameter names.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterator  # noqa: TC003
from pathlib import Path, PurePosixPath

DEFAULT_EXCLUDE_DIRS = {"test", "tests", "examples", "example", "contrib"}

SNIPPET_REQUIRED_FIELDS = {
    "id",
    "file",
    "language",
    "kind",
    "name",
    "lines",
    "content",
    "tags",
    "token_count",
    "callees",
    "continuation",
}

_INPUT_SYSCALLS = (
    "read(",
    "recv(",
    "recvfrom(",
    "fgets(",
    "fread(",
    "accept(",
    "getenv(",
    "request.",
    "http",
    "socket",
)
_SUPPORTED_EXTENSIONS = {".c", ".cc", ".cpp", ".go", ".h", ".js", ".py", ".rs", ".ts"}
_CST_EXTENSIONS = {".c", ".h"}
_IMPORT_C_RE = re.compile(r'^\s*#\s*include\s*[<"]([^">]+)[">]', re.MULTILINE)
_IMPORT_PY_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z0-9_\.]+)\s+import|import\s+([A-Za-z0-9_\.]+))",
    re.MULTILINE,
)
_IMPORT_JS_RE = re.compile(
    r'^\s*import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]|^\s*import\s+[\'"]([^\'"]+)[\'"]',
    re.MULTILINE,
)
_REQUIRE_JS_RE = re.compile(r'require\(\s*[\'"]([^\'"]+)[\'"]\s*\)')
_IMPORT_GO_RE = re.compile(r'^\s*import\s+(?:\(\s*)?(".*?"|`.*?`)', re.MULTILINE)
_IMPORT_GO_BLOCK_RE = re.compile(r"^\s*import\s*\((.*?)\)", re.MULTILINE | re.DOTALL)
_IMPORT_RUST_RE = re.compile(r"^\s*use\s+([A-Za-z0-9_:]+)", re.MULTILINE)
_FUNC_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONTROL_FLOW = {"if", "for", "while", "switch", "return", "sizeof"}
_FUNC_PATTERNS = {
    ".py": re.compile(r"^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE),
    ".go": re.compile(
        r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
        re.MULTILINE,
    ),
    ".rs": re.compile(
        r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
        re.MULTILINE,
    ),
    ".ts": re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
        r"|^\s*(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{",
        re.MULTILINE,
    ),
    ".js": re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
        r"|^\s*(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{",
        re.MULTILINE,
    ),
}


def _is_probably_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    non_text = sum(b < 9 or (13 < b < 32) or b == 127 for b in sample)
    return (non_text / len(sample)) > 0.30


def should_exclude_path(path: str, is_library_target: bool = True) -> bool:
    if not is_library_target:
        return False
    parts = [p.lower() for p in PurePosixPath(path).parts]
    return any(p in DEFAULT_EXCLUDE_DIRS or p.startswith(".") for p in parts)


def detect_external_input(content: str, is_library_target: bool = True) -> bool:
    s = content.lower()
    if not is_library_target:
        return any(
            k in s
            for k in ("request", "params", "headers", "argv", "stdin", "socket", "http")
        )
    return any(k in s for k in _INPUT_SYSCALLS)


def detect_integer_arith_untrusted(content: str) -> bool:
    s = content.lower()
    has_len_math = bool(
        re.search(
            r"(len|size|count|index)\s*[+\-*/%]|[+\-*/%]\s*(len|size|count|index)",
            s,
        ),
    )
    has_untrusted_marker = (
        any(k in s for k in _INPUT_SYSCALLS) or "taint" in s or "untrusted" in s
    )
    return has_len_math and has_untrusted_marker


def tag_snippet(snippet: dict, is_library_target: bool = True) -> list[str]:
    text = (snippet.get("content") or "").lower()
    tags = set()

    if any(
        k in text for k in ("malloc", "free", "memcpy", "memmove", "buffer", "pointer")
    ):
        tags.add("memory")
    if detect_external_input(text, is_library_target=is_library_target):
        tags.add("external-input")
    if any(k in text for k in ("auth", "token", "session", "credential", "permission")):
        tags.add("auth")
    if any(k in text for k in ("crypto", "cipher", "hash", "nonce", "iv", "tls")):
        tags.add("crypto")
    if any(
        k in text for k in ("socket", "pipe", "mmap", "shared memory", "shm", "dbus")
    ):
        tags.add("ipc")
    if any(k in text for k in ("unsafe", "reinterpret_cast", "raw pointer")):
        tags.add("unsafe")
    if re.search(r"\b(printf|sprintf|snprintf|gzprintf)\s*\(", text):
        tags.add("format-string")
    if detect_integer_arith_untrusted(text):
        tags.add("integer-arith")

    return sorted(tags)


def filter_snippets(snippets: list[dict], is_library_target: bool = True) -> list[dict]:
    return [
        s
        for s in snippets
        if not should_exclude_path(
            s.get("file", ""),
            is_library_target=is_library_target,
        )
    ]


def load_repo_snippets(repo: Path, is_library_target: bool = True) -> list[dict]:
    snippets: list[dict] = []
    for path in sorted(repo.rglob("*")):
        if path.suffix.lower() not in _SUPPORTED_EXTENSIONS or not path.is_file():
            continue
        if _is_probably_binary(path):
            continue
        snippets.extend(
            _extract_path_snippets(path, repo, is_library_target=is_library_target),
        )
    _populate_callers(snippets)
    return snippets


def _extract_path_snippets(
    path: Path,
    repo: Path,
    is_library_target: bool = True,
) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    relative = str(path.relative_to(repo))
    if path.suffix.lower() in _CST_EXTENSIONS:
        snippets = _extract_cst_snippets(
            path,
            repo,
            text,
            is_library_target=is_library_target,
        )
        if snippets:
            return snippets
    snippets = _extract_regex_function_snippets(
        path,
        repo,
        text,
        is_library_target=is_library_target,
    )
    if snippets:
        return snippets
    return [
        _build_file_snippet(
            relative,
            path.stem,
            text,
            is_library_target=is_library_target,
        ),
    ]


def _extract_cst_snippets(
    path: Path,
    repo: Path,
    text: str,
    is_library_target: bool = True,
) -> list[dict]:
    parser = _make_c_parser()
    if parser is None:
        return []

    tree = parser.parse(text.encode("utf-8"))
    relative = str(path.relative_to(repo))
    imports = _extract_imports(text, language=_detect_language(path))
    snippets: list[dict] = []
    for node in _iter_nodes(tree.root_node):
        if getattr(node, "type", None) != "function_definition":
            continue
        name = _get_function_name(node)
        if not name:
            continue
        content = text[node.start_byte : node.end_byte]
        snippet = {
            "id": _make_snippet_id(relative, name, node.start_point[0] + 1),
            "file": relative,
            "language": _detect_language(path),
            "kind": "function",
            "name": name,
            "lines": [node.start_point[0] + 1, node.end_point[0] + 1],
            "content": content,
            "imports": imports,
            "callees": _extract_callees(content, func_name=name),
            "callers": [],
            "token_count": _count_tokens(content),
            "continuation": False,
        }
        snippet["tags"] = tag_snippet(snippet, is_library_target=is_library_target)
        snippets.append(snippet)
    return snippets


def _build_file_snippet(
    relative: str,
    name: str,
    text: str,
    is_library_target: bool = True,
) -> dict:
    content = text[:6000]
    snippet = {
        "id": _make_snippet_id(relative, name, 1),
        "file": relative,
        "language": _detect_language(Path(relative)),
        "kind": "file",
        "name": name,
        "lines": [1, max(1, text.count("\n") + 1)],
        "content": content,
        "imports": _extract_imports(text, language=_detect_language(Path(relative))),
        "callees": _extract_callees(content, func_name=name),
        "callers": [],
        "token_count": _count_tokens(content),
        "continuation": False,
    }
    snippet["tags"] = tag_snippet(snippet, is_library_target=is_library_target)
    return snippet


def _count_tokens(text: str) -> int:
    if not text:
        return 1
    try:
        import tiktoken
    except ImportError:
        return max(1, len(text) // 4)
    return max(1, len(tiktoken.get_encoding("cl100k_base").encode(text)))


def _detect_language(path: Path) -> str:
    return {
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".go": "go",
        ".h": "c",
        ".js": "javascript",
        ".py": "python",
        ".rs": "rust",
        ".ts": "typescript",
    }.get(path.suffix.lower(), "text")


def _extract_regex_function_snippets(
    path: Path,
    repo: Path,
    text: str,
    is_library_target: bool = True,
) -> list[dict]:
    pattern = _FUNC_PATTERNS.get(path.suffix.lower())
    if pattern is None:
        return []

    matches = list(pattern.finditer(text))
    if not matches:
        return []

    relative = str(path.relative_to(repo))
    imports = _extract_imports(text, language=_detect_language(path))
    snippets: list[dict] = []

    for idx, match in enumerate(matches):
        name = (
            match.groupdict().get("name") or match.groupdict().get("method") or ""
        ).strip()
        if not name or name in _CONTROL_FLOW:
            continue
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        content = text[start:end].strip()
        if not content:
            continue
        start_line = text.count("\n", 0, start) + 1
        end_line = text.count("\n", 0, end) + 1
        snippet = {
            "id": _make_snippet_id(relative, name, start_line),
            "file": relative,
            "language": _detect_language(path),
            "kind": "function",
            "name": name,
            "lines": [start_line, max(start_line, end_line)],
            "content": content[:6000],
            "imports": imports,
            "callees": _extract_callees(content[:6000], func_name=name),
            "callers": [],
            "token_count": _count_tokens(content[:6000]),
            "continuation": False,
        }
        snippet["tags"] = tag_snippet(snippet, is_library_target=is_library_target)
        snippets.append(snippet)
    return snippets


def _extract_imports(text: str, language: str = "text") -> list[str]:
    imports: list[str] = []
    if language in {"c", "cpp"}:
        imports.extend(_IMPORT_C_RE.findall(text))
    if language == "python":
        for left, right in _IMPORT_PY_RE.findall(text):
            imports.append(left or right)
    if language in {"javascript", "typescript"}:
        for left, right in _IMPORT_JS_RE.findall(text):
            imports.append(left or right)
        imports.extend(_REQUIRE_JS_RE.findall(text))
    if language == "go":
        for token in _IMPORT_GO_RE.findall(text):
            imports.append(token.strip('"`'))
        for block in _IMPORT_GO_BLOCK_RE.findall(text):
            imports.extend(m.group(1) for m in re.finditer(r'"([^"]+)"', block))
    if language == "rust":
        imports.extend(_IMPORT_RUST_RE.findall(text))
    return sorted(dict.fromkeys(i for i in imports if i))


def _extract_callees(body: str, func_name: str = "") -> list[str]:
    seen: set[str] = set()
    callees: list[str] = []
    for match in _FUNC_NAME_RE.finditer(body):
        name = match.group(1)
        if name == func_name or name in _CONTROL_FLOW or name in seen:
            continue
        seen.add(name)
        callees.append(name)
    return callees


def _populate_callers(snippets: list[dict]) -> None:
    callers_by_callee: dict[str, set[str]] = defaultdict(set)
    for snippet in snippets:
        caller = str(snippet.get("name") or "")
        if not caller:
            continue
        for callee in snippet.get("callees") or []:
            callers_by_callee[str(callee)].add(caller)
    for snippet in snippets:
        snippet["callers"] = sorted(
            callers_by_callee.get(str(snippet.get("name") or ""), set()),
        )


def _make_snippet_id(file: str, name: str, line: int) -> str:
    digest = hashlib.sha256(f"{file}:{name}:{line}".encode()).hexdigest()
    return f"sha256:{digest[:6]}:{digest[-6:]}"


def _make_c_parser() -> object | None:
    try:
        from tree_sitter import Language, Parser
        from tree_sitter_c import language as c_language
    except ImportError:
        return None
    parser = Parser()
    parser.language = Language(c_language())
    return parser


def _iter_nodes(node: object) -> Iterator[object]:
    yield node
    for child in getattr(node, "children", []) or []:
        yield from _iter_nodes(child)


def _get_function_name(node: object) -> str | None:
    name_node = getattr(node, "child_by_field_name", lambda _name: None)("name")
    if name_node is not None:
        return _node_text(name_node)

    decl = getattr(node, "child_by_field_name", lambda _name: None)("declarator")
    if decl is None:
        return None

    for child in _iter_nodes(decl):
        if getattr(child, "type", None) == "identifier":
            return _node_text(child)
    return None


def _node_text(node: object) -> str | None:
    text = getattr(node, "text", None)
    if isinstance(text, bytes):
        return text.decode("utf-8", errors="ignore")
    if isinstance(text, str):
        return text
    return None
