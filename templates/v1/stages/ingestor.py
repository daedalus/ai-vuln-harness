from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
import re

DEFAULT_EXCLUDE_DIRS = {'test', 'tests', 'examples', 'example', 'contrib'}
_INPUT_SYSCALLS = ('read(', 'recv(', 'recvfrom(', 'fgets(', 'fread(', 'accept(', 'getenv(', 'request.', 'http', 'socket')
_SUPPORTED_EXTENSIONS = {'.c', '.cc', '.cpp', '.go', '.h', '.js', '.py', '.rs', '.ts'}
_CST_EXTENSIONS = {'.c', '.h'}
_IMPORT_RE = re.compile(r'^\s*#\s*include\s*[<"]([^">]+)[">]', re.MULTILINE)
_FUNC_NAME_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
_CONTROL_FLOW = {'if', 'for', 'while', 'switch', 'return', 'sizeof'}


def should_exclude_path(path: str, is_library_target: bool = True) -> bool:
    if not is_library_target:
        return False
    parts = [p.lower() for p in PurePosixPath(path).parts]
    return any(p in DEFAULT_EXCLUDE_DIRS or p.startswith('.') for p in parts)


def detect_external_input(content: str, is_library_target: bool = True) -> bool:
    s = content.lower()
    if not is_library_target:
        return any(k in s for k in ('request', 'params', 'headers', 'argv', 'stdin', 'socket', 'http'))
    return any(k in s for k in _INPUT_SYSCALLS)


def detect_integer_arith_untrusted(content: str) -> bool:
    s = content.lower()
    has_len_math = bool(re.search(r'(len|size|count|index)\s*[+\-*/%]|[+\-*/%]\s*(len|size|count|index)', s))
    has_untrusted_marker = any(k in s for k in _INPUT_SYSCALLS) or 'taint' in s or 'untrusted' in s
    return has_len_math and has_untrusted_marker


def tag_snippet(snippet: dict, is_library_target: bool = True) -> list[str]:
    text = (snippet.get('content') or '').lower()
    tags = set()

    if any(k in text for k in ('malloc', 'free', 'memcpy', 'memmove', 'buffer', 'pointer')):
        tags.add('memory')
    if detect_external_input(text, is_library_target=is_library_target):
        tags.add('external-input')
    if any(k in text for k in ('auth', 'token', 'session', 'credential', 'permission')):
        tags.add('auth')
    if any(k in text for k in ('crypto', 'cipher', 'hash', 'nonce', 'iv', 'tls')):
        tags.add('crypto')
    if any(k in text for k in ('socket', 'pipe', 'mmap', 'shared memory', 'shm', 'dbus')):
        tags.add('ipc')
    if any(k in text for k in ('unsafe', 'reinterpret_cast', 'raw pointer')):
        tags.add('unsafe')
    if re.search(r'\b(printf|sprintf|snprintf|gzprintf)\s*\(', text):
        tags.add('format-string')
    if detect_integer_arith_untrusted(text):
        tags.add('integer-arith')

    return sorted(tags)


def filter_snippets(snippets: list[dict], is_library_target: bool = True) -> list[dict]:
    return [s for s in snippets if not should_exclude_path(s.get('file', ''), is_library_target=is_library_target)]


def load_repo_snippets(repo: Path, is_library_target: bool = True) -> list[dict]:
    snippets: list[dict] = []
    for path in sorted(repo.rglob('*')):
        if path.suffix.lower() not in _SUPPORTED_EXTENSIONS or not path.is_file():
            continue
        snippets.extend(_extract_path_snippets(path, repo, is_library_target=is_library_target))
    _populate_callers(snippets)
    return snippets


def _extract_path_snippets(path: Path, repo: Path, is_library_target: bool = True) -> list[dict]:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []

    relative = str(path.relative_to(repo))
    if path.suffix.lower() in _CST_EXTENSIONS:
        snippets = _extract_cst_snippets(path, repo, text, is_library_target=is_library_target)
        if snippets:
            return snippets
    return [_build_file_snippet(relative, path.stem, text, is_library_target=is_library_target)]


def _extract_cst_snippets(path: Path, repo: Path, text: str, is_library_target: bool = True) -> list[dict]:
    parser = _make_c_parser()
    if parser is None:
        return []

    tree = parser.parse(text.encode('utf-8'))
    relative = str(path.relative_to(repo))
    imports = _extract_imports(text)
    snippets: list[dict] = []
    for node in _iter_nodes(tree.root_node):
        if getattr(node, 'type', None) != 'function_definition':
            continue
        name = _get_function_name(node)
        if not name:
            continue
        content = text[node.start_byte:node.end_byte]
        snippet = {
            'id': _make_snippet_id(relative, name, node.start_point[0] + 1),
            'file': relative,
            'language': _detect_language(path),
            'kind': 'function',
            'name': name,
            'lines': [node.start_point[0] + 1, node.end_point[0] + 1],
            'content': content,
            'imports': imports,
            'callees': _extract_callees(content, func_name=name),
            'callers': [],
            'token_count': _count_tokens(content),
            'continuation': False,
        }
        snippet['tags'] = tag_snippet(snippet, is_library_target=is_library_target)
        snippets.append(snippet)
    return snippets


def _build_file_snippet(relative: str, name: str, text: str, is_library_target: bool = True) -> dict:
    content = text[:6000]
    snippet = {
        'id': _make_snippet_id(relative, name, 1),
        'file': relative,
        'language': _detect_language(Path(relative)),
        'kind': 'file',
        'name': name,
        'lines': [1, max(1, text.count('\n') + 1)],
        'content': content,
        'imports': _extract_imports(text),
        'callees': _extract_callees(content, func_name=name),
        'callers': [],
        'token_count': _count_tokens(content),
        'continuation': False,
    }
    snippet['tags'] = tag_snippet(snippet, is_library_target=is_library_target)
    return snippet


def _count_tokens(text: str) -> int:
    if not text:
        return 1
    try:
        import tiktoken  # type: ignore
    except ImportError:
        return max(1, len(text) // 4)
    return max(1, len(tiktoken.get_encoding('cl100k_base').encode(text)))


def _detect_language(path: Path) -> str:
    return {
        '.c': 'c',
        '.cc': 'cpp',
        '.cpp': 'cpp',
        '.go': 'go',
        '.h': 'c',
        '.js': 'javascript',
        '.py': 'python',
        '.rs': 'rust',
        '.ts': 'typescript',
    }.get(path.suffix.lower(), 'text')


def _extract_imports(text: str) -> list[str]:
    return sorted(dict.fromkeys(_IMPORT_RE.findall(text)))


def _extract_callees(body: str, func_name: str = '') -> list[str]:
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
        caller = str(snippet.get('name') or '')
        if not caller:
            continue
        for callee in snippet.get('callees') or []:
            callers_by_callee[str(callee)].add(caller)
    for snippet in snippets:
        snippet['callers'] = sorted(callers_by_callee.get(str(snippet.get('name') or ''), set()))


def _make_snippet_id(file: str, name: str, line: int) -> str:
    digest = hashlib.sha256(f'{file}:{name}:{line}'.encode()).hexdigest()
    return f'sha256:{digest[:6]}:{digest[-6:]}'


def _make_c_parser():
    try:
        from tree_sitter import Language, Parser  # type: ignore
        from tree_sitter_c import language as c_language  # type: ignore
    except ImportError:
        return None
    parser = Parser()
    parser.language = Language(c_language())
    return parser


def _iter_nodes(node):
    yield node
    for child in getattr(node, 'children', []) or []:
        yield from _iter_nodes(child)


def _get_function_name(node) -> str | None:
    name_node = getattr(node, 'child_by_field_name', lambda _name: None)('name')
    if name_node is not None:
        return _node_text(name_node)

    decl = getattr(node, 'child_by_field_name', lambda _name: None)('declarator')
    if decl is None:
        return None

    for child in _iter_nodes(decl):
        if getattr(child, 'type', None) == 'identifier':
            return _node_text(child)
    return None


def _node_text(node) -> str | None:
    text = getattr(node, 'text', None)
    if isinstance(text, bytes):
        return text.decode('utf-8', errors='ignore')
    if isinstance(text, str):
        return text
    return None
