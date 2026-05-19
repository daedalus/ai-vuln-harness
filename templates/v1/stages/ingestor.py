from __future__ import annotations

from pathlib import PurePosixPath
import re

DEFAULT_EXCLUDE_DIRS = {'test', 'tests', 'examples', 'example', 'contrib'}
_INPUT_SYSCALLS = ('read(', 'recv(', 'recvfrom(', 'fgets(', 'fread(', 'accept(', 'getenv(', 'request.', 'http', 'socket')


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
