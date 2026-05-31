from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime import JsonCache

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

_MANIFEST_PARSERS: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    "go.mod": "Go",
    "go.sum": "Go",
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "Pipfile": "PyPI",
    "Pipfile.lock": "PyPI",
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
}

_ECOSYSTEM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^github\.com/", re.I), "Go"),
    (re.compile(r"^golang\.org/", re.I), "Go"),
    (re.compile(r"^google\.golang\.org/", re.I), "Go"),
    (re.compile(r"^cloud\.google\.com/", re.I), "Go"),
    (re.compile(r"^\w+\.\w+/"), "Go"),
    (re.compile(r"^@"), "npm"),
    (re.compile(r"^node/"), "npm"),
    (re.compile(r"^::"), "crates.io"),
]


def scan_manifests(repo_path: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for filename, ecosystem in _MANIFEST_PARSERS.items():
        path = repo_path / filename
        if not path.exists():
            path = repo_path / ".." / filename
            if not path.exists():
                continue
        try:
            deps = _parse_manifest(path, ecosystem)
            if deps:
                result.setdefault(ecosystem, set()).update(deps)
        except Exception:
            pass
    return result


def _parse_manifest(path: Path, ecosystem: str) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")

    if path.name == "requirements.txt":
        names = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            name = re.split(r"[=<>!~]", line, 1)[0].strip()
            extras = re.search(r"\[.*?\]", name)
            if extras:
                name = name[: extras.start()]
            if name:
                names.append(name)
        return names

    if path.name in ("Cargo.toml", "pyproject.toml"):
        return _parse_toml_deps(text, ecosystem)

    if path.name in ("package.json",):
        return _parse_json_deps(text, "dependencies")

    if path.name == "Pipfile":
        return _parse_json_deps(text, "packages")

    if path.name == "package-lock.json":
        return _parse_npm_lock(text)

    if path.name == "Cargo.lock":
        return _parse_cargo_lock(text)

    if path.name in ("go.mod",):
        return _parse_go_mod(text)

    if path.name in ("Gemfile",):
        return _parse_gemfile(text)

    if path.name == "Gemfile.lock":
        return _parse_gemfile_lock(text)

    return []


def _parse_toml_deps(text: str, ecosystem: str) -> list[str]:
    try:
        import tomllib
    except ImportError:
        return []
    try:
        data = tomllib.loads(text)
    except Exception:
        return []
    names: list[str] = []
    if ecosystem == "crates.io":
        deps = data.get("dependencies") or {}
        for key in deps:
            names.append(key)
    elif ecosystem == "PyPI":
        proj = data.get("project") or {}
        for dep in proj.get("dependencies") or []:
            name = re.split(r"[=<>!~\[ ]", dep, 1)[0].strip()
            if name:
                names.append(name)
    return names


def _parse_json_deps(text: str, field: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps = data.get(field) or {}
    return list(deps.keys()) if isinstance(deps, dict) else []


def _parse_npm_lock(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    names: list[str] = []
    packages = data.get("packages") or {}
    for key in packages:
        if key == "":
            continue
        if key.startswith("node_modules/"):
            name = key.split("node_modules/", 1)[1].split("/")[0]
            if name:
                names.append(name)
        else:
            names.append(key)
    return names


def _parse_cargo_lock(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if m:
            names.append(m.group(1))
    return names


_GO_MOD_REQUIRE_RE = re.compile(r"^\s*require\s+(.+?)(?:\s+//.+)?$", re.MULTILINE)
_GO_MOD_BLOCK_RE = re.compile(r"require\s*\(\s*(.*?)\s*\)", re.MULTILINE | re.DOTALL)
_GO_MOD_SINGLE_RE = re.compile(r"^\s*([^\s]+)\s+v?\S+", re.MULTILINE)


def _parse_go_mod(text: str) -> list[str]:
    names: list[str] = []
    block_m = _GO_MOD_BLOCK_RE.search(text)
    if block_m:
        for line in block_m.group(1).splitlines():
            m = _GO_MOD_SINGLE_RE.match(line)
            if m:
                names.append(m.group(1))
    for m in _GO_MOD_REQUIRE_RE.finditer(text):
        parts = m.group(1).split()
        if parts:
            names.append(parts[0])
    return names


def _parse_gemfile(text: str) -> list[str]:
    names: list[str] = []
    for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"]", text):
        names.append(m.group(1))
    return names


def _parse_gemfile_lock(text: str) -> list[str]:
    names: list[str] = []
    in_gem = False
    for line in text.splitlines():
        if line.startswith("GEM"):
            in_gem = True
            continue
        if in_gem:
            m = re.match(r"^\s+remote:|^\s+sources:", line)
            if m:
                continue
            m = re.match(r"^\s+([a-zA-Z0-9_-]+)\s", line)
            if m:
                names.append(m.group(1))
    return names


def infer_ecosystem(
    dep_name: str, known_ecosystems: set[str] | None = None
) -> str | None:
    if known_ecosystems:
        return next(iter(known_ecosystems))
    for pattern, ecosys in _ECOSYSTEM_PATTERNS:
        if pattern.search(dep_name):
            return ecosys
    return None


def _osv_query(pkg_name: str, ecosystem: str) -> list[dict]:
    req = urllib.request.Request(
        _OSV_BATCH_URL,
        data=json.dumps(
            {"queries": [{"package": {"name": pkg_name, "ecosystem": ecosystem}}]}
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []
    results = data.get("results") or []
    vulns: list[dict] = []
    for entry in results:
        for v in (
            entry.get("vulns")
            if isinstance(entry, dict)
            else entry
            if isinstance(entry, list)
            else []
        ):
            vulns.append(v)
    return vulns


def _osv_batch_query(
    queries: list[tuple[str, str]],
) -> dict[tuple[str, str], list[dict]]:
    payload = {
        "queries": [
            {"package": {"name": name, "ecosystem": eco}} for name, eco in queries
        ]
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        _OSV_BATCH_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return {}
    results = data.get("results") or []
    result_map: dict[tuple[str, str], list[dict]] = {}
    for i, entry in enumerate(results):
        if i >= len(queries):
            break
        name, eco = queries[i]
        vulns = []
        for v in (
            entry.get("vulns")
            if isinstance(entry, dict)
            else entry
            if isinstance(entry, list)
            else []
        ):
            vulns.append(v)
        if vulns:
            result_map[(name, eco)] = vulns
    return result_map


def _extract_cve_entries(
    osv_results: dict[tuple[str, str], list[dict]],
) -> list[dict]:
    entries: list[dict] = []
    seen: set[str] = set()
    for (pkg_name, ecosystem), vulns in osv_results.items():
        for v in vulns:
            cve_id = v.get("id", "")
            aliases = v.get("aliases") or []
            cve_alias = next((a for a in aliases if a.startswith("CVE-")), cve_id)
            if cve_alias in seen:
                continue
            seen.add(cve_alias)
            severity_str = _extract_severity(v)
            entries.append(
                {
                    "cve_id": cve_alias,
                    "description": v.get("summary") or v.get("details", "")[:200],
                    "class": _cve_class_from_description(
                        v.get("summary", "") + " " + (v.get("details") or "")
                    ),
                    "file": "",
                    "function": "",
                    "severity": severity_str,
                    "ecosystem": ecosystem,
                    "package": pkg_name,
                }
            )
    return entries


_CVE_SEVERITY_KEYWORDS: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def _cvss_severity(vector: str) -> str | None:
    parts = vector.upper().split("/")
    impact_map = {}
    for p in parts:
        if ":" in p:
            k, _, v = p.partition(":")
            impact_map[k] = v
    c = impact_map.get("C", "N")
    i = impact_map.get("I", "N")
    a = impact_map.get("A", "N")
    has_high = c == "H" or i == "H" or a == "H"
    has_low = c == "L" or i == "L" or a == "L"
    if has_high:
        return "HIGH"
    if has_low:
        return "MEDIUM"
    return "LOW"


def _extract_severity(vuln: dict) -> str:
    for s in vuln.get("severity") or []:
        raw = s.get("score", "") if isinstance(s, dict) else str(s)
        result = _cvss_severity(raw)
        if result:
            return result
    db_specific = vuln.get("database_specific") or {}
    severity = db_specific.get("severity", "")
    if severity:
        upper = severity.upper()
        if upper in _CVE_SEVERITY_KEYWORDS:
            return upper
    return "UNKNOWN"


def _cve_class_from_description(text: str) -> str:
    lower = text.lower()
    patterns: list[tuple[re.Pattern, str]] = [
        (
            re.compile(r"\bbuffer\s*overflow\b|\bout.of.bounds\b|\boob\b"),
            "buffer-overflow",
        ),
        (re.compile(r"\buse.after.free\b|\buaf\b|\bdangling\b"), "use-after-free"),
        (re.compile(r"\bdouble.free\b"), "double-free"),
        (
            re.compile(r"\binteger\s*overflow\b|\bwrap\b|\boverflow.*int\b"),
            "integer-overflow",
        ),
        (
            re.compile(r"\bnull[ .]pointer\b|\bnull.ptr\b|\bnull.pointer.deref\b"),
            "null-pointer",
        ),
        (re.compile(r"\bformat.string\b|\bformat.str\b"), "format-string"),
        (re.compile(r"\bmemory.leak\b"), "memory-leak"),
        (
            re.compile(r"\bpath.traversal\b|\bdirectory.traversal\b|\b\.\./\b"),
            "path-traversal",
        ),
        (
            re.compile(r"\bcommand.injection\b|\bcode.exec\b|\bremote.code\b|\brce\b"),
            "command-injection",
        ),
        (re.compile(r"\bsql.injection\b|\bsqli\b"), "sql-injection"),
        (re.compile(r"\bauth.bypass\b|\bprivilege.escalation\b"), "auth-bypass"),
        (
            re.compile(r"\bweak.crypto\b|\bcrypto.*weak\b|\bweak.*encrypt"),
            "weak-crypto",
        ),
        (
            re.compile(r"\brace.condition\b|\btoctou\b|\btime.of.check\b"),
            "race-condition",
        ),
        (re.compile(r"\bxss\b|\bcross.site\b"), "command-injection"),
        (
            re.compile(r"\bdenial.of.service\b|\bdos\b|\bresource.exhaust\b"),
            "resource-exhaustion",
        ),
    ]
    for pattern, cls in patterns:
        if pattern.search(lower):
            return cls
    return ""


def build_cve_corpus(
    repo_path: Path,
    snippets: list[dict],
    cache: JsonCache | None = None,
    user_corpus_path: Path | None = None,
    no_fetch: bool = False,
) -> list[dict]:
    from .cve_corpus import load_cve_corpus as load_user_corpus

    entries: list[dict] = []

    if user_corpus_path:
        try:
            entries.extend(load_user_corpus(user_corpus_path))
        except Exception:
            pass

    if no_fetch:
        return entries

    cached = cache.get("cve_fetcher_entries") if cache else []
    if isinstance(cached, list) and cached:
        entries.extend(cached)
        return entries

    queries = _collect_cve_queries(repo_path, snippets)
    if queries:
        osv_results = _osv_batch_query(queries)
        fetched = _extract_cve_entries(osv_results)
        if fetched and cache is not None:
            cache.put("cve_fetcher_entries", fetched)
        entries.extend(fetched)

    return entries


def _collect_cve_queries(
    repo_path: Path,
    snippets: list[dict],
) -> list[tuple[str, str]]:
    manifest_deps = scan_manifests(repo_path)
    queries: list[tuple[str, str]] = []
    seen_pkg: set[tuple[str, str]] = set()

    from .recon import _normalise_dependency_name

    for ecosystem, pkg_names in manifest_deps.items():
        for name in pkg_names:
            key = (name, ecosystem)
            if key not in seen_pkg:
                queries.append(key)
                seen_pkg.add(key)

    for snip in snippets:
        for raw_name in snip.get("imports") or []:
            raw_name = raw_name.strip()
            ecosystem = infer_ecosystem(
                raw_name, set(manifest_deps.keys()) if manifest_deps else None
            )
            if not ecosystem:
                continue
            normed = _normalise_dependency_name(raw_name)
            key = (normed, ecosystem)
            if key not in seen_pkg and normed:
                queries.append(key)
                seen_pkg.add(key)

    return queries
