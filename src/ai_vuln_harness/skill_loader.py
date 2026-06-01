"""SKILL.md loader — parse skill front matter and expose metadata programmatically.

The SKILL.md file in the repository root carries a YAML front matter block
that identifies this package as an AI coding skill:

    ---
    name: ai-vuln-harness
    description: >
      ...
    version: "1.0.0"
    entry_point: "src/ai_vuln_harness"
    mcp_server: "ai-vuln-harness-mcp"
    ---

``load_skill_metadata()`` parses that block without an external YAML dependency
(stdlib only) and returns it as a plain dict. The body text (everything after
the closing ``---``) is returned under the ``"body"`` key so callers can render
the documentation section if needed. User-provided skills can also be
discovered dynamically from ``~/.ai-vuln-harness/skills/``.
"""

from __future__ import annotations

import re
from importlib import resources  # nosem: project requires Python >=3.11
from pathlib import Path
from typing import Any

USER_SKILLS_DIR = Path.home() / ".ai-vuln-harness" / "skills"


def _default_skill_metadata() -> dict[str, Any]:
    """Return fallback metadata when no skill file is available."""
    return {
        "name": "ai-vuln-harness",
        "description": "Multi-agent vulnerability research harness",
        "skill_path": None,
        "skill_dir": None,
        "body": "",
    }


# ---------------------------------------------------------------------------
# Locate builtin and user-provided SKILL.md files.
# ---------------------------------------------------------------------------


def _find_builtin_skill_md() -> Path | None:
    """Return the bundled SKILL.md by searching upward from the package."""
    # Try importlib.resources first (works in both editable and installed layouts)
    try:
        pkg_files = resources.files("ai_vuln_harness")
        # Walk up from the package anchor to find the repo/project root
        pkg_path = Path(str(pkg_files))
        for candidate in (
            pkg_path / "SKILL.md",
            *[p / "SKILL.md" for p in pkg_path.parents],
        ):
            if candidate.is_file():
                return candidate
    except (TypeError, AttributeError, OSError):
        pass
    # Fallback: walk up from __file__
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "SKILL.md"
        if candidate.is_file():
            return candidate
    return None


def _list_discovered_skill_mds(skills_dir: Path | None = None) -> list[Path]:
    """Return discovered user skill files under the configured skills directory."""
    root = (skills_dir or USER_SKILLS_DIR).expanduser()
    if not root.is_dir():
        return []

    return sorted(
        candidate.resolve()
        for candidate in root.rglob("SKILL.md")
        if candidate.is_file()
    )


# ---------------------------------------------------------------------------
# Minimal YAML front-matter parser (stdlib only, no PyYAML dependency).
# ---------------------------------------------------------------------------

_SIMPLE_VALUE_RE = re.compile(r'^\s*"(.*?)"\s*$|^\s*\'(.*?)\'\s*$|^\s*([^#]+?)\s*$')
_FOLDED_SCALAR_RE = re.compile(r"^>\s*$")  # folded block scalar marker


def _collect_folded_scalar(fm_lines: list[str], start: int) -> tuple[str, int]:
    parts: list[str] = []
    i = start
    while i < len(fm_lines):
        cont = fm_lines[i]
        if cont and cont[0] in (" ", "\t"):
            parts.append(cont.strip())
            i += 1
        else:
            break
    return " ".join(parts), i


def _parse_front_matter(text: str) -> tuple[dict[str, Any], str]:
    """Split YAML front matter from Markdown body.

    Returns ``(metadata_dict, body_text)``.  The parser handles only the
    simple scalar / folded-block-scalar subset that SKILL.md uses.
    """
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip() != "---":
        return {}, text

    fm_lines: list[str] = []
    end_idx = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        if line.rstrip() == "---":
            end_idx = i + 1
            break
        fm_lines.append(line)

    meta: dict[str, Any] = {}
    body = "".join(lines[end_idx:])
    i = 0
    while i < len(fm_lines):
        raw = fm_lines[i].rstrip("\n")
        i += 1
        if not raw or raw.lstrip().startswith("#"):
            continue
        if ":" not in raw:
            continue
        key, _, rest = raw.partition(":")
        key = key.strip()
        rest = rest.strip()
        if _FOLDED_SCALAR_RE.match(rest):
            value, i = _collect_folded_scalar(fm_lines, i)
            meta[key] = value
        else:
            m = _SIMPLE_VALUE_RE.match(rest)
            if m:
                meta[key] = m.group(1) or m.group(2) or m.group(3)
            else:
                meta[key] = rest
    return meta, body


def _load_skill_file(path: Path) -> dict[str, Any]:
    """Load one SKILL.md file and normalize metadata fields."""
    text = path.read_text(encoding="utf-8")
    meta, body = _parse_front_matter(text)
    normalized = dict(meta)
    resolved = path.resolve()
    normalized["body"] = body
    normalized["skill_path"] = str(resolved)
    normalized["skill_dir"] = str(resolved.parent)
    return normalized


def _find_skill_by_name(name: str, skills_dir: Path | None = None) -> Path | None:
    """Return a user or builtin skill file matching the requested skill name."""
    for candidate in _list_discovered_skill_mds(skills_dir):
        meta, _ = _parse_front_matter(candidate.read_text(encoding="utf-8"))
        if str(meta.get("name", "")).strip() == name:
            return candidate

    builtin = _find_builtin_skill_md()
    if builtin is None:
        return None
    meta, _ = _parse_front_matter(builtin.read_text(encoding="utf-8"))
    if str(meta.get("name", "")).strip() == name:
        return builtin
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def discover_skills(
    skills_dir: Path | None = None, *, include_builtin: bool = True
) -> list[dict[str, Any]]:
    """Return metadata for builtin and discovered user skills."""
    seen_paths: set[Path] = set()
    discovered: list[dict[str, Any]] = []

    if include_builtin:
        builtin = _find_builtin_skill_md()
        if builtin is not None:
            resolved = builtin.resolve()
            seen_paths.add(resolved)
            discovered.append(_load_skill_file(resolved))

    for candidate in _list_discovered_skill_mds(skills_dir):
        if candidate in seen_paths:
            continue
        seen_paths.add(candidate)
        discovered.append(_load_skill_file(candidate))

    return discovered


def load_skill_metadata(
    skill_path: Path | None = None,
    *,
    name: str | None = None,
    skills_dir: Path | None = None,
) -> dict[str, Any]:
    """Return the parsed SKILL.md front matter as a dict.

    Args:
        skill_path: Explicit path to a SKILL.md file.  When *None* (default)
            the function loads the bundled skill metadata.
        name: Optional discovered skill name to load from ``skills_dir`` or the
            bundled skill metadata.
        skills_dir: Optional override for the user skills discovery directory.

    Returns:
        A dict containing at minimum ``name`` and ``description`` keys from
        the front matter, plus a ``"body"`` key with the Markdown body text
        and a ``"skill_path"`` key with the resolved file path as a string.
        Returns a minimal sentinel dict when no SKILL.md is found.

    Example::

        >>> from ai_vuln_harness.skill_loader import load_skill_metadata
        >>> meta = load_skill_metadata()
        >>> meta["name"]
        'ai-vuln-harness'
    """
    if skill_path is not None and name is not None:
        msg = "Specify either skill_path or name, not both."
        raise ValueError(msg)

    if skill_path is not None:
        path = skill_path
    elif name is not None:
        path = _find_skill_by_name(name, skills_dir)
    else:
        path = _find_builtin_skill_md()

    if path is None or not path.exists():
        return _default_skill_metadata()

    return _load_skill_file(path)


def skill_name(
    skill_path: Path | None = None,
    *,
    name: str | None = None,
    skills_dir: Path | None = None,
) -> str:
    """Return the skill name from SKILL.md front matter."""
    return str(
        load_skill_metadata(skill_path, name=name, skills_dir=skills_dir).get(
            "name", "ai-vuln-harness"
        )
    )


def skill_description(
    skill_path: Path | None = None,
    *,
    name: str | None = None,
    skills_dir: Path | None = None,
) -> str:
    """Return the skill description from SKILL.md front matter."""
    return str(
        load_skill_metadata(skill_path, name=name, skills_dir=skills_dir).get(
            "description", "Multi-agent vulnerability research harness"
        )
    )
