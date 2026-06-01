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
(stdlib only) and returns it as a plain dict.  The body text (everything after
the closing ``---``) is returned under the ``"body"`` key so callers can render
the documentation section if needed.
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Locate SKILL.md — search the package root, then walk up the filesystem
# tree from the package directory until we find it (handles editable installs,
# wheel installs, and arbitrary directory layouts).
# ---------------------------------------------------------------------------


def _find_skill_md() -> Path | None:
    """Return the first existing SKILL.md by searching upward from the package."""
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


# ---------------------------------------------------------------------------
# Minimal YAML front-matter parser (stdlib only, no PyYAML dependency).
# ---------------------------------------------------------------------------

_SIMPLE_VALUE_RE = re.compile(r'^"(.*)"|^\'(.*)\'|^(.+)$')
_FOLDED_SCALAR_RE = re.compile(r"^>\s*$")  # folded block scalar marker


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
            # collect continuation lines (indented)
            parts: list[str] = []
            while i < len(fm_lines):
                cont = fm_lines[i]
                if cont and cont[0] in (" ", "\t"):
                    parts.append(cont.strip())
                    i += 1
                else:
                    break
            meta[key] = " ".join(parts)
        else:
            m = _SIMPLE_VALUE_RE.match(rest)
            if m:
                meta[key] = m.group(1) or m.group(2) or m.group(3)
            else:
                meta[key] = rest
    return meta, body


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_skill_metadata(skill_path: Path | None = None) -> dict[str, Any]:
    """Return the parsed SKILL.md front matter as a dict.

    Args:
        skill_path: Explicit path to a SKILL.md file.  When *None* (default)
            the function searches the repository root relative to this module.

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
    path = skill_path or _find_skill_md()
    if path is None or not path.exists():
        return {
            "name": "ai-vuln-harness",
            "description": "Multi-agent vulnerability research harness",
            "skill_path": None,
            "body": "",
        }

    text = path.read_text(encoding="utf-8")
    meta, body = _parse_front_matter(text)
    meta["body"] = body
    meta["skill_path"] = str(path.resolve())
    return meta


def skill_name(skill_path: Path | None = None) -> str:
    """Return the skill name from SKILL.md front matter."""
    return str(load_skill_metadata(skill_path).get("name", "ai-vuln-harness"))


def skill_description(skill_path: Path | None = None) -> str:
    """Return the skill description from SKILL.md front matter."""
    return str(
        load_skill_metadata(skill_path).get(
            "description", "Multi-agent vulnerability research harness"
        )
    )
