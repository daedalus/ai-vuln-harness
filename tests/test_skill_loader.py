"""Tests for skill_loader.py."""

from __future__ import annotations

from ai_vuln_harness.skill_loader import (
    _parse_front_matter,
    load_skill_metadata,
    skill_description,
    skill_name,
)

_SAMPLE_SKILL_MD = """\
---
name: test-skill
description: >
  A test skill for unit testing.
version: "2.0.0"
entry_point: "src/test_skill"
mcp_server: "test-mcp"
---

# Test Skill

Body text here.
"""

_MINIMAL_SKILL_MD = """\
---
name: minimal
description: Minimal skill
---
"""

_NO_FRONT_MATTER = """\
# Just a Markdown file

No front matter here.
"""


class TestParseFrontMatter:
    def test_parses_name(self):
        meta, _ = _parse_front_matter(_SAMPLE_SKILL_MD)
        assert meta["name"] == "test-skill"

    def test_parses_folded_description(self):
        meta, _ = _parse_front_matter(_SAMPLE_SKILL_MD)
        assert "A test skill" in meta["description"]

    def test_parses_version(self):
        meta, _ = _parse_front_matter(_SAMPLE_SKILL_MD)
        assert meta["version"] == "2.0.0"

    def test_parses_entry_point(self):
        meta, _ = _parse_front_matter(_SAMPLE_SKILL_MD)
        assert meta["entry_point"] == "src/test_skill"

    def test_parses_mcp_server(self):
        meta, _ = _parse_front_matter(_SAMPLE_SKILL_MD)
        assert meta["mcp_server"] == "test-mcp"

    def test_body_contains_heading(self):
        _, body = _parse_front_matter(_SAMPLE_SKILL_MD)
        assert "# Test Skill" in body

    def test_body_contains_text(self):
        _, body = _parse_front_matter(_SAMPLE_SKILL_MD)
        assert "Body text here." in body

    def test_no_front_matter_returns_empty_meta(self):
        meta, body = _parse_front_matter(_NO_FRONT_MATTER)
        assert meta == {}
        assert "No front matter here." in body

    def test_minimal_skill(self):
        meta, _ = _parse_front_matter(_MINIMAL_SKILL_MD)
        assert meta["name"] == "minimal"
        assert meta["description"] == "Minimal skill"

    def test_empty_string(self):
        meta, body = _parse_front_matter("")
        assert meta == {}
        assert body == ""


class TestLoadSkillMetadata:
    def test_loads_from_explicit_path(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text(_SAMPLE_SKILL_MD)
        meta = load_skill_metadata(skill_file)
        assert meta["name"] == "test-skill"
        assert meta["version"] == "2.0.0"

    def test_includes_body(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text(_SAMPLE_SKILL_MD)
        meta = load_skill_metadata(skill_file)
        assert "# Test Skill" in meta["body"]

    def test_includes_skill_path(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text(_SAMPLE_SKILL_MD)
        meta = load_skill_metadata(skill_file)
        assert meta["skill_path"] == str(skill_file.resolve())

    def test_missing_file_returns_sentinel(self, tmp_path):
        missing = tmp_path / "SKILL.md"
        meta = load_skill_metadata(missing)
        assert meta["name"] == "ai-vuln-harness"
        assert meta["skill_path"] is None
        assert meta["body"] == ""

    def test_real_skill_md_loads(self):
        """The real SKILL.md should load successfully."""
        meta = load_skill_metadata()
        assert meta["name"] == "ai-vuln-harness"
        assert len(meta["description"]) > 10
        assert meta["skill_path"] is not None

    def test_real_skill_md_has_mcp_server(self):
        meta = load_skill_metadata()
        assert meta.get("mcp_server") == "ai-vuln-harness-mcp"

    def test_real_skill_md_has_version(self):
        meta = load_skill_metadata()
        assert "version" in meta

    def test_real_skill_md_body_not_empty(self):
        meta = load_skill_metadata()
        assert meta["body"].strip()


class TestSkillNameDescription:
    def test_skill_name_from_file(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text(_SAMPLE_SKILL_MD)
        assert skill_name(skill_file) == "test-skill"

    def test_skill_description_from_file(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text(_SAMPLE_SKILL_MD)
        assert "A test skill" in skill_description(skill_file)

    def test_skill_name_from_real_skill_md(self):
        assert skill_name() == "ai-vuln-harness"

    def test_skill_description_real(self):
        desc = skill_description()
        assert len(desc) > 10

    def test_skill_name_fallback_when_missing(self, tmp_path):
        missing = tmp_path / "SKILL.md"
        assert skill_name(missing) == "ai-vuln-harness"

    def test_skill_description_fallback_when_missing(self, tmp_path):
        missing = tmp_path / "SKILL.md"
        assert "harness" in skill_description(missing).lower()
