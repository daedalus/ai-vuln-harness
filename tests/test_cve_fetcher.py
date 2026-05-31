"""Tests for the CVE fetcher module (OSV.dev API, manifest scanning, ecosystem inference)."""

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ai_vuln_harness.stages.cve_fetcher import (
    _cve_class_from_description,
    _extract_cve_entries,
    _extract_severity,
    _parse_cargo_lock,
    _parse_gemfile,
    _parse_gemfile_lock,
    _parse_go_mod,
    _parse_manifest,
    _parse_npm_lock,
    _parse_toml_deps,
    build_cve_corpus,
    infer_ecosystem,
    scan_manifests,
)


class ScanManifestsTests(unittest.TestCase):
    def test_empty_repo_returns_empty(self, tmp_path: Path = Path("/tmp/nonexist")):
        result = scan_manifests(Path("/tmp/__nonexistent_repo__"))
        self.assertEqual(result, {})

    def test_package_json_detected(self):
        with _temp_repo(
            {"package.json": '{"dependencies": {"lodash": "^4.0.0"}}'}
        ) as repo:
            result = scan_manifests(repo)
        self.assertIn("npm", result)
        self.assertIn("lodash", result["npm"])

    def test_cargo_toml_detected(self):
        content = '[dependencies]\nserde = "1.0"\ntokio = { version = "1", features = ["full"] }\n'
        with _temp_repo({"Cargo.toml": content}) as repo:
            result = scan_manifests(repo)
        self.assertIn("crates.io", result)
        self.assertIn("serde", result["crates.io"])
        self.assertIn("tokio", result["crates.io"])

    def test_go_mod_detected(self):
        content = "module example.com/m\n\ngo 1.21\n\nrequire (\n\tgithub.com/foo/bar v1.0.0\n)\n"
        with _temp_repo({"go.mod": content}) as repo:
            result = scan_manifests(repo)
        self.assertIn("Go", result)
        self.assertTrue(any("github.com/foo/bar" in d for d in result["Go"]))

    def test_requirements_txt_detected(self):
        content = "flask==2.0\nrequests>=2.28\n# comment\ndjango\n"
        with _temp_repo({"requirements.txt": content}) as repo:
            result = scan_manifests(repo)
        self.assertIn("PyPI", result)
        for name in ("flask", "requests", "django"):
            self.assertIn(name, result["PyPI"])

    def test_multiple_manifest_files(self):
        files = {
            "package.json": '{"dependencies": {"express": "^4.0.0"}}',
            "Cargo.toml": '[dependencies]\nserde = "1.0"\n',
        }
        with _temp_repo(files) as repo:
            result = scan_manifests(repo)
        self.assertIn("npm", result)
        self.assertIn("crates.io", result)


class ParseNpmLockTests(unittest.TestCase):
    def test_parse_npm_lock_v3(self):
        content = json.dumps(
            {
                "packages": {
                    "": {"name": "test"},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/express/lib": {"version": "4.18.0"},
                }
            }
        )
        names = _parse_npm_lock(content)
        self.assertIn("lodash", names)
        self.assertNotIn("", names)

    def test_parse_npm_lock_empty(self):
        self.assertEqual(_parse_npm_lock("{}"), [])

    def test_parse_npm_lock_invalid(self):
        self.assertEqual(_parse_npm_lock("not-json"), [])


class ParseCargoLockTests(unittest.TestCase):
    def test_parse_cargo_lock(self):
        content = '[[package]]\nname = "serde"\nversion = "1.0"\n\n[[package]]\nname = "tokio"\nversion = "1.0"\n'
        names = _parse_cargo_lock(content)
        self.assertIn("serde", names)
        self.assertIn("tokio", names)

    def test_parse_cargo_lock_empty(self):
        self.assertEqual(_parse_cargo_lock(""), [])


class ParseGoModTests(unittest.TestCase):
    def test_parse_block_require(self):
        content = "module example.com/m\n\ngo 1.21\n\nrequire (\n\tgithub.com/foo/bar v1.0.0\n\tgolang.org/x/net v0.5.0\n)\n"
        names = _parse_go_mod(content)
        self.assertIn("github.com/foo/bar", names)
        self.assertIn("golang.org/x/net", names)

    def test_parse_single_require(self):
        content = (
            "module example.com/m\n\ngo 1.21\n\nrequire github.com/foo/bar v1.0.0\n"
        )
        names = _parse_go_mod(content)
        self.assertIn("github.com/foo/bar", names)

    def test_parse_empty(self):
        self.assertEqual(_parse_go_mod(""), [])


class ParseTomlDepsTests(unittest.TestCase):
    def test_crates_deps(self):
        text = '[dependencies]\nserde = "1.0"\ntokio = { version = "1" }\n'
        names = _parse_toml_deps(text, "crates.io")
        self.assertIn("serde", names)
        self.assertIn("tokio", names)


class ParseGemfileTests(unittest.TestCase):
    def test_gemfile(self):
        content = "source 'https://rubygems.org'\ngem 'rails'\ngem 'devise', '~> 4.0'\n"
        names = _parse_gemfile(content)
        self.assertIn("rails", names)
        self.assertIn("devise", names)

    def test_gemfile_empty(self):
        self.assertEqual(_parse_gemfile(""), [])


class ParseGemfileLockTests(unittest.TestCase):
    def test_gemfile_lock(self):
        content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n    nokogiri (1.15.0)\n"
        names = _parse_gemfile_lock(content)
        self.assertIn("rails", names)
        self.assertIn("nokogiri", names)


class InferEcosystemTests(unittest.TestCase):
    def test_github_dot_com_is_go(self):
        self.assertEqual(infer_ecosystem("github.com/gorilla/mux"), "Go")

    def test_scoped_npm_is_npm(self):
        self.assertEqual(infer_ecosystem("@angular/core"), "npm")

    def test_rust_crate_is_crates_io(self):
        self.assertEqual(infer_ecosystem("::serde"), "crates.io")

    def test_unknown_returns_none(self):
        self.assertIsNone(infer_ecosystem("some_random_lib"))

    def test_uses_known_ecosystem_first(self):
        self.assertEqual(infer_ecosystem("flask", {"PyPI"}), "PyPI")


class CveClassFromDescriptionTests(unittest.TestCase):
    def test_buffer_overflow(self):
        self.assertEqual(
            _cve_class_from_description("Buffer overflow in foo()"), "buffer-overflow"
        )

    def test_use_after_free(self):
        self.assertEqual(
            _cve_class_from_description("Use-after-free in bar()"), "use-after-free"
        )

    def test_path_traversal(self):
        self.assertEqual(
            _cve_class_from_description("Directory traversal via ../"), "path-traversal"
        )

    def test_unknown_returns_empty(self):
        self.assertEqual(_cve_class_from_description("Some random bug"), "")

    def test_case_insensitive(self):
        self.assertEqual(
            _cve_class_from_description("BUFFER OVERFLOW"), "buffer-overflow"
        )


class ExtractSeverityTests(unittest.TestCase):
    def test_from_cvss_score(self):
        vuln = {
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ]
        }
        self.assertEqual(_extract_severity(vuln), "HIGH")

    def test_from_database_specific(self):
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        self.assertEqual(_extract_severity(vuln), "CRITICAL")

    def test_unknown_when_no_severity(self):
        self.assertEqual(_extract_severity({}), "UNKNOWN")


class ExtractCveEntriesTests(unittest.TestCase):
    def test_extract_basic(self):
        osv_results = {
            ("lodash", "npm"): [
                {
                    "id": "GHSA-xxxx",
                    "aliases": ["CVE-2024-1234"],
                    "summary": "Prototype pollution in lodash",
                    "details": "Lodash is vulnerable to prototype pollution",
                    "severity": [],
                }
            ]
        }
        entries = _extract_cve_entries(osv_results)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["cve_id"], "CVE-2024-1234")
        self.assertEqual(entries[0]["package"], "lodash")
        self.assertEqual(entries[0]["ecosystem"], "npm")

    def test_deduplicates_by_cve_id(self):
        osv_results = {
            ("lodash", "npm"): [
                {"id": "GHSA-xxx", "aliases": ["CVE-2024-1234"], "summary": "Bug 1"},
                {"id": "GHSA-yyy", "aliases": ["CVE-2024-1234"], "summary": "Bug 2"},
            ]
        }
        entries = _extract_cve_entries(osv_results)
        self.assertEqual(len(entries), 1)

    def test_no_aliases_uses_id(self):
        osv_results = {
            ("pkg", "npm"): [{"id": "CVE-2024-5678", "aliases": [], "summary": "Bug"}]
        }
        entries = _extract_cve_entries(osv_results)
        self.assertEqual(entries[0]["cve_id"], "CVE-2024-5678")


class BuildCveCorpusTests(unittest.TestCase):
    def test_no_fetch_returns_empty(self):
        cache = MagicMock()
        result = build_cve_corpus(
            Path("/tmp/nonexist"),
            [],
            cache=cache,
            no_fetch=True,
        )
        self.assertEqual(result, [])

    def test_user_corpus_included(self):
        with _temp_repo(
            {
                "cves.json": json.dumps(
                    [
                        {
                            "cve_id": "CVE-2024-0001",
                            "description": "test",
                            "class": "buffer-overflow",
                        },
                    ]
                )
            }
        ) as repo:
            result = build_cve_corpus(
                repo / "..",
                [],
                cache=MagicMock(),
                user_corpus_path=repo / "cves.json",
                no_fetch=True,
            )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2024-0001")

    def test_cache_hit_skips_network(self):
        cache = MagicMock()
        cache.get.return_value = [{"cve_id": "CVE-2024-0001", "description": "cached"}]
        with patch("ai_vuln_harness.stages.cve_fetcher._osv_batch_query") as mock_query:
            result = build_cve_corpus(
                Path("/tmp/nonexist"),
                [],
                cache=cache,
            )
        mock_query.assert_not_called()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2024-0001")

    def test_manifest_drives_queries(self):
        cache = MagicMock()
        cache.get.return_value = None
        with (
            _temp_repo(
                {"package.json": '{"dependencies": {"lodash": "^4.0.0"}}'}
            ) as repo,
            patch("ai_vuln_harness.stages.cve_fetcher._osv_batch_query") as mock_query,
        ):
            mock_query.return_value = {
                ("lodash", "npm"): [
                    {
                        "id": "GHSA-xxx",
                        "aliases": ["CVE-2024-1234"],
                        "summary": "PP in lodash",
                    }
                ]
            }
            result = build_cve_corpus(repo, [], cache=cache)
        mock_query.assert_called_once()
        args = mock_query.call_args[0][0]
        self.assertIn(("lodash", "npm"), args)
        self.assertEqual(len(result), 1)

    def test_snippet_imports_also_queried(self):
        cache = MagicMock()
        cache.get.return_value = None
        snippets = [
            {
                "imports": ["github.com/gorilla/mux"],
            }
        ]
        with patch("ai_vuln_harness.stages.cve_fetcher._osv_batch_query") as mock_query:
            mock_query.return_value = {
                ("github.com", "Go"): [
                    {"id": "CVE-2024-5678", "aliases": [], "summary": "Go bug"}
                ]
            }
            result = build_cve_corpus(Path("/tmp/nonexist"), snippets, cache=cache)
        mock_query.assert_called_once()
        self.assertEqual(len(result), 1)


def _temp_repo(files: dict[str, str]):
    import tempfile
    from contextlib import contextmanager

    @contextmanager
    def _inner():
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            for name, content in files.items():
                (repo / name).write_text(content)
            yield repo

    return _inner()
