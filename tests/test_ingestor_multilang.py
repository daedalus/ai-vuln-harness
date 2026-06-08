import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_vuln_harness.stages.ingestor import (
    _LANGUAGE_CST_CONFIG,
    load_repo_snippets,
)


class IngestorMultiLanguageTests(unittest.TestCase):
    def test_extracts_function_snippets_for_python_go_rust_typescript(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.py").write_text(
                "import requests\n\ndef handle(req):\n    return req\n"
            )
            (root / "server.go").write_text(
                'package main\nimport "net/http"\nfunc Serve() { http.ListenAndServe(":80", nil) }\n'
            )
            (root / "lib.rs").write_text(
                'use std::fs;\npub fn parse() { let _ = fs::read_to_string("x"); }\n'
            )
            (root / "app.ts").write_text(
                'import axios from "axios"\nexport function run() { return axios.get("/") }\n'
            )

            snippets = load_repo_snippets(root)

        funcs = [s for s in snippets if s.get("kind") == "function"]
        names = {s.get("name") for s in funcs}
        self.assertIn("handle", names)
        self.assertIn("Serve", names)
        self.assertIn("parse", names)
        self.assertIn("run", names)

    def test_extracts_language_specific_imports(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.py").write_text("from urllib import parse\nimport requests\n")
            (root / "main.ts").write_text(
                'import lodash from "lodash"\nconst x = require("left-pad")\n'
            )
            (root / "main.go").write_text(
                'package main\nimport (\n  "net/http"\n  "fmt"\n)\n'
            )
            snippets = load_repo_snippets(root)

        imports = {s["file"]: set(s.get("imports") or []) for s in snippets}
        self.assertIn("requests", imports["main.py"])
        self.assertIn("urllib", imports["main.py"])
        self.assertIn("lodash", imports["main.ts"])
        self.assertIn("left-pad", imports["main.ts"])
        self.assertIn("net/http", imports["main.go"])

    def test_extracts_java_snippets(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "App.java").write_text(
                "import java.util.List;\npublic class App {\n  public void run() {}\n}\n"
            )
            snippets = load_repo_snippets(root)

        self.assertEqual(len(snippets), 1)
        self.assertEqual(snippets[0]["language"], "java")
        self.assertEqual(snippets[0]["kind"], "function")
        self.assertIn("java.util.List", snippets[0].get("imports") or [])

    def test_extracts_java_imports(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Main.java").write_text(
                "import java.util.Map;\nimport java.io.*;\n"
                "import static org.junit.Assert.*;\n"
            )
            snippets = load_repo_snippets(root)
        imports = {s["file"]: set(s.get("imports") or []) for s in snippets}
        self.assertIn("java.util.Map", imports["Main.java"])
        self.assertIn("java.io.*", imports["Main.java"])
        self.assertIn("org.junit.Assert.*", imports["Main.java"])

    def test_language_config_has_all_supported_languages(self):
        expected = {
            "c",
            "cpp",
            "rust",
            "go",
            "python",
            "javascript",
            "typescript",
            "java",
        }
        self.assertEqual(set(_LANGUAGE_CST_CONFIG.keys()), expected)

    def test_java_file_in_supported_extensions(self):
        from ai_vuln_harness.stages.ingestor import (
            _SUPPORTED_EXTENSIONS,
            _detect_language,
        )

        self.assertIn(".java", _SUPPORTED_EXTENSIONS)
        self.assertEqual(_detect_language(Path("test.java")), "java")

    def test_falls_back_to_regex_when_tree_sitter_not_installed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.py").write_text(
                "import os\n\ndef work(arg):\n    return os.path.join(arg, 'x')\n"
            )
            with patch(
                "ai_vuln_harness.stages.ingestor._make_parser",
                return_value=None,
            ):
                snippets = load_repo_snippets(root)
        funcs = [s for s in snippets if s.get("kind") == "function"]
        names = {s.get("name") for s in funcs}
        self.assertIn("work", names)

    def test_tree_sitter_used_when_available(self):
        fake_snippets = [
            {
                "id": "sha256:aaaaaa:bbbbbb",
                "file": "main.py",
                "language": "python",
                "kind": "function",
                "name": "process",
                "lines": [1, 3],
                "content": "def process(data):\n    return data.strip()",
                "imports": [],
                "callees": [],
                "callers": [],
                "tags": [],
                "token_count": 10,
                "continuation": False,
            },
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.py").write_text(
                "def process(data):\n    return data.strip()\n"
            )
            with patch(
                "ai_vuln_harness.stages.ingestor._extract_cst_snippets",
                return_value=fake_snippets,
            ):
                snippets = load_repo_snippets(root)
        self.assertEqual([s["name"] for s in snippets], ["process"])


if __name__ == "__main__":
    unittest.main()
