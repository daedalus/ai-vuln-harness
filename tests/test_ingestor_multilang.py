import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.ingestor import load_repo_snippets


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


if __name__ == "__main__":
    unittest.main()
