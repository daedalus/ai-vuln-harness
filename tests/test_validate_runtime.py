import unittest
from unittest.mock import patch

from ai_vuln_harness.stages.validate import (
    recompile_and_run_unvalidated_vulnerable_snippet,
)


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class ValidateRuntimeTests(unittest.TestCase):
    def test_non_c_snippet_skips(self):
        finding = {"unvalidated_vulnerable_snippet": 'print("hi")'}
        snippet = {"file": "x.py", "language": "python"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertFalse(out["compile_attempted"])
        self.assertFalse(out["run_attempted"])

    @patch("ai_vuln_harness.stages.validate.subprocess.run")
    def test_compile_failure(self, run_mock):
        run_mock.return_value = _Proc(returncode=1, stderr="compile err")
        finding = {"unvalidated_vulnerable_snippet": "int main(){ return nope; }"}
        snippet = {"file": "x.c", "language": "c"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertTrue(out["compile_attempted"])
        self.assertFalse(out["compile_succeeded"])
        self.assertEqual(out["error"], "compile_failed")
        self.assertFalse(out["run_attempted"])
        self.assertEqual(run_mock.call_count, 1)

    @patch("ai_vuln_harness.stages.validate.subprocess.run")
    def test_compile_and_run_success_with_vuln_signal(self, run_mock):
        run_mock.side_effect = [
            _Proc(returncode=0, stdout="", stderr=""),
            _Proc(returncode=1, stdout="", stderr="Segmentation fault"),
        ]
        finding = {
            "unvalidated_vulnerable_snippet": "int main(){int *p=0; *p=1; return 0;}"
        }
        snippet = {"file": "x.c", "language": "c"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertTrue(out["compile_succeeded"])
        self.assertTrue(out["run_attempted"])
        self.assertTrue(out["run_succeeded"])
        self.assertTrue(out["vulnerability_observed"])
        self.assertEqual(out["exit_code"], 1)

    @patch("ai_vuln_harness.stages.validate.subprocess.run")
    def test_sandbox_prefix_applied(self, run_mock):
        run_mock.side_effect = [_Proc(returncode=0), _Proc(returncode=0)]
        finding = {"unvalidated_vulnerable_snippet": "int main(){return 0;}"}
        snippet = {"file": "x.cpp", "language": "cpp"}
        _ = recompile_and_run_unvalidated_vulnerable_snippet(
            finding,
            snippet,
            sandbox_prefix=["qemu-x86_64"],
        )
        run_cmd = run_mock.call_args_list[1].args[0]
        self.assertEqual(run_cmd[0], "qemu-x86_64")


if __name__ == "__main__":
    unittest.main()
