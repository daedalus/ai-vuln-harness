"""ASAN output parsing: frame extraction, crash_reason, excerpt construction."""

from __future__ import annotations

import unittest

from ai_vuln_harness.asan import (
    asan_excerpt,
    crash_reason,
    project_frames,
    top_frame,
)


# ── Sample traces ────────────────────────────────────────────────────────────

ASAN_OVERFLOW_WRITE = """\
==79==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f5837100030
WRITE of size 17 at 0x7f5837100030 thread T0
    #0 0x7f58396817ee in memcpy (/usr/local/lib64/libasan.so.8+0xf27ee)
    #1 0x4012e9 in parse_bravo /work/entry.c:38
SUMMARY: AddressSanitizer: stack-buffer-overflow (/usr/local/lib64/libasan.so.8+0xf27ee) in memcpy
"""

ASAN_OVERFLOW_READ = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000110
READ of size 4 at 0x602000000110 thread T0
    #0 0x55a1 in decode_chunk /work/decoder.h:4521:9
SUMMARY: AddressSanitizer: heap-buffer-overflow /work/decoder.h:4521 in decode_chunk
"""

ASAN_SEGV_WRITE = """\
AddressSanitizer:DEADLYSIGNAL
==200==ERROR: AddressSanitizer: SEGV on unknown address 0x7f85c3ef87fa
==200==The signal is caused by a WRITE memory access.
    #0 0x4053d5 in out_gif_code /work/img.h:6668
SUMMARY: AddressSanitizer: SEGV /work/img.h:6668 in out_gif_code
"""

ASAN_ALLOC_TOO_BIG = """\
==1==ERROR: AddressSanitizer: requested allocation size 0xffffffff80008000 exceeds maximum supported size
    #0 0x7fedd2e4ac57 in malloc (/usr/local/lib64/libasan.so.8+0xf4c57)
    #1 0x4173ee in my_malloc /work/img.h:987
SUMMARY: AddressSanitizer: allocation-size-too-big (/usr/local/lib64/libasan.so.8+0xf4c57) in malloc
"""

ASSERTION_OUTPUT = """\
entry: /work/img.h:1761: convert_format: Assertion `n >= 1 && n <= 4' failed.
Aborted
"""

UAF_STACK = """\
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020000000f0
WRITE of size 8 at 0x6020000000f0 thread T0
    #0 0x401234 in use_after_free /work/buggy.c:42
    #1 0x401567 in caller_func /work/main.c:120
    #2 0x401789 in main /work/main.c:15
    #3 0x7f1234567890 in __libc_start_main (libc.so.6+0x12345)
freed by thread T0 here:
    #0 0x7f9876543210 in free (libasan.so.8+0x67890)
    #1 0x401111 in free_buf /work/buggy.c:30
previously allocated by thread T0 here:
    #0 0x7f9876543220 in malloc (libasan.so.8+0x67900)
    #1 0x401222 in alloc_buf /work/buggy.c:25
SUMMARY: AddressSanitizer: heap-use-after-free /work/buggy.c:42 in use_after_free
"""


# ── crash_reason tests ───────────────────────────────────────────────────────


class CrashReasonTest(unittest.TestCase):
    """crash_reason() extracts crash_type + operation from ASAN output."""

    def test_summary_line_parsed(self):
        r = crash_reason(ASAN_OVERFLOW_READ)
        self.assertEqual(r["crash_type"], "heap-buffer-overflow")
        self.assertEqual(r["operation"], "READ")

    def test_write_overflow(self):
        r = crash_reason(ASAN_OVERFLOW_WRITE)
        self.assertEqual(
            r, {"crash_type": "stack-buffer-overflow", "operation": "WRITE"}
        )

    def test_segv_write_op(self):
        r = crash_reason(ASAN_SEGV_WRITE)
        self.assertEqual(r, {"crash_type": "SEGV", "operation": "WRITE"})

    def test_allocation_too_big_no_op(self):
        r = crash_reason(ASAN_ALLOC_TOO_BIG)
        self.assertEqual(
            r, {"crash_type": "allocation-size-too-big", "operation": None}
        )

    def test_assertion_failure(self):
        r = crash_reason(ASSERTION_OUTPUT)
        self.assertEqual(r, {"crash_type": "assertion-failure", "operation": None})

    def test_assertion_overrides_abrt(self):
        trace = (
            "entry: /w/x.h:1761: convert: Assertion `n >= 1' failed.\n"
            "==1==ERROR: AddressSanitizer: ABRT on unknown address\n"
            "    #0 0x7f4 in raise (/lib/libc.so.6+0x94)\n"
            "SUMMARY: AddressSanitizer: ABRT (/lib/libc.so.6+0x94)\n"
        )
        r = crash_reason(trace)
        self.assertEqual(r["crash_type"], "assertion-failure")

    def test_bare_abrt_without_assertion(self):
        r = crash_reason("SUMMARY: AddressSanitizer: ABRT (/lib/libc.so.6+0x94)\n")
        self.assertEqual(r, {"crash_type": "ABRT", "operation": None})

    def test_unparseable_output(self):
        r = crash_reason("<no parseable trace>")
        self.assertEqual(r, {"crash_type": None, "operation": None})

    def test_empty_output(self):
        r = crash_reason("")
        self.assertEqual(r, {"crash_type": None, "operation": None})

    def test_uaf_reason(self):
        r = crash_reason(UAF_STACK)
        self.assertEqual(r["crash_type"], "heap-use-after-free")
        self.assertEqual(r["operation"], "WRITE")


# ── project_frames tests ─────────────────────────────────────────────────────


class ProjectFramesTest(unittest.TestCase):
    """project_frames() extracts top-N frames with project source info."""

    def test_returns_project_frames(self):
        frames = project_frames(ASAN_OVERFLOW_WRITE)
        self.assertEqual(len(frames), 1)
        self.assertIn("parse_bravo /work/entry.c:38", frames[0])

    def test_returns_multiple_frames(self):
        frames = project_frames(ASAN_OVERFLOW_READ)
        self.assertEqual(len(frames), 1)
        self.assertIn("decode_chunk /work/decoder.h:4521", frames[0])

    def test_respects_n_param(self):
        frames = project_frames(UAF_STACK, n=2)
        self.assertEqual(len(frames), 2)
        self.assertIn("/work/buggy.c:42", frames[0])
        self.assertIn("/work/main.c:120", frames[1])

    def test_stops_at_second_alloc_section(self):
        """UAF traces have allocated-by/freed-by sections — stop at them."""
        frames = project_frames(UAF_STACK, n=10)
        self.assertEqual(len(frames), 3)
        # All three project frames from the first section, none from freed-by.
        self.assertIn("/work/buggy.c:42", frames[0])
        self.assertIn("/work/main.c:120", frames[1])
        self.assertIn("/work/main.c:15", frames[2])

    def test_assertion_returns_formatted_frame(self):
        frames = project_frames(ASSERTION_OUTPUT)
        self.assertEqual(len(frames), 1)
        self.assertIn("convert_format", frames[0])

    def test_empty_output_yields_empty(self):
        self.assertEqual(project_frames(""), [])

    def test_garbage_output_yields_empty(self):
        self.assertEqual(project_frames("not an asan trace at all\n"), [])

    def test_fallback_to_frame_zero_when_no_source_loc(self):
        lib_only = """\
==1==ERROR: AddressSanitizer: SEGV
    #0 0x7f1234 in memset (libc.so.6+0x5678)
SUMMARY: AddressSanitizer: SEGV
"""
        frames = project_frames(lib_only)
        self.assertEqual(len(frames), 1)
        self.assertIn("memset", frames[0])


# ── top_frame tests ──────────────────────────────────────────────────────────


class TopFrameTest(unittest.TestCase):
    """top_frame() is a convenience wrapper returning the first frame."""

    def test_returns_first_project_frame(self):
        self.assertEqual(top_frame(ASAN_OVERFLOW_WRITE), "parse_bravo /work/entry.c:38")

    def test_returns_none_for_empty(self):
        self.assertIsNone(top_frame(""))

    def test_returns_none_for_garbage(self):
        self.assertIsNone(top_frame("no asan output here"))

    def test_returns_formatted_for_assertion(self):
        t = top_frame(ASSERTION_OUTPUT)
        self.assertIsNotNone(t)
        self.assertIn("convert_format", t)


# ── asan_excerpt tests ───────────────────────────────────────────────────────


class AsanExcerptTest(unittest.TestCase):
    """asan_excerpt() builds compact summaries of ASAN traces."""

    def test_excerpt_contains_error_and_summary(self):
        ex = asan_excerpt(ASAN_OVERFLOW_WRITE)
        self.assertIn("ERROR: AddressSanitizer: stack-buffer-overflow", ex)
        self.assertIn("SUMMARY: AddressSanitizer: stack-buffer-overflow", ex)

    def test_excerpt_includes_frames(self):
        ex = asan_excerpt(ASAN_OVERFLOW_WRITE)
        self.assertIn("#0", ex)
        self.assertIn("#1", ex)

    def test_excerpt_caps_frames(self):
        many_frames = "\n".join(
            f"    #{i} 0x{i:04x} in func_{i} /work/code.c:{100 + i}" for i in range(20)
        )
        trace = f"==1==ERROR: AddressSanitizer: SEGV\n{many_frames}\nSUMMARY: AddressSanitizer: SEGV\n"
        ex = asan_excerpt(trace, max_frames=10)
        self.assertIn("#9 ", ex)
        self.assertNotIn("#10 ", ex)

    def test_excerpt_non_asan_fallback(self):
        ex = asan_excerpt(ASSERTION_OUTPUT)
        self.assertIn("Assertion", ex)
        self.assertIn("Aborted", ex)

    def test_excerpt_empty(self):
        self.assertEqual(asan_excerpt(""), "")

    def test_excerpt_garbage(self):
        ex = asan_excerpt("some random unformatted text\non multiple lines\n")
        self.assertIn("some random unformatted text", ex)
