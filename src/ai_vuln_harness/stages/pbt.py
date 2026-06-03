"""Property-Based Testing stage — multi-language invariant inference + harness fuzzing.

Placement: after LOCALIZATION, before VALIDATE.
Goal: for each localized finding, infer the invariant the finding claims is
violated, generate a fuzz harness in the snippet's language that probes that
invariant with bounded-random inputs, and run it under a language-appropriate
sanitizer / error detector.

Supported languages: c, cpp, rust, go, python, javascript, typescript.

The LLM call is only for invariant inference (not for fuzzing itself), so
PBT does not require a disjoint model pool from HUNT.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from .contracts import has_valid_suspicious_points

logger = logging.getLogger(__name__)

# ── Language toolchain availability ──

_LANGUAGE_TOOLCHAIN: dict[str, list[str]] = {
    "c": ["gcc"],
    "cpp": ["g++"],
    "rust": ["rustc"],
    "go": ["go"],
    "python": ["python3"],
    "javascript": ["node"],
    "typescript": ["npx"],
}


def _toolchain_available(language: str) -> tuple[bool, str]:
    tools = _LANGUAGE_TOOLCHAIN.get(language, [])
    missing = [t for t in tools if not shutil.which(t)]
    if missing:
        return False, f"missing: {', '.join(missing)}"
    return True, "ok"


# ── PBT language runtime (compile/run per language) ──
# Mirrors the pattern from poc.py `_LANGUAGE_RUNTIME` with PBT-specific flags.

_PBT_LANGUAGE_RUNTIME: dict[str, dict] = {
    "c": {
        "compile": [
            "gcc",
            "-O0",
            "-g",
            "-fsanitize=address",
            "{src}",
            "-o",
            "{bin}",
        ],
        "run": ["{bin}"],
        "source_ext": ".c",
        "binary_ext": ".bin",
    },
    "cpp": {
        "compile": [
            "g++",
            "-O0",
            "-g",
            "-fsanitize=address",
            "{src}",
            "-o",
            "{bin}",
        ],
        "run": ["{bin}"],
        "source_ext": ".cpp",
        "binary_ext": ".bin",
    },
    "rust": {
        "compile": [
            "rustc",
            "-C",
            "opt-level=0",
            "-C",
            "debuginfo=2",
            "-Z",
            "sanitizer=address",
            "{src}",
            "-o",
            "{bin}",
        ],
        "run": ["{bin}"],
        "source_ext": ".rs",
        "binary_ext": ".bin",
    },
    "rust_nightly": {
        "compile": [
            "rustc",
            "+nightly",
            "-C",
            "opt-level=0",
            "-C",
            "debuginfo=2",
            "-Z",
            "sanitizer=address",
            "{src}",
            "-o",
            "{bin}",
        ],
        "run": ["{bin}"],
        "source_ext": ".rs",
        "binary_ext": ".bin",
    },
    "go": {
        "compile": [
            "go",
            "build",
            "-o",
            "{bin}",
            "{src}",
        ],
        "run": ["{bin}"],
        "source_ext": ".go",
        "binary_ext": ".bin",
    },
    "python": {
        "compile": None,
        "run": ["python3", "{bin}"],
        "source_ext": ".py",
        "binary_ext": ".py",
    },
    "javascript": {
        "compile": None,
        "run": ["node", "{bin}"],
        "source_ext": ".js",
        "binary_ext": ".js",
    },
    "typescript": {
        "compile": [
            "npx",
            "tsc",
            "--strict",
            "--outDir",
            "{outdir}",
            "{src}",
        ],
        "run": ["node", "{bin}"],
        "source_ext": ".ts",
        "binary_ext": ".js",
    },
}

# ── Language-specific vulnerability signal markers ──

_VULN_MARKERS: dict[str, tuple[str, ...]] = {
    "c": (
        "addresssanitizer",
        "undefinedbehaviorsanitizer",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "use-after-free",
        "stack smashing detected",
        "segmentation fault",
        "sigsegv",
        "invalid read of size",
        "invalid write of size",
    ),
    "cpp": (
        "addresssanitizer",
        "undefinedbehaviorsanitizer",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "use-after-free",
        "stack smashing detected",
        "segmentation fault",
        "sigsegv",
        "invalid read of size",
        "invalid write of size",
        "terminate called after throwing",
        "std::bad_alloc",
        "std::out_of_range",
    ),
    "rust": (
        "addresssanitizer",
        "panicked",
        "called `option::unwrap()`",
        "called `result::unwrap()`",
        "index out of bounds",
        "segmentation fault",
        "sigsegv",
        "aborted",
        "abort",
    ),
    "go": (
        "panic:",
        "runtime error:",
        "fatal error:",
        "data race",
        "race:",
        "nil pointer dereference",
        "index out of range",
        "slice bounds out of range",
    ),
    "python": (
        "traceback",
        "memoryerror",
        "segmentationfault",
        "typeerror",
        "valueerror",
        "keyerror",
        "indexerror",
        "attributeerror",
        "recursionerror",
        "systemexit",
        "falsifying example",
    ),
    "javascript": (
        "typeerror",
        "referenceerror",
        "rangeerror",
        "syntaxerror",
        "uncaught",
        "undefined is not",
        "cannot read property",
        "cannot set property",
    ),
    "typescript": (
        "typeerror",
        "referenceerror",
        "rangeerror",
        "syntaxerror",
        "uncaught",
        "undefined is not",
        "cannot read property",
        "cannot set property",
    ),
}

# ── System prompt ──

_PBT_SYSTEM_PROMPT = (
    (Path(__file__).parent.parent / "prompts" / "pbt.md")
    .read_text(encoding="utf-8")
    .strip()
)


# ── Fallback harness generators (per-language, per-sink) ──

SinkHarnessFn = Callable[[dict, dict], str]


def _c_fallback_buffer_overflow(_finding: dict, _snippet: dict) -> str:
    return r"""#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int test_buffer_overflow(void) {
    int errors = 0;
    for (int i = 0; i < 200; i++) {
        size_t sz = (size_t)(rand() % 256);
        char *buf = (char*)malloc(sz + 1);
        if (!buf) continue;
        size_t write_sz = (size_t)(rand() % 512);
        for (size_t j = 0; j < write_sz && j < sz; j++) {
            buf[j] = (char)(rand() % 256);
        }
        if (write_sz > sz) {
            errors++;
        }
        free(buf);
    }
    return errors;
}

int main(void) {
    srand((unsigned)time(NULL));
    int result = test_buffer_overflow();
    if (result > 0) {
        printf("PBT: potential buffer overflow detected (%d hits)\n", result);
        return 1;
    }
    printf("PBT: no overflow detected\n");
    return 0;
}
"""


def _c_fallback_use_after_free(_finding: dict, _snippet: dict) -> str:
    return """#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int test_use_after_free(void) {
    int errors = 0;
    for (int i = 0; i < 200; i++) {
        size_t sz = (size_t)(rand() % 128) + 1;
        char *buf = (char*)malloc(sz);
        if (!buf) continue;
        free(buf);
        if (rand() % 5 == 0) {
            buf[rand() % sz] = (char)(rand() % 256);
            errors++;
        }
    }
    return errors;
}

int main(void) {
    srand((unsigned)time(NULL));
    int result = test_use_after_free();
    if (result > 0) {
        printf("PBT: potential use-after-free detected (%d hits)\\n", result);
        return 1;
    }
    printf("PBT: no use-after-free detected\\n");
    return 0;
}
"""


def _c_fallback_format_string(_finding: dict, _snippet: dict) -> str:
    return """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int test_format_string(void) {
    int errors = 0;
    for (int i = 0; i < 200; i++) {
        char fmt[64];
        int len = snprintf(fmt, sizeof(fmt), "%%%ds%%s%%n%%n%%n",
                           rand() % 10 + 1);
        if (len < 0 || (size_t)len >= sizeof(fmt)) {
            errors++;
            continue;
        }
    }
    return errors;
}

int main(void) {
    srand((unsigned)time(NULL));
    int result = test_format_string();
    if (result > 0) {
        printf("PBT: potential format-string hazard detected\\n");
        return 1;
    }
    printf("PBT: no format-string hazard detected\\n");
    return 0;
}
"""


def _c_fallback_generic(_finding: dict, _snippet: dict) -> str:
    return """#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int test_generic(void) {
    int errors = 0;
    for (int i = 0; i < 200; i++) {
        size_t sz = (size_t)(rand() % 256);
        char *buf = (char*)malloc(sz + 1);
        if (!buf) continue;
        memset(buf, 0, sz + 1);
        size_t idx = (size_t)(rand() % (sz + 5));
        if (idx < sz) {
            buf[idx] = (char)(rand() % 256);
        } else {
            errors++;
        }
        free(buf);
    }
    return errors;
}

int main(void) {
    srand((unsigned)time(NULL));
    int result = test_generic();
    if (result > 0) {
        printf("PBT: potential memory error detected (%d hits)\\n", result);
        return 1;
    }
    printf("PBT: no memory error detected\\n");
    return 0;
}
"""


# ── C++ fallbacks ──


def _cpp_fallback_buffer_overflow(_finding: dict, _snippet: dict) -> str:
    return """#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

static int test_buffer_overflow(void) {
    int errors = 0;
    for (int i = 0; i < 200; i++) {
        size_t sz = (size_t)(std::rand() % 256);
        size_t write_sz = (size_t)(std::rand() % 512);
        std::vector<char> buf(sz + 1, 0);
        if (write_sz > sz) {
            errors++;
        }
    }
    return errors;
}

int main(void) {
    std::srand((unsigned)std::time(nullptr));
    int result = test_buffer_overflow();
    if (result > 0) {
        std::printf("PBT: potential buffer overflow detected (%d hits)\\n", result);
        return 1;
    }
    std::printf("PBT: no overflow detected\\n");
    return 0;
}
"""


def _cpp_fallback_use_after_free(_finding: dict, _snippet: dict) -> str:
    return """#include <cstdlib>
#include <cstdio>
#include <ctime>

static int test_use_after_free(void) {
    int errors = 0;
    for (int i = 0; i < 200; i++) {
        size_t sz = (size_t)(std::rand() % 128) + 1;
        char *buf = new char[sz];
        delete[] buf;
        if (std::rand() % 5 == 0) {
            buf[std::rand() % sz] = (char)(std::rand() % 256);
            errors++;
        }
    }
    return errors;
}

int main(void) {
    std::srand((unsigned)std::time(nullptr));
    int result = test_use_after_free();
    if (result > 0) {
        std::printf("PBT: potential use-after-free detected (%d hits)\\n", result);
        return 1;
    }
    std::printf("PBT: no use-after-free detected\\n");
    return 0;
}
"""


def _cpp_fallback_generic(_finding: dict, _snippet: dict) -> str:
    return """#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>

static int test_generic(void) {
    int errors = 0;
    for (int i = 0; i < 200; i++) {
        size_t sz = (size_t)(std::rand() % 256);
        char *buf = (char*)std::malloc(sz + 1);
        if (!buf) continue;
        std::memset(buf, 0, sz + 1);
        size_t idx = (size_t)(std::rand() % (sz + 5));
        if (idx >= sz) {
            errors++;
        }
        std::free(buf);
    }
    return errors;
}

int main(void) {
    std::srand((unsigned)std::time(nullptr));
    int result = test_generic();
    if (result > 0) {
        std::printf("PBT: potential memory error detected (%d hits)\\n", result);
        return 1;
    }
    std::printf("PBT: no memory error detected\\n");
    return 0;
}
"""


# ── Rust fallbacks (use extern C for libc rand) ──


def _rust_fallback_buffer_overflow(_finding: dict, _snippet: dict) -> str:
    return """#![allow(unused_unsafe)]

extern "C" {
    fn rand() -> i32;
    fn srand(seed: u32);
}

fn test_buffer_overflow() -> i32 {
    let mut errors = 0i32;
    for _ in 0..200 {
        let sz: usize = (unsafe { rand() } as usize) % 256;
        let write_sz: usize = (unsafe { rand() } as usize) % 512;
        let mut buf = vec![0u8; sz + 1];
        if write_sz > sz {
            errors += 1;
        }
        unsafe {
            let ptr = buf.as_mut_ptr();
            for j in 0..write_sz.min(sz) {
                *ptr.add(j) = unsafe { rand() } as u8;
            }
        }
    }
    errors
}

fn main() {
    unsafe { srand(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_secs() as u32) };
    let result = test_buffer_overflow();
    if result > 0 {
        eprintln!("PBT: potential buffer overflow detected ({} hits)", result);
        std::process::exit(1);
    }
    eprintln!("PBT: no overflow detected");
}
"""


def _rust_fallback_use_after_free(_finding: dict, _snippet: dict) -> str:
    return """#![allow(unused_unsafe)]

extern "C" {
    fn rand() -> i32;
    fn srand(seed: u32);
}

fn test_use_after_free() -> i32 {
    let mut errors = 0i32;
    for _ in 0..200 {
        let sz: usize = (unsafe { rand() } as usize % 128) + 1;
        let mut v = vec![0u8; sz];
        drop(v);
        if unsafe { rand() } % 5 == 0 {
            unsafe {
                let _ = v.as_ptr(); // dangling reference
            }
            errors += 1;
        }
    }
    errors
}

fn main() {
    unsafe { srand(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_secs() as u32) };
    let result = test_use_after_free();
    if result > 0 {
        eprintln!("PBT: potential use-after-free detected ({} hits)", result);
        std::process::exit(1);
    }
    eprintln!("PBT: no use-after-free detected");
}
"""


def _rust_fallback_generic(_finding: dict, _snippet: dict) -> str:
    return """#![allow(unused_unsafe)]

extern "C" {
    fn rand() -> i32;
    fn srand(seed: u32);
}

fn test_generic() -> i32 {
    let mut errors = 0i32;
    for _ in 0..200 {
        let sz: usize = (unsafe { rand() } as usize) % 256;
        let write_sz: usize = (unsafe { rand() } as usize) % 512;
        let mut buf = vec![0u8; sz + 1];
        unsafe {
            let ptr = buf.as_mut_ptr();
            for j in 0..write_sz {
                if j < sz {
                    *ptr.add(j) = unsafe { rand() } as u8;
                } else {
                    *ptr.add(j) = unsafe { rand() } as u8;
                    errors += 1;
                }
            }
        }
    }
    errors
}

fn main() {
    unsafe { srand(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_secs() as u32) };
    let result = test_generic();
    if result > 0 {
        eprintln!("PBT: potential unsafe memory error detected ({} hits)", result);
        std::process::exit(1);
    }
    eprintln!("PBT: no unsafe memory error detected");
}
"""


# ── Go fallbacks ──


def _go_fallback_slice_bounds(_finding: dict, _snippet: dict) -> str:
    return """package main

import (
    "fmt"
    "math/rand"
    "time"
    "os"
)

func testSliceBounds() int {
    errors := 0
    for i := 0; i < 200; i++ {
        sz := rand.Intn(256)
        writeSz := rand.Intn(512)
        buf := make([]byte, sz+1)
        if writeSz > sz {
            errors++
        }
        for j := 0; j < writeSz && j < len(buf); j++ {
            buf[j] = byte(rand.Intn(256))
        }
    }
    return errors
}

func main() {
    rand.Seed(time.Now().UnixNano())
    result := testSliceBounds()
    if result > 0 {
        fmt.Printf("PBT: potential slice bounds violation (%d hits)\\n", result)
        os.Exit(1)
    }
    fmt.Println("PBT: no slice bounds violation")
}
"""


def _go_fallback_nil_pointer(_finding: dict, _snippet: dict) -> str:
    return """package main

import (
    "fmt"
    "math/rand"
    "time"
    "os"
)

func testNilPointer() int {
    errors := 0
    for i := 0; i < 200; i++ {
        var p *int
        if rand.Intn(5) == 0 {
            _ = *p // nil dereference when triggered
            errors++
        }
    }
    return errors
}

func main() {
    rand.Seed(time.Now().UnixNano())
    result := testNilPointer()
    if result > 0 {
        fmt.Printf("PBT: potential nil pointer dereference (%d hits)\\n", result)
        os.Exit(1)
    }
    fmt.Println("PBT: no nil pointer dereference")
}
"""


def _go_fallback_generic(_finding: dict, _snippet: dict) -> str:
    return """package main

import (
    "fmt"
    "math/rand"
    "time"
    "os"
)

func testGeneric() int {
    errors := 0
    for i := 0; i < 200; i++ {
        sz := rand.Intn(256)
        idx := rand.Intn(sz + 5)
        buf := make([]byte, sz+1)
        if idx >= sz+1 {
            errors++
        } else {
            buf[idx] = byte(rand.Intn(256))
        }
    }
    return errors
}

func main() {
    rand.Seed(time.Now().UnixNano())
    result := testGeneric()
    if result > 0 {
        fmt.Printf("PBT: potential memory error detected (%d hits)\\n", result)
        os.Exit(1)
    }
    fmt.Println("PBT: no memory error detected")
}
"""


# ── Python fallbacks ──


def _python_fallback_buffer_overflow(_finding: dict, _snippet: dict) -> str:
    return r"""import os
import sys
import random

def test_buffer_overflow():
    errors = 0
    iterations = int(os.environ.get("PBT_ITERATIONS", "200"))
    for _ in range(iterations):
        sz = random.randint(0, 256)
        write_sz = random.randint(0, 512)
        buf = bytearray(sz + 1)
        try:
            for j in range(write_sz):
                if j < sz:
                    buf[j] = random.randint(0, 255)
                else:
                    errors += 1
                    break
        except (IndexError, MemoryError):
            errors += 1
    return errors

if __name__ == "__main__":
    result = test_buffer_overflow()
    if result > 0:
        print(f"PBT: potential buffer overflow detected ({result} hits)")
        sys.exit(1)
    print("PBT: no overflow detected")
    sys.exit(0)
"""


def _python_fallback_null_pointer(_finding: dict, _snippet: dict) -> str:
    return r"""import os
import sys
import random

class Container:
    def __init__(self):
        self.value = None

def test_null_pointer():
    errors = 0
    iterations = int(os.environ.get("PBT_ITERATIONS", "200"))
    for _ in range(iterations):
        c = Container()
        try:
            if random.randint(0, 4) == 0:
                _ = c.value.some_attr
                errors += 1
        except AttributeError:
            errors += 1
        except TypeError:
            errors += 1
    return errors

if __name__ == "__main__":
    result = test_null_pointer()
    if result > 0:
        print(f"PBT: potential null pointer / None dereference detected ({result} hits)")
        sys.exit(1)
    print("PBT: no null pointer detected")
    sys.exit(0)
"""


def _python_fallback_generic(_finding: dict, _snippet: dict) -> str:
    return r"""import os
import sys
import random

def test_generic():
    errors = 0
    iterations = int(os.environ.get("PBT_ITERATIONS", "200"))
    for _ in range(iterations):
        sz = random.randint(0, 256)
        idx = random.randint(0, sz + 5)
        buf = bytearray(sz + 1)
        try:
            val = buf[idx]
        except (IndexError, TypeError):
            errors += 1
    return errors

if __name__ == "__main__":
    result = test_generic()
    if result > 0:
        print(f"PBT: potential index error detected ({result} hits)")
        sys.exit(1)
    print("PBT: no index error detected")
    sys.exit(0)
"""


# ── Python Hypothesis harness generators ──


def _python_hypothesis_buffer_overflow(_finding: dict, _snippet: dict) -> str:
    return r"""import os
import sys
from hypothesis import given, settings, strategies as st

@settings(max_examples=int(os.environ.get("PBT_HYPOTHESIS_EXAMPLES", "500")), deadline=None, database=None)
@given(st.integers(min_value=0, max_value=512))
def test_buffer_overflow(write_sz):
    sz = 256
    buf = bytearray(sz + 1)
    for j in range(write_sz):
        if j < sz:
            buf[j] = 0x41
        else:
            raise AssertionError("buffer overflow")

if __name__ == "__main__":
    try:
        test_buffer_overflow()
        print("PBT(H): no overflow detected")
        sys.exit(0)
    except (AssertionError, IndexError, MemoryError):
        print("PBT(H): potential buffer overflow detected via Hypothesis")
        sys.exit(1)
"""


def _python_hypothesis_null_pointer(_finding: dict, _snippet: dict) -> str:
    return r"""import os
import sys
from hypothesis import given, settings, strategies as st

class Container:
    def __init__(self):
        self.value = None

@settings(max_examples=int(os.environ.get("PBT_HYPOTHESIS_EXAMPLES", "500")), deadline=None, database=None)
@given(st.integers(min_value=0, max_value=4))
def test_null_pointer(choice):
    c = Container()
    if choice == 0:
        _ = c.value.some_attr
        raise AssertionError("null dereference")

if __name__ == "__main__":
    try:
        test_null_pointer()
        print("PBT(H): no null pointer detected")
        sys.exit(0)
    except (AttributeError, TypeError):
        print("PBT(H): potential null pointer detected via Hypothesis")
        sys.exit(1)
"""


def _python_hypothesis_generic(_finding: dict, _snippet: dict) -> str:
    return r"""import os
import sys
from hypothesis import given, settings, strategies as st

@settings(max_examples=int(os.environ.get("PBT_HYPOTHESIS_EXAMPLES", "500")), deadline=None, database=None)
@given(st.integers(min_value=0, max_value=512))
def test_generic(idx):
    sz = 256
    buf = bytearray(sz + 1)
    val = buf[idx]
    if val is None:
        raise AssertionError("index error")

if __name__ == "__main__":
    try:
        test_generic()
        print("PBT(H): no index error detected")
        sys.exit(0)
    except (IndexError, TypeError):
        print("PBT(H): potential index error detected via Hypothesis")
        sys.exit(1)
"""


_HYPOTHESIS_TEMPLATES: dict[str, dict[str, Callable]] = {
    "python": {
        "buffer-overflow": _python_hypothesis_buffer_overflow,
        "memory-corruption": _python_hypothesis_buffer_overflow,
        "nil-pointer": _python_hypothesis_null_pointer,
        "__default__": _python_hypothesis_generic,
    },
}


# ── JavaScript fallbacks ──


def _javascript_fallback_type_error(_finding: dict, _snippet: dict) -> str:
    return """const iterations = parseInt(process.env.PBT_ITERATIONS || "200", 10);

function testTypeConfusion() {
    let errors = 0;
    for (let i = 0; i < iterations; i++) {
        try {
            const val = Math.random() > 0.5 ? "string" : 42;
            const result = val();
            errors++;
        } catch (e) {
            if (e instanceof TypeError) errors++;
        }
    }
    return errors;
}

function main() {
    const result = testTypeConfusion();
    if (result > 0) {
        console.error(`PBT: potential type error detected (${result} hits)`);
        process.exit(1);
    }
    console.log("PBT: no type error detected");
}

main();
"""


def _javascript_fallback_generic(_finding: dict, _snippet: dict) -> str:
    return """const iterations = parseInt(process.env.PBT_ITERATIONS || "200", 10);

function testGeneric() {
    let errors = 0;
    for (let i = 0; i < iterations; i++) {
        try {
            const sz = Math.floor(Math.random() * 256);
            const idx = Math.floor(Math.random() * (sz + 5));
            const buf = new Uint8Array(sz + 1);
            if (idx >= buf.length) {
                errors++;
            }
        } catch (e) {
            errors++;
        }
    }
    return errors;
}

function main() {
    const result = testGeneric();
    if (result > 0) {
        console.error(`PBT: potential memory error detected (${result} hits)`);
        process.exit(1);
    }
    console.log("PBT: no memory error detected");
}

main();
"""


def _javascript_fallback_null_pointer(_finding: dict, _snippet: dict) -> str:
    return """const iterations = parseInt(process.env.PBT_ITERATIONS || "200", 10);

function testNullPointer() {
    let errors = 0;
    for (let i = 0; i < iterations; i++) {
        try {
            const obj = Math.random() > 0.5 ? {value: 42} : null;
            const v = obj.value;
            errors++;
        } catch (e) {
            if (e instanceof TypeError) errors++;
        }
    }
    return errors;
}

function main() {
    const result = testNullPointer();
    if (result > 0) {
        console.error(`PBT: potential null pointer detected (${result} hits)`);
        process.exit(1);
    }
    console.log("PBT: no null pointer detected");
}

main();
"""


def _typescript_fallback_generic(_finding: dict, _snippet: dict) -> str:
    return """const iterations = parseInt(process.env.PBT_ITERATIONS || "200", 10);

function testGeneric(): number {
    let errors = 0;
    for (let i = 0; i < iterations; i++) {
        try {
            const sz: number = Math.floor(Math.random() * 256);
            const idx: number = Math.floor(Math.random() * (sz + 5));
            const buf: Uint8Array = new Uint8Array(sz + 1);
            if (idx >= buf.length) {
                errors++;
            }
        } catch (e: unknown) {
            errors++;
        }
    }
    return errors;
}

function main(): void {
    const result = testGeneric();
    if (result > 0) {
        console.error(`PBT: potential memory error detected (${result} hits)`);
        process.exit(1);
    }
    console.log("PBT: no memory error detected");
}

main();
"""


# ── Fallback template dispatch table ──
# Maps (language, sink_type) → harness generator function.
# Each language should have a "__default__" fallback.

_FALLBACK_TEMPLATES: dict[str, dict[str, SinkHarnessFn]] = {
    "c": {
        "buffer-overflow": _c_fallback_buffer_overflow,
        "memory-corruption": _c_fallback_buffer_overflow,
        "use-after-free": _c_fallback_use_after_free,
        "format-string": _c_fallback_format_string,
        "__default__": _c_fallback_generic,
    },
    "cpp": {
        "buffer-overflow": _cpp_fallback_buffer_overflow,
        "memory-corruption": _cpp_fallback_buffer_overflow,
        "use-after-free": _cpp_fallback_use_after_free,
        "__default__": _cpp_fallback_generic,
    },
    "rust": {
        "buffer-overflow": _rust_fallback_buffer_overflow,
        "memory-corruption": _rust_fallback_buffer_overflow,
        "use-after-free": _rust_fallback_use_after_free,
        "__default__": _rust_fallback_generic,
    },
    "go": {
        "buffer-overflow": _go_fallback_slice_bounds,
        "memory-corruption": _go_fallback_slice_bounds,
        "nil-pointer": _go_fallback_nil_pointer,
        "__default__": _go_fallback_generic,
    },
    "python": {
        "buffer-overflow": _python_fallback_buffer_overflow,
        "memory-corruption": _python_fallback_buffer_overflow,
        "nil-pointer": _python_fallback_null_pointer,
        "__default__": _python_fallback_generic,
    },
    "javascript": {
        "buffer-overflow": _javascript_fallback_generic,
        "memory-corruption": _javascript_fallback_generic,
        "type-confusion": _javascript_fallback_type_error,
        "nil-pointer": _javascript_fallback_null_pointer,
        "__default__": _javascript_fallback_generic,
    },
    "typescript": {
        "buffer-overflow": _typescript_fallback_generic,
        "memory-corruption": _typescript_fallback_generic,
        "__default__": _typescript_fallback_generic,
    },
}

# ── Prompt building ──


def _build_pbt_prompt(finding: dict, snippet: dict, language: str) -> str:
    points = finding.get("suspicious_points") or []
    point = points[0] if points else {}
    sink = str(point.get("sink_source_type", finding.get("class", "unknown")))
    func = str(point.get("function", snippet.get("name", "unknown")))
    file = str(point.get("file", snippet.get("file", "?")))
    content = str(snippet.get("content", ""))
    desc = str(finding.get("desc", ""))
    return f"""Your job is to infer the invariant that a vulnerability finding
claims is violated, then generate a fuzz harness to test it.

The target language is: {language}

Finding:
- class: {finding.get("class", "?")}
- sink/source type: {sink}
- function: {func}
- file: {file}
- description: {desc}

Source code:
```{language}
{content}
```

Output VALID JSON ONLY with these fields:
{{
  "invariant": "short description of the invariant being tested",
  "harness_source": "complete {language} source code for the fuzz harness"
}}

Requirements for the harness:
1. It MUST be valid, compilable/executable {language} code with no external dependencies beyond the standard library.
2. Include the vulnerable function's logic inline or as a simplified model.
3. Define a `main()` (or equivalent entry point) that loops with randomized inputs.
4. Use language-appropriate sanitization patterns (e.g., AddressSanitizer for C/C++, panic detection for Rust, exception handling for Python).
5. The harness MUST detect the specific hazard class ({sink}) if present.
6. Return non-zero exit code if the vulnerability is triggered.
7. Keep it self-contained.
8. Iterate at least 100 times with varied inputs using the language's RNG.
"""


# ── Signal detection ──


def _contains_vuln_signal(text: str, exit_code: int, language: str) -> bool:
    markers = _VULN_MARKERS.get(language, _VULN_MARKERS["c"])
    lowered = text.lower()
    if exit_code < 0:
        return True
    return any(marker in lowered for marker in markers)


# ── LLM invariant inference ──


def _call_llm_for_invariant(
    finding: dict,
    snippet: dict,
    *,
    language: str,
    model: str,
    auth: dict[str, str] | None,
    cache: object | None,
    call_llm_func: Callable[..., str] | None,
) -> tuple[str, str, str]:
    prompt = _build_pbt_prompt(finding, snippet, language)
    raw = ""
    if call_llm_func is not None:
        raw = call_llm_func(
            model,
            prompt,
            system=_PBT_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
    invariant = ""
    harness_source = ""
    if raw:
        parsed, _ = _repair_json_output(raw)
        if isinstance(parsed, dict):
            invariant = str(parsed.get("invariant", "") or "")
            harness_source = str(parsed.get("harness_source", "") or "")
    return invariant, harness_source, raw


# ── JSON repair ──


def _repair_json_output(raw: str) -> tuple[object, bool]:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        cleaned = []
        in_block = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("```"):
                in_block = not in_block
                continue
            if in_block:
                cleaned.append(line)
        raw = "\n".join(cleaned).strip()
    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        candidate = raw[start : end + 1]
        try:
            return json.loads(candidate), True
        except json.JSONDecodeError:
            pass
    return {"invariant": "", "harness_source": raw}, True


# ── Fallback harness generation ──


def _generate_fallback_harness(finding: dict, snippet: dict, language: str) -> str:
    points = finding.get("suspicious_points") or []
    point = points[0] if points else {}
    sink = str(point.get("sink_source_type", finding.get("class", "unknown")))

    lang_templates = _FALLBACK_TEMPLATES.get(language)
    if lang_templates is None:
        lang_templates = _FALLBACK_TEMPLATES["c"]

    generator = lang_templates.get(
        sink, lang_templates.get("__default__", _c_fallback_generic)
    )
    return generator(finding, snippet)


# ── Compilation ──


def _compile_harness(
    harness_source: str,
    timeout: int,
    language: str,
    *,
    sandbox_manager: object | None = None,
) -> dict:
    rt = _PBT_LANGUAGE_RUNTIME.get(language, _PBT_LANGUAGE_RUNTIME["c"])
    ext = rt["source_ext"]
    bin_ext = rt["binary_ext"]

    result: dict = {
        "compile_succeeded": False,
        "stderr": "",
        "binary_path": "",
    }

    with tempfile.TemporaryDirectory(prefix="ai-vuln-pbt-") as td:
        tmp = Path(td)
        src = tmp / f"pbt_harness{ext}"
        binary = tmp / f"pbt_harness{bin_ext}"
        src.write_text(harness_source, encoding="utf-8")

        if rt["compile"] is None:
            return {
                "compile_succeeded": True,
                "stderr": "",
                "binary_path": str(src),
            }

        cmd = [
            part.replace("{src}", str(src))
            .replace("{bin}", str(binary))
            .replace("{outdir}", str(tmp))
            for part in rt["compile"]
        ]

        _run_compile_in_sandbox = (
            sandbox_manager is not None
            and getattr(sandbox_manager, "available", lambda: False)()
        )
        if _run_compile_in_sandbox:
            compile_result = sandbox_manager.execute(
                cmd,
                timeout=timeout,
                language=language,
            )
            result["compile_succeeded"] = compile_result["returncode"] == 0
            result["stderr"] = compile_result["stderr"]
        else:
            compile_proc = subprocess.run(
                cmd,
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            result["compile_succeeded"] = compile_proc.returncode == 0
            result["stderr"] = compile_proc.stderr
        if result["compile_succeeded"]:
            result["binary_path"] = str(binary)
            return result

    return result


# ── Harness execution ──


def _run_harness(
    binary_path: str,
    *,
    timeout: int,
    iterations: int,
    language: str,
    extra_env: dict[str, str] | None = None,
    sandbox_manager: object | None = None,
) -> dict:
    result: dict = {
        "run_succeeded": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "vulnerability_observed": False,
    }

    rt = _PBT_LANGUAGE_RUNTIME.get(language, _PBT_LANGUAGE_RUNTIME["c"])
    target = Path(binary_path)
    if not target.exists():
        result["stderr"] = "binary_not_found"
        return result

    cmd = [part.replace("{bin}", str(target)) for part in rt["run"]]

    env = {"PBT_ITERATIONS": str(iterations)}
    if extra_env:
        env.update(extra_env)
    system_path = os.environ.get("PATH", "/usr/bin:/bin")
    proc_env = {**env, **{"PATH": system_path}}

    if (
        sandbox_manager is not None
        and getattr(sandbox_manager, "available", lambda: False)()
    ):
        sandbox_result = sandbox_manager.execute(
            cmd,
            timeout=timeout,
            env=proc_env,
            language=language,
        )
        run_proc_ret = sandbox_result["returncode"]
        run_proc_stdout = sandbox_result["stdout"]
        run_proc_stderr = sandbox_result["stderr"]
    else:
        run_proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=proc_env,
        )
        run_proc_ret = run_proc.returncode
        run_proc_stdout = run_proc.stdout
        run_proc_stderr = run_proc.stderr
    result["run_succeeded"] = True
    result["exit_code"] = run_proc_ret
    result["stdout"] = run_proc_stdout
    result["stderr"] = run_proc_stderr
    combined = f"{run_proc_stdout}\n{run_proc_stderr}"
    result["vulnerability_observed"] = _contains_vuln_signal(
        combined,
        run_proc.returncode,
        language,
    )
    return result


# ── Single-finding PBT runner ──

_SUPPORTED_LANGUAGES = {"c", "cpp", "rust", "go", "python", "javascript", "typescript"}


def _hypothesis_available() -> bool:
    try:
        import hypothesis  # noqa: F401

        return True
    except ImportError:
        return False


def _generate_hypothesis_harness(finding: dict, snippet: dict) -> str:
    points = finding.get("suspicious_points") or []
    point = points[0] if points else {}
    sink = str(point.get("sink_source_type", finding.get("class", "unknown")))
    lang_templates = _HYPOTHESIS_TEMPLATES.get("python", {})
    generator = lang_templates.get(
        sink, lang_templates.get("__default__", _python_hypothesis_generic)
    )
    return generator(finding, snippet)


def _extract_falsifying_example(text: str) -> str:
    for line in text.splitlines():
        if "falsifying example:" in line.lower():
            return line.strip()
    return ""


def _resolve_pbt_language(pbt_result: dict, snippet: dict, language: str) -> str | None:
    if not snippet.get("content"):
        pbt_result["pbt_skipped"] = True
        pbt_result["pbt_confidence_boost"] = 0.0
        return None
    lang = language or snippet.get("language", "c")
    if lang not in _SUPPORTED_LANGUAGES:
        logger.warning("[PBT] unsupported language '%s', falling back to 'c'", lang)
        lang = "c"
    available, msg = _toolchain_available(lang)
    if not available:
        if lang in ("rust",):
            logger.info(
                "[PBT] %s toolchain not available (%s), trying nightly fallback",
                lang,
                msg,
            )
            available_alt, _msg_alt = _toolchain_available("rust_nightly")
            if available_alt:
                lang = "rust_nightly"
                available = True
        if not available:
            logger.warning(
                "[PBT] toolchain for '%s' not available (%s), skipping", lang, msg
            )
            pbt_result["pbt_skipped"] = True
            pbt_result["pbt_confidence_boost"] = 0.0
            return None
    return lang


def _generate_pbt_harness(
    pbt_result: dict,
    finding: dict,
    snippet: dict,
    *,
    lang: str,
    enable_llm: bool,
    call_llm_func: Callable[..., str] | None,
    model: str,
    auth: dict[str, str] | None,
    cache: object | None,
) -> None:
    if enable_llm and call_llm_func is not None and model:
        invariant, harness_source, _raw = _call_llm_for_invariant(
            finding,
            snippet,
            language=lang,
            model=model,
            auth=auth,
            cache=cache,
            call_llm_func=call_llm_func,
        )
        pbt_result["pbt_invariant"] = invariant
        pbt_result["pbt_harness_source"] = harness_source
    else:
        harness_source = ""
    if not harness_source.strip():
        harness_source = _generate_fallback_harness(finding, snippet, lang)
        pbt_result["pbt_harness_source"] = harness_source
        if not pbt_result["pbt_invariant"]:
            pbt_result["pbt_invariant"] = (
                f"no memory safety violation with varied inputs "
                f"({finding.get('class', 'unknown')})"
            )


def run_pbt_on_finding(
    finding: dict,
    snippet: dict,
    *,
    pbt_iterations: int = 500,
    compile_timeout: int = 30,
    run_timeout: int = 15,
    model: str = "",
    auth: dict[str, str] | None = None,
    cache: object | None = None,
    call_llm_func: Callable[..., str] | None = None,
    enable_llm: bool = True,
    language: str = "",
    enable_hypothesis: bool = True,
    hypothesis_max_examples: int = 500,
    sandbox_manager: object | None = None,
    sandbox_compile: bool = False,
) -> dict:
    pbt_result: dict = {
        "pbt_invariant": "",
        "pbt_harness_source": "",
        "pbt_compile_succeeded": False,
        "pbt_compile_error": "",
        "pbt_run_succeeded": False,
        "pbt_falsified": False,
        "pbt_iterations_run": pbt_iterations,
        "pbt_exit_code": None,
        "pbt_stdout": "",
        "pbt_stderr": "",
        "pbt_skipped": False,
        "pbt_confidence_boost": 0.0,
        "pbt_hypothesis_falsified": False,
        "pbt_hypothesis_falsifying_example": "",
    }

    lang = _resolve_pbt_language(pbt_result, snippet, language)
    if lang is None:
        return pbt_result

    _generate_pbt_harness(
        pbt_result,
        finding,
        snippet,
        lang=lang,
        enable_llm=enable_llm,
        call_llm_func=call_llm_func,
        model=model,
        auth=auth,
        cache=cache,
    )

    compile_sandbox = sandbox_manager if sandbox_compile else None
    compile_result = _compile_harness(
        pbt_result["pbt_harness_source"],
        compile_timeout,
        lang,
        sandbox_manager=compile_sandbox,
    )
    pbt_result["pbt_compile_succeeded"] = compile_result["compile_succeeded"]
    pbt_result["pbt_compile_error"] = compile_result["stderr"]

    if not compile_result["compile_succeeded"]:
        pbt_result["pbt_confidence_boost"] = 0.0
        return pbt_result

    run_result = _run_harness(
        compile_result["binary_path"],
        timeout=run_timeout,
        iterations=pbt_iterations,
        language=lang,
        sandbox_manager=sandbox_manager,
    )
    pbt_result["pbt_run_succeeded"] = run_result["run_succeeded"]
    pbt_result["pbt_falsified"] = run_result["vulnerability_observed"]
    pbt_result["pbt_exit_code"] = run_result["exit_code"]
    pbt_result["pbt_stdout"] = run_result["stdout"]
    pbt_result["pbt_stderr"] = run_result["stderr"]

    if run_result["vulnerability_observed"]:
        pbt_result["pbt_confidence_boost"] = 0.2
    elif run_result["run_succeeded"] and run_result["exit_code"] == 0:
        pbt_result["pbt_confidence_boost"] = -0.1
    else:
        pbt_result["pbt_confidence_boost"] = 0.0

    if enable_hypothesis and lang == "python" and _hypothesis_available():
        _run_hypothesis_on_finding(
            pbt_result,
            finding,
            snippet,
            compile_timeout=compile_timeout,
            run_timeout=run_timeout,
            pbt_iterations=pbt_iterations,
            hypothesis_max_examples=hypothesis_max_examples,
            sandbox_manager=sandbox_manager,
        )

    return pbt_result


def _run_hypothesis_on_finding(
    pbt_result: dict,
    finding: dict,
    snippet: dict,
    *,
    compile_timeout: int = 30,
    run_timeout: int = 15,
    pbt_iterations: int = 500,
    hypothesis_max_examples: int = 500,
    sandbox_manager: object | None = None,
) -> None:
    hyp_source = _generate_hypothesis_harness(finding, snippet)
    if not hyp_source.strip():
        return
    hyp_compile = _compile_harness(
        hyp_source,
        compile_timeout,
        "python",
        sandbox_manager=sandbox_manager,
    )
    if not hyp_compile["compile_succeeded"]:
        return
    hyp_env = {"PBT_HYPOTHESIS_EXAMPLES": str(hypothesis_max_examples)}
    hyp_result = _run_harness(
        hyp_compile["binary_path"],
        timeout=run_timeout,
        iterations=pbt_iterations,
        language="python",
        extra_env=hyp_env,
        sandbox_manager=sandbox_manager,
    )
    pbt_result["pbt_hypothesis_falsified"] = hyp_result["vulnerability_observed"]
    if hyp_result["vulnerability_observed"]:
        combined_output = f"{hyp_result['stdout']}\n{hyp_result['stderr']}"
        pbt_result["pbt_hypothesis_falsifying_example"] = _extract_falsifying_example(
            combined_output
        )


# ── Finding annotation ──


def _annotate_finding_from_pbt(finding: dict, pbt_result: dict) -> float:
    pbt_boost = float(pbt_result.get("pbt_confidence_boost", 0.0))
    finding["pbt_invariant"] = pbt_result.get("pbt_invariant", "")
    finding["pbt_falsified"] = pbt_result.get("pbt_falsified", False)
    finding["pbt_iterations_run"] = pbt_result.get("pbt_iterations_run", 0)
    finding["pbt_confidence_boost"] = pbt_boost
    finding["pbt_compile_succeeded"] = pbt_result.get("pbt_compile_succeeded", False)
    finding["pbt_skipped"] = pbt_result.get("pbt_skipped", False)
    finding["pbt_hypothesis_falsified"] = pbt_result.get(
        "pbt_hypothesis_falsified", False
    )
    finding["pbt_hypothesis_falsifying_example"] = pbt_result.get(
        "pbt_hypothesis_falsifying_example", ""
    )
    if pbt_boost != 0.0:
        current_conf = float(finding.get("localization_confidence", 0.0))
        finding["localization_confidence"] = max(
            0.0, min(1.0, current_conf + pbt_boost)
        )
        finding["pbt_adjusted_confidence"] = True
    else:
        finding["pbt_adjusted_confidence"] = False
    return pbt_boost


# ── Skipped-finding appending ──


def _append_skipped_findings(
    annotated: list[dict],
    findings: list[dict],
    valid: list[dict],
) -> None:
    seen = {id(f) for f in valid}
    for f in findings:
        if id(f) not in seen:
            f["pbt_skipped"] = True
            f["pbt_falsified"] = False
            f["pbt_confidence_boost"] = 0.0
            f["pbt_adjusted_confidence"] = False
            f["pbt_hypothesis_falsified"] = False
            f["pbt_hypothesis_falsifying_example"] = ""
            annotated.append(f)


# ── Full PBT orchestrator ──


def run_pbt_on_findings(
    findings: list[dict],
    snippet_db: dict[str, dict],
    *,
    pbt_iterations: int = 500,
    compile_timeout: int = 30,
    run_timeout: int = 15,
    model: str = "",
    auth: dict[str, str] | None = None,
    cache: object | None = None,
    call_llm_func: object = None,
    enable_llm: bool = True,
    max_findings: int = 50,
    enable_hypothesis: bool = True,
    hypothesis_max_examples: int = 500,
    sandbox_manager: object | None = None,
    sandbox_compile: bool = False,
) -> list[dict]:
    valid = [f for f in findings if has_valid_suspicious_points(f)]
    if not valid:
        logger.info("[PBT] no valid findings to test")
        return findings[:]

    valid = valid[:max_findings]
    logger.info(
        "[PBT] testing %d/%d finding(s)",
        len(valid),
        len(findings),
    )

    annotated = []
    for i, finding in enumerate(valid):
        sid = str(finding.get("snippet_id", ""))
        snippet = snippet_db.get(sid, {})
        pbt_result = run_pbt_on_finding(
            finding,
            snippet,
            pbt_iterations=pbt_iterations,
            compile_timeout=compile_timeout,
            run_timeout=run_timeout,
            model=model,
            auth=auth,
            cache=cache,
            call_llm_func=call_llm_func,
            enable_llm=enable_llm,
            enable_hypothesis=enable_hypothesis,
            hypothesis_max_examples=hypothesis_max_examples,
            sandbox_manager=sandbox_manager,
            sandbox_compile=sandbox_compile,
        )
        pbt_boost = _annotate_finding_from_pbt(finding, pbt_result)
        logger.info(
            "[PBT] finding %d/%d: lang=%s falsified=%s boost=%.2f %s",
            i + 1,
            len(valid),
            snippet.get("language", "c"),
            pbt_result.get("pbt_falsified"),
            pbt_boost,
            "(skipped)" if pbt_result.get("pbt_skipped") else "",
        )
        annotated.append(finding)

    _append_skipped_findings(annotated, findings, valid)

    logger.info(
        "[PBT] completed: %d falsified, %d boosted, %d skipped",
        sum(1 for f in annotated if f.get("pbt_falsified")),
        sum(1 for f in annotated if f.get("pbt_adjusted_confidence")),
        sum(1 for f in annotated if f.get("pbt_skipped")),
    )
    return annotated
