"""Per-target context templates — target-specific guidance for different codebase types.

Different codebase types benefit from different hunting strategies. A kernel
module has different attack surfaces than a web API. These templates provide
target-specific guidance injected into HUNT prompts to focus effort on the
most productive bug classes for each target type.

Templates are selected automatically based on recon output, or can be
specified manually via --target-template.
"""

from __future__ import annotations

TEMPLATES: dict[str, dict] = {
    "c-cpp-parser": {
        "name": "C/C++ Parser / Decoder",
        "description": "Native parsers, decoders, codec families, media processing",
        "focus_classes": [
            "buffer-overflow",
            "integer-overflow",
            "use-after-free",
            "format-string",
            "out-of-bounds-read",
            "double-free",
            "uninitialized-memory",
        ],
        "hunt_guidance": (
            "Focus on: length-field validation, size calculations before allocation, "
            "loop bounds, pointer arithmetic, struct packing, alignment, endianness. "
            "Check every size_t → int cast. Trace every malloc/calloc size through "
            "arithmetic. Verify every memcpy/memmove length against buffer bounds. "
            "Look for integer overflow in size calculations (a * b where a,b are "
            "user-controlled). Check for signed/unsigned confusion in comparisons."
        ),
        "sanitizers": "ASan + UBSan + MSan",
        "build_flags": "-fsanitize=address,undefined -fno-omit-frame-pointer -g",
    },
    "web-api": {
        "name": "Web API / HTTP Service",
        "description": "REST/GraphQL APIs, web frameworks, HTTP handlers",
        "focus_classes": [
            "injection",
            "path-traversal",
            "auth-bypass",
            "idor",
            "ssrf",
            "xss",
            "csrf",
            "deserialization",
        ],
        "hunt_guidance": (
            "Focus on: input validation at entry points, auth middleware coverage, "
            "IDOR via direct object references, SSRF via user-controlled URLs, "
            "template injection, deserialization of untrusted data. Check every "
            "endpoint for auth + authz. Trace user input through middleware to "
            "database queries. Look for endpoints that bypass auth checks. "
            "Check for mass assignment / parameter pollution."
        ),
        "sanitizers": "N/A (dynamic testing via HTTP)",
        "build_flags": "",
    },
    "kernel-module": {
        "name": "Linux Kernel Module",
        "description": "Kernel modules, drivers, syscalls, ioctls",
        "focus_classes": [
            "buffer-overflow",
            "use-after-free",
            "race-condition",
            "privilege-escalation",
            "null-pointer-deref",
            "double-free",
            "out-of-bounds",
        ],
        "hunt_guidance": (
            "Focus on: copy_from_user/copy_to_user validation, ioctl command parsing, "
            "race conditions between file operations, reference counting (get/put), "
            "lock ordering, NULL checks after container_of. Check for missing "
            "access_ok() before copy_to_user. Verify copy_from_user returns are "
            "checked. Look for TOCTOU between VFS operations. Check lock ordering "
            "for ABBA deadlocks."
        ),
        "sanitizers": "KASAN + KMSAN + KCSAN",
        "build_flags": "-fsanitize=kernel-address",
    },
    "crypto-library": {
        "name": "Cryptographic Library",
        "description": "Crypto primitives, TLS, key management, signing",
        "focus_classes": [
            "timing-side-channel",
            "key-reuse",
            "padding-oracle",
            "weak-randomness",
            "constant-time-violation",
            "side-channel",
        ],
        "hunt_guidance": (
            "Focus on: constant-time comparisons (verify every secrets.compare, "
            "crypto_memcmp), nonce/IV reuse, key derivation weakness, padding "
            "validation, timing side channels in signature verification. Check "
            "every branch on secret data for timing leaks. Verify memcmp is "
            "replaced with constant-time comparison. Look for early-return on "
            "MAC verification. Check random number generation quality."
        ),
        "sanitizers": "Valgrind (constant-time analysis)",
        "build_flags": "",
    },
    "embedded-firmware": {
        "name": "Embedded Firmware / IoT",
        "description": "Bare-metal, RTOS, MCU firmware, hardware interfaces",
        "focus_classes": [
            "buffer-overflow",
            "format-string",
            "command-injection",
            "hardcoded-credentials",
            "insecure-update",
            "side-channel",
        ],
        "hunt_guidance": (
            "Focus on: UART/SPI/I2C input validation, OTA update integrity, "
            "hardcoded credentials and backdoor commands, format string in debug "
            "interfaces, buffer overflow in packet parsing. Check every printf-like "
            "call for user-controlled format strings. Verify OTA signatures are "
            "checked. Look for debug interfaces left enabled in production. "
            "Check for JTAG/UART access control."
        ),
        "sanitizers": "N/A (limited instrumentation)",
        "build_flags": "",
    },
    "binary-only": {
        "name": "Binary-Only / Closed Source",
        "description": "Reverse engineering targets, proprietary binaries",
        "focus_classes": [
            "buffer-overflow",
            "use-after-free",
            "type-confusion",
            "heap-spray",
            "control-flow-hijack",
        ],
        "hunt_guidance": (
            "Focus on: input parsing routines, protocol handlers, file format "
            "parsers. Trace input from network/file to dangerous sinks. Look for "
            "custom allocators, vtable usage, exception handlers. Check for "
            "weak ASLR/DEP/CFG. Identify ROP gadget availability. Look for "
            "use-after-free in object lifecycle management."
        ),
        "sanitizers": "Dynamic analysis (Frida, QEMU)",
        "build_flags": "",
    },
    "data-pipeline": {
        "name": "Data Pipeline / ETL",
        "description": "Data processing, serialization, transforms, batch jobs",
        "focus_classes": [
            "deserialization",
            "injection",
            "path-traversal",
            "data-poisoning",
            "resource-exhaustion",
        ],
        "hunt_guidance": (
            "Focus on: deserialization of untrusted data (pickle, yaml, json), "
            "schema validation bypass, path traversal in file operations, "
            "injection via template engines, resource exhaustion from unbounded "
            "inputs. Check every pickle.load/yaml.load for unsafe loaders. "
            "Verify schema validation is enforced. Look for path traversal "
            "in file import/export. Check for unbounded loops on malformed input."
        ),
        "sanitizers": "N/A (dynamic testing via data injection)",
        "build_flags": "",
    },
    "config-system": {
        "name": "Configuration Management",
        "description": "Config parsers, env variable handling, feature flags",
        "focus_classes": [
            "config-injection",
            "env-override",
            "path-traversal",
            "deserialization",
            "privilege-escalation",
        ],
        "hunt_guidance": (
            "Focus on: environment variable overrides of security controls, "
            "config file parsing for injection, feature flags that disable "
            "validation, default-insecure configurations, config file path "
            "traversal. Check every env var read for security impact. Verify "
            "feature flags cannot disable auth. Look for config files loaded "
            "from user-writable paths. Check for config injection via "
            "string interpolation."
        ),
        "sanitizers": "N/A",
        "build_flags": "",
    },
}


def detect_target_type(recon_tasks: list[dict], snippets: list[dict]) -> str | None:
    """Auto-detect target type from recon output and snippet metadata.

    Returns a template key or None if no match.
    """
    # Check file extensions to determine language
    extensions: dict[str, int] = {}
    for s in snippets:
        f = str(s.get("file") or "")
        for ext in (
            ".c",
            ".h",
            ".cc",
            ".cpp",
            ".rs",
            ".go",
            ".py",
            ".js",
            ".ts",
            ".java",
        ):
            if f.endswith(ext):
                extensions[ext] = extensions.get(ext, 0) + 1

    c_count = sum(extensions.get(e, 0) for e in (".c", ".h", ".cc", ".cpp"))
    total = sum(extensions.values()) or 1

    # Check domain names from recon tasks
    domains = {str(t.get("domain") or "") for t in recon_tasks}

    if c_count / total > 0.7:
        # Mostly C/C++ — check for parser/codec patterns
        parser_hints = sum(
            1
            for s in snippets
            if any(
                kw in str(s.get("file", "")).lower()
                for kw in ("parser", "decode", "codec", "lexer", "reader", "parse")
            )
        )
        if parser_hints > 5:
            return "c-cpp-parser"
        if "mem-safety" in domains and "concurrency" in domains:
            return "kernel-module"
        return "c-cpp-parser"

    if any(d.startswith(("web", "api", "http", "rest")) for d in domains):
        return "web-api"
    if any(d.startswith(("crypto",)) for d in domains):
        return "crypto-library"
    if any(d.startswith(("config", "env", "flag")) for d in domains):
        return "config-system"
    if any(d.startswith(("data", "etl", "pipeline", "serialize")) for d in domains):
        return "data-pipeline"

    return None


def get_template(target_type: str) -> dict | None:
    """Get a template by key."""
    return TEMPLATES.get(target_type)


def list_templates() -> dict[str, str]:
    """Return {key: name} for all available templates."""
    return {k: v["name"] for k, v in TEMPLATES.items()}


def inject_template_guidance(
    pack: dict,
    template: dict,
) -> dict:
    """Inject target-specific guidance into a context pack.

    Adds a ``target_guidance`` field with the template's hunt guidance,
    focus classes, and sanitizer recommendations.
    """
    pack = dict(pack)
    pack["target_guidance"] = {
        "target_type": template["name"],
        "focus_classes": template["focus_classes"],
        "hunt_guidance": template["hunt_guidance"],
        "sanitizers": template["sanitizers"],
        "build_flags": template["build_flags"],
    }
    return pack
