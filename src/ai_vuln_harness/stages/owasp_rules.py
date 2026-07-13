"""OWASP Top 10 Rule System — pre-configured audit rules mapped to OWASP categories.

Provides hunt guidance and validation rules for each OWASP Top 10 category.
Rules are injected into HUNT prompts to ensure coverage of standard web
vulnerability classes.
"""

from __future__ import annotations

OWASP_RULES: dict[str, dict] = {
    "A01-broken-access-control": {
        "owasp_id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
        "hunt_patterns": [
            "missing authorization check on endpoint",
            "IDOR via direct object reference",
            "privilege escalation via role manipulation",
            "CORS misconfiguration allowing unauthorized access",
            "missing function-level access control",
            "directory traversal to access protected files",
        ],
        "code_patterns": [
            r"@app\.route.*methods.*POST",
            r"def\s+delete.*request",
            r"def\s+update.*request",
            r"os\.path\.join.*request",
        ],
        "severity_boost": 1,
    },
    "A02-cryptographic-failures": {
        "owasp_id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often leads to exposure of sensitive data.",
        "hunt_patterns": [
            "weak hashing algorithm (MD5, SHA1 for passwords)",
            "hardcoded encryption keys",
            "missing TLS enforcement",
            "insecure random number generation for tokens",
            "weak cipher suite configuration",
        ],
        "code_patterns": [
            r"md5\(",
            r"sha1\(",
            r"ECB\s+mode",
            r"Random\(\)",
            r"Math\.random\(\)",
        ],
        "severity_boost": 0,
    },
    "A03-injection": {
        "owasp_id": "A03:2021",
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application.",
        "hunt_patterns": [
            "SQL injection via string concatenation",
            "command injection via os.system/exec",
            "LDAP injection",
            "NoSQL injection",
            "template injection (SSTI)",
            "CRLF injection",
        ],
        "code_patterns": [
            r"execute\(.*%s",
            r"execute\(.*\+",
            r"os\.system\(.*\+",
            r"os\.system\(.*%",
            r"subprocess\.call\(.*shell=True",
        ],
        "severity_boost": 1,
    },
    "A04-insecure-design": {
        "owasp_id": "A04:2021",
        "name": "Insecure Design",
        "description": "Risks related to design flaws, missing or ineffective security controls.",
        "hunt_patterns": [
            "missing rate limiting on authentication endpoints",
            "no account lockout mechanism",
            "insecure password reset flow",
            "missing input validation at trust boundaries",
            "business logic bypass",
        ],
        "code_patterns": [],
        "severity_boost": 0,
    },
    "A05-security-misconfiguration": {
        "owasp_id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing appropriate security hardening across any part of the application stack.",
        "hunt_patterns": [
            "debug mode enabled in production",
            "default credentials unchanged",
            "unnecessary features enabled",
            "missing security headers",
            "verbose error messages exposing internals",
            "directory listing enabled",
        ],
        "code_patterns": [
            r"DEBUG\s*=\s*True",
            r"debug\s*=\s*true",
            r"ALLOWED_HOSTS\s*=\s*\[.*\*",
        ],
        "severity_boost": 0,
    },
    "A06-vulnerable-components": {
        "owasp_id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "hunt_patterns": [
            "outdated dependency versions",
            "known CVEs in dependency tree",
            "unpinned dependency versions",
            "unused dependencies",
        ],
        "code_patterns": [],
        "severity_boost": 0,
    },
    "A07-auth-failures": {
        "owasp_id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management is not implemented correctly.",
        "hunt_patterns": [
            "weak password policy",
            "missing multi-factor authentication",
            "session fixation",
            "credential stuffing vulnerability",
            "improper session timeout",
            "session token in URL",
        ],
        "code_patterns": [
            r"password.*=.*request",
            r"session\[.*\]\s*=",
            r"Set-Cookie.*(?:;?\s*Secure|;?\s*HttpOnly)",
        ],
        "severity_boost": 1,
    },
    "A08-data-integrity-failures": {
        "owasp_id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations.",
        "hunt_patterns": [
            "insecure deserialization",
            "unsigned software updates",
            "CI/CD pipeline injection",
            "insecure auto-update mechanisms",
            "missing integrity checks on data",
        ],
        "code_patterns": [
            r"pickle\.load",
            r"yaml\.load\s*\(",
            r"eval\(.*request",
            r"exec\(.*request",
        ],
        "severity_boost": 1,
    },
    "A09-logging-failures": {
        "owasp_id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, detection, monitoring, and active response.",
        "hunt_patterns": [
            "missing audit logging for security events",
            "sensitive data in logs",
            "log injection",
            "missing alerting on failed authentication",
        ],
        "code_patterns": [
            r"password.*log",
            r"token.*log",
            r"secret.*log",
        ],
        "severity_boost": -1,
    },
    "A10-ssrf": {
        "owasp_id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.",
        "hunt_patterns": [
            "user-controlled URL in server-side request",
            "missing URL validation for outbound requests",
            "DNS rebinding vulnerability",
            "redirect-based SSRF",
            "SSRF to internal services",
        ],
        "code_patterns": [
            r"requests\.get\(.*request",
            r"requests\.post\(.*request",
            r"urllib\.request\.urlopen\(.*request",
            r"fetch\(.*request",
        ],
        "severity_boost": 1,
    },
}


def get_owasp_rules(*categories: str) -> list[dict]:
    """Get OWASP rules for specified categories.

    If no categories specified, returns all rules.
    """
    if not categories:
        return list(OWASP_RULES.values())
    return [OWASP_RULES[c] for c in categories if c in OWASP_RULES]


def format_owasp_hunt_guidance(*categories: str) -> str:
    """Format OWASP rules as hunt guidance text for injection into prompts."""
    rules = get_owasp_rules(*categories)
    if not rules:
        return ""

    lines = ["## OWASP Top 10 Hunt Guidance", ""]
    for rule in rules:
        lines.append(f"### {rule['owasp_id']}: {rule['name']}")
        lines.append(rule["description"])
        lines.append("")
        lines.append("Hunt for:")
        for pattern in rule["hunt_patterns"]:
            lines.append(f"- {pattern}")
        if rule["code_patterns"]:
            lines.append("")
            lines.append("Code patterns to grep:")
            for pat in rule["code_patterns"]:
                lines.append(f"  `{pat}`")
        lines.append("")

    return "\n".join(lines)


def match_owasp_category(finding: dict) -> str | None:
    """Match a finding to an OWASP category based on its class and description."""
    vuln_class = str(finding.get("class") or "").lower()
    desc = str(finding.get("desc") or "").lower()

    # Direct class mapping
    class_map = {
        "injection": "A03-injection",
        "path-traversal": "A01-broken-access-control",
        "auth-bypass": "A07-auth-failures",
        "crypto": "A02-cryptographic-failures",
        "deserialization": "A08-data-integrity-failures",
        "ssrf": "A10-ssrf",
        "xss": "A03-injection",
    }

    for key, category in class_map.items():
        if key in vuln_class:
            return category

    # Description-based matching
    if any(
        kw in desc for kw in ("sql injection", "command injection", "ldap injection")
    ):
        return "A03-injection"
    if any(kw in desc for kw in ("idor", "access control", "privilege escalation")):
        return "A01-broken-access-control"
    if any(kw in desc for kw in ("ssrf", "server-side request")):
        return "A10-ssrf"
    if any(kw in desc for kw in ("deserialization", "pickle", "yaml.load")):
        return "A08-data-integrity-failures"
    if any(kw in desc for kw in ("weak", "md5", "sha1", "hardcoded key")):
        return "A02-cryptographic-failures"
    if any(kw in desc for kw in ("session", "authentication", "password")):
        return "A07-auth-failures"

    return None
