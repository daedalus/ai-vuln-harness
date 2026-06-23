# Validation Evidence Requirements

For each vulnerability class, gather specific evidence before confirming a finding.

## Universal Requirements

Every confirmed finding needs:
- **Entry point**: Where attacker input enters the system
- **Flow**: Path from entry to dangerous operation
- **Sink**: The vulnerable operation or decision point
- **Guard**: Existing protections (or lack thereof)
- **Impact**: Concrete security consequence

## By Vulnerability Class

### Injection (SQL, NoSQL, Command, LDAP)

Prove:
- Attacker-controlled value reaches query/command construction
- No parameterized queries, escaping, or input validation at sink
- Database/OS execution context with meaningful privileges

Common false positives:
- Parameterized queries (not string concatenation)
- Input validation before query construction
- ORM operations with bound parameters

### Cross-Site Scripting (XSS)

Prove:
- Attacker-controlled string rendered in HTML/JS context
- No output encoding for the specific context
- Attacker can trigger execution (stored, reflected with link, or DOM sink)

Context matters: HTML body, attribute, script block, CSS — each requires different encoding.

### Authentication / Session

Prove:
- Credential or session token is attacker-controlled
- Validation logic is missing, incorrect, or bypassable
- Result is unauthorized access to another account or privilege

Check: token binding, expiration, revocation, multi-factor enforcement.

### Authorization / Access Control

Prove:
- Request targets resource belonging to another user/tenant
- No ownership check, or check uses attacker-controlled values
- Direct object reference without authorization

Common patterns: IDOR, missing role checks, tenant isolation failure.

### Server-Side Request Forgery (SSRF)

Prove:
- URL or host parameter is attacker-controlled
- No allowlist, denylist, or network segmentation blocks access
- Internal services are reachable (metadata, databases, admin panels)

DNS rebinding, IPv6, and URL parsing inconsistencies can bypass filters.

### Path Traversal / File Access

Prove:
- File path contains attacker-controlled segments
- Canonicalization or containment check is missing or bypassable
- Target files contain sensitive data or enable code execution

Check: null bytes, Unicode normalization, symlink following, parent directory access.

### Deserialization

Prove:
- Attacker controls serialized data (request, file, message queue)
- Deserializer accepts arbitrary types or executes code during deserialization
- No type filtering, signing, or integrity checks

Language-specific: Java (ObjectInputStream), Python (pickle), PHP (unserialize), .NET (BinaryFormatter).

### XML External Entity (XXE)

Prove:
- XML parser processes external entities
- Input is attacker-controlled (upload, API, import)
- Sensitive files or internal services are accessible

Modern parsers often disable DTD by default — verify actual configuration.

### Cryptographic Issues

Prove:
- Weak algorithm, hardcoded key, or predictable IV
- Direct security impact (forgery, decryption, key recovery)
- Not mitigated by other layers (TLS, key management)

Common: ECB mode, MD5/SHA1 for passwords, static IVs, hardcoded secrets.

### Template Injection (SSTI)

Prove:
- User input reaches template rendering
- Template engine allows code execution (not just variable interpolation)
- Execution context has meaningful permissions

Test: `${7*7}` or `{{7*7}}` — if it evaluates to 49, RCE is likely.

### Security Misconfiguration

Prove:
- Default credentials, open admin interfaces, verbose errors
- Directly exploitable without other vulnerabilities
- Exposes sensitive functionality or data

Not just "missing headers" — demonstrate what an attacker gains.

### Supply Chain / Dependency

Prove:
- Dependency has known vulnerability with available exploit
- Vulnerable code path is actually called by the application
- No mitigation (patch, WAF rule, configuration change)

CVSS score alone isn't proof — verify reachability.

## Evidence Quality Scale

1. **Theoretical**: Vulnerability class exists, no proven path
2. **Partial**: Some conditions demonstrated, key step missing
3. **Confirmed**: Complete path from input to impact demonstrated
4. **Exploited**: Working proof-of-concept or real-world evidence

Mark findings at level 2 or below as unconfirmed until validated.
