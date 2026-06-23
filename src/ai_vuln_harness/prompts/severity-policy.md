# Vulnerability Severity Assessment

Use this framework after collecting technical evidence: reachability, impact scope, and exploitation difficulty.

## Severity Levels

### P0 — Critical

Conditions that justify this level:
- Remote code execution without authentication
- Full account compromise leading to admin access
- Bypass of all authentication/authorization on sensitive operations
- Mass data exfiltration of credentials, secrets, or PII
- Supply chain compromise affecting downstream users
- Sandbox/container escape with persistent access

Requires concrete proof: working exploit path, not theoretical.

### P1 — High

Conditions that justify this level:
- Server-side request forgery reaching internal services
- Stored cross-site scripting with session theft
- SQL/NoSQL injection modifying or exfiltrating data
- Path traversal reading sensitive files
- Authentication bypass on specific endpoints
- Broken access control exposing other users' data

Requires demonstrated attacker control and reachable sink.

### P2 — Medium

Conditions that justify this level:
- Information disclosure of non-sensitive data
- CSRF on non-critical state changes
- Reflected XSS without direct impact evidence
- Open redirect in multi-step flows
- Missing security headers without exploit chain
- Race conditions with limited impact

May be valid but lacks the impact or reach for higher rating.

### P3 — Low / Informational

- Best practice violations without demonstrated impact
- Version disclosure, error messages, stack traces
- Missing CSP, HSTS, or similar headers in isolation
- Theory-only vulnerabilities requiring many assumptions

## Escalation Factors

Push a finding up one level when:
- No authentication required
- Exploitation is trivial (no user interaction)
- Affects multiple tenants or cross-boundary data
- Compromises signing, identity, or control-plane systems
- Enables persistent access or lateral movement

## Downgrade Rules

Reduce severity or mark informational when:
- Requires existing admin/developer/operator access
- No realistic attacker can reach the code path
- Impact is limited to self-affected data
- Issue is theoretical without demonstrated exploitability
- Would not survive bug bounty triage at this severity

## Severity Matrix

| Impact \ Likelihood | High | Medium | Low |
|---------------------|------|--------|-----|
| **High** | P1 | P2 | P3 |
| **Medium** | P1 | P2 | P3 |
| **Low** | P2 | P3 | Info |

Likelihood factors:
- Network-exposed = high
- Requires user interaction = medium
- Local only = low
- Impossible scenario = Info

## Acceptance Criteria

Before assigning P0 or P1, confirm all:
1. Component is in scope
2. Attacker has realistic capability
3. Attack surface is accessible
4. Exploitation path is demonstrated (not speculative)
5. Security impact is material

## Priority Mapping

- P0 → fix immediately, deploy blocker
- P1 → fix before next release
- P2 → fix in current sprint
- P3 → backlog, best-effort
