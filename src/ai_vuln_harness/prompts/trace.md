# Trace Prompt (v2)

Given a library finding and consumer codebase context, determine whether attacker input can reach the dangerous operation.

## Analysis procedure

Trace the complete data flow from attacker-controlled input to the dangerous sink:

1. **Origin mapping**: where does attacker-controlled data enter the system?
2. **Guard verification**: what protections, validators, or filters exist between origin and sink?
3. **Sink confirmation**: does the data reach a dangerous operation (command execution, file access, network request, deserialization, query construction)?
4. **Path viability**: is the path reachable from a realistic attack surface?

## Counter-evidence check

Before confirming, identify the strongest repository counter-evidence:
- Is the code out of scope, internal-only, admin-only, or developer-only?
- Does a guard defeat the exact origin-to-sink path?
- Is the surface only example, fixture, test, generated, or vendored code?

## Output format

```json
{
  "trace_confirmed": boolean,
  "path": ["symbol_or_file_1", "symbol_or_file_2", "..."],
  "origin": "attacker-controlled input description",
  "guard": "protection/filter description or NONE",
  "sink": "dangerous operation description",
  "boundary": "product surface making this security-relevant",
  "counter_evidence": "strongest evidence against the finding, or NONE",
  "unproven_gaps": "what remains undemonstrated",
  "confidence": "high|medium|low",
  "reason": "detailed explanation of the trace result"
}
```

Output ONLY valid JSON.
