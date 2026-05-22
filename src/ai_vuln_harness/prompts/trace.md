# Trace Prompt (v1)

Given a library finding and consumer codebase context, determine whether attacker input can reach the sink.

Output JSON object:
- trace_confirmed: boolean
- path: array of symbols/files
- reason: string
