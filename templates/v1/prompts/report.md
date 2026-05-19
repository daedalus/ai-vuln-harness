# Report Prompt (v1)

Generate final structured report matching `schemas/report.schema.json`.

Rules:
- Include `bucket_rationale` on each finding
- For library targets, findings without confirmed Trace cannot be `fix_now`
