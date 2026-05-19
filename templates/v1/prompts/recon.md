# Recon Prompt (v1)

Map the repository and emit a JSON array matching `schemas/recon_tasks.schema.json`.

Requirements:
- Identify subsystem boundaries and likely trust boundaries
- Prioritize attack classes by risk and external input exposure
- Emit concrete `target_files`; do not emit wildcard-only tasks
