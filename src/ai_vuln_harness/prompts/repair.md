Your previous response could not be parsed. Fix only the formatting — keep the same assessment content.

MALFORMED OUTPUT (your previous response):
{malformed_output}

PARSE ERROR:
{parse_error}

EXPECTED FORMAT (output must match one of these exactly):

--- JSON (preferred) ---
{{"status": "confirmed|rejected|needs-more-info", "reason": "...", "criteria": {{"evidentiary": "PASS|FAIL|N/A", "reproducible": "PASS|FAIL|N/A", "not_by_design": "PASS|FAIL|N/A", "project_code": "PASS|FAIL|N/A", "consistent": "PASS|FAIL|N/A"}}}}

--- XML fallback ---
<validate_result>
  <status>confirmed|rejected|needs-more-info</status>
  <reason>...</reason>
  <criteria>
    <evidentiary>PASS|FAIL|N/A</evidentiary>
    <reproducible>PASS|FAIL|N/A</reproducible>
    <not_by_design>PASS|FAIL|N/A</not_by_design>
    <project_code>PASS|FAIL|N/A</project_code>
    <consistent>PASS|FAIL|N/A</consistent>
  </criteria>
</validate_result>

Instructions:
1. Output ONLY the corrected response — no preamble, no explanation, no markdown fences.
2. Do NOT change the semantic content of your assessment.
3. Keep the same status, reason, and criteria values you intended.
