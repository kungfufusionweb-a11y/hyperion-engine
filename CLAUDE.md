# Hyperion Engine Project Rules

## Token Optimization & Style
- Be concise. Write code directly. 
- Do not write multi-paragraph summaries or explain changes unless explicitly asked.

## Output Schema Contract
Every detected vulnerability MUST strictly follow this exact JSON schema contract. Do not improvise fields:
{
  "file": "string (relative path to file)",
  "line_number": "integer",
  "snippet": "string (the exact offending line of code)",
  "pattern_type": "string (Secret / SQL Injection / Command Injection / Deserialization)",
  "confidence": "string (Low / Medium / High)"
}
