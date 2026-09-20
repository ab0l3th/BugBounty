# Program Scope Template

## Status
- Program: <program name>
- Scope status: intake in progress
- Notes: populate only with approved, non-sensitive scope details

## In-scope targets
- *.example.com
- *.sub.example.com
- example.com

These are the currently recognized scope wildcards from the approved vendor documentation and should be treated as the authoritative scope list unless a newer official program update supersedes them.

## Out-of-scope targets
- Any assets not explicitly approved by the program
- Customer data, PII, credentials, or production secrets
- Internal-only systems not listed in authorized scope
- Systems or attack paths requiring MITM, physical access, or social engineering
- Activities that could disrupt or degrade service availability

## Rules
- Validate all scope against official program documentation before testing.
- Restrict automated checks to approved assets only.
- No exploitation without explicit approval.
- No collection or retention of sensitive customer or employee data.
- No public disclosure of vulnerability details or indicators.
- Report one issue per submission unless a chained issue is necessary and clearly justified.
