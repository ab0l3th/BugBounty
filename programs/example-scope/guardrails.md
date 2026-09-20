# Example Program Guardrails

## Purpose
This program folder follows the standard private bug bounty intake model for approved, non-sensitive passive recon.

## Required controls
- Validate every host against the official scope before execution.
- Only use approved domains and subdomains.
- Keep automation passive and non-invasive.
- Do not store sensitive customer data, credentials, or production secrets.
- Treat the program policy as the controlling source of truth.

## Review workflow
- Confirm the scope file is current.
- Confirm the program rules match the policy.
- Validate all job definitions against the approved scope.
- Review all results locally before any external sharing.
