# Automation

This folder holds the passive recon and automation workflows for approved programs.

## Intended use

- polling and scheduling jobs
- passive recon tasks
- DNS, certificate, and asset discovery modules
- change detection and scoring logic
- notification and triage triggers

## Guardrails

- Do not run active exploitation without explicit approval.
- Keep automation limited to approved assets and allowed testing methods.
- Store only sanitized output; avoid saving secrets or personal data.
