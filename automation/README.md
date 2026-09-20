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

## Scheduled runner pattern

The repo includes a passive scheduler model that:

- runs the worker on a fixed interval via systemd timer or cron
- reads approved jobs from `jobs/`
- validates each target against the in-scope list
- writes the latest result to `results/`
- saves the previous run under `results/.state/`
- compares the current result to the previous one
- only emits an alert when a change is detected

This gives you a reviewable passive recon loop without sending noise for unchanged results.
