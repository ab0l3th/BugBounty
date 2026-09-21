# BugBounty

A private workflow repository for approved security research, scope tracking, passive recon automation, and program-specific notes.

## Purpose

This repository is designed to support authorized bug bounty and security testing work, with a focus on:

- program intake and scope tracking
- reusable automation and scanning jobs
- passive reconnaissance and enrichment workflows
- finding triage and evidence management
- structured notes per program

## Security principles

- Only track in-scope assets and approved testing targets.
- Do not store secrets, credentials, tokens, customer data, or production credentials.
- Keep program notes organized and explicitly tied to written approval.
- Maintain a clear boundary between passive recon, active testing, and exploit validation.
- Treat the program policy as the controlling source of scope and guardrails.

## Required guardrails

- Confirm official program scope before any testing or automation job is queued.
- Keep all activity within approved domains and assets only.
- No credential theft, data exfiltration, customer-data collection, or service disruption.
- No social engineering, phishing, MITM, or physical access testing.
- No public disclosure of findings or indicators before program policy allows it.
- Maintain sanitized evidence and avoid storing sensitive or regulated data.

## Repository structure

- `automation/` — polling workers, schedules, and passive recon automation
- `programs/` — one folder per program or engagement
- `programs/template/` — reusable template for all new scope intakes
- `templates/` — reusable templates for notes, issue records, and reports
- `notes/` — general working memory and process notes
- `scans/` — queued or archived scan definitions and outputs
- `findings/` — references and triage records for discovered issues
- `logs/` — workflow and execution logs

## Program intake workflow

1. Validate scope and approvals.
2. Copy the standard template from `programs/template/`.
3. Rename it for the new program and replace the sample domain entries.
4. Record allowed targets, rules, and exclusions.
5. Add automation jobs in `jobs/` only after scope is confirmed.
6. Maintain clean evidence and clear reporting paths.

Every new program should use the same passive-only intake flow, scope validation, and review model as the AA scope.

## Automation workflow

The project includes a basic passive recon worker that:

- reads approved jobs from `jobs/`
- validates targets against the in-scope asset list
- skips out-of-scope targets
- writes a sanitized result record under `results/`

This workflow is intentionally limited to passive reconnaissance and scope enforcement. No active exploitation or service degradation is allowed.

## Local LAN dashboard

A lightweight dashboard is included for local review over your private network:

- app entry: `automation/dashboard_app.py`
- service file: `automation/systemd/bugbounty-dashboard.service`
- local docs: `automation/dashboard_README.md`

It reads the JSON result files from `results/` and serves a simple web view suitable for hosts on your LAN. It is intended for private, in-network access only and is not exposed publicly.

## Testing sequence and dependency order

This sequence is intentionally ordered and must be followed in order:

1. Validate scope and approved targets.
   - Confirm the in-scope assets and allowed testing surfaces.
   - Ensure the discovery list is limited to authorized targets only.

2. Enumerate services on the live and relevant hosts.
   - Check which hosts respond and what services are exposed.
   - Use service fingerprinting to identify HTTP, APIs, proxies, admin panels, and alternate ports.
   - Keep only the hosts and ports that are genuinely relevant to the in-scope program.

3. Confirm live web assets first, but only after steps 1 and 2 are complete.
   - Use the narrowed target list from steps 1 and 2 before validating which domains are worth testing.
   - Check the relevant domains for live HTTP responses on:
     - 80 / 443
     - 8080 / 8443
     - 8000 / 5000, if internal app patterns apply
   - Use:
     - `httpx` or `curl` to verify HTTP status
     - `nmap` for service fingerprinting when needed
     - `whatweb` or Wappalyzer-style checks for tech stack
   - Goal: reduce the list from "all discovered domains" to "real web apps worth testing"
   - Important: this step must not run before steps 1 and 2 because it depends on the host/service data produced by those steps.

4. Run vhost discovery only when there is evidence of shared infrastructure.
   - Use vhost checks when multiple apps share the same IP, or when a proxy/CDN is likely fronting the application.
   - Skip vhost fuzzing for simple single-app domains unless evidence suggests it is necessary.

5. Run targeted directory and file enumeration only on the confirmed live targets.
   - Focus on actual app roots rather than broad, noisy scans across every discovered domain.
   - Prioritize likely application paths such as `/admin`, `/login`, `/api`, `/docs`, `/health`, `/backup`, `/config`, and similar known app locations.

6. Move into application testing only after the live targets and reachable app surface are known.
   - Test authentication flows, exposed APIs, admin panels, and likely misconfigurations.
   - Keep testing minimal, scoped, and aligned with the approved rules.

## Initial status

This repository has been initialized as a private, controlled workspace for approved bug bounty and security research workflows.
