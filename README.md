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

4. Enumerate services on the live hosts.
   - For every host that responds, run a port and service check to see what is exposed.
   - Identify whether the asset is a plain static site, a reverse proxy, an API gateway, or a true application server.
   - Look for alternate hosts, admin endpoints, login surfaces, and exposed management interfaces.
   - This is higher value than broad directory scanning because it answers what the app actually is before brute-forcing paths.

5. Run vhost discovery only when there is evidence of shared infrastructure.
   - Use vhost checks when multiple apps share the same IP, or when a proxy/CDN is likely fronting the application.
   - Skip vhost fuzzing for simple single-app domains unless evidence suggests it is necessary.
   - This is the "maybe" stage, not the default first move.
   - Implemented as the `vhost-discovery-shared-infra` job: it groups the Step 4 live hosts by resolved IP, flags only hosts that share an IP or are proxy/CDN fronted, and confirms name-based virtual hosting using in-scope co-located hostnames (no blind external wordlists).

6. Run targeted directory and file enumeration only on the confirmed live targets.
   - Focus on actual app roots rather than broad, noisy scans across every discovered domain.
   - Prioritize likely application paths such as `/admin`, `/login`, `/api`, `/docs`, `/health`, `/backup`, `/config`, and similar known app locations.
   - Implemented as the `directory-enumeration-live-hosts` job: it takes the combined Step 4 (service enumeration) and Step 5 (vhost) live hosts, then checks a curated app-root path list per host and records interesting HTTP statuses (200/301/302/401/403).

7. Move into application testing only after the live targets and reachable app surface are known.
   - Test authentication flows, exposed APIs, admin panels, and likely misconfigurations.
   - Keep testing minimal, scoped, and aligned with the approved rules.
   - Implemented as the `application-security-testing` job: non-destructive detection across the combined live hosts — missing security headers, tech/version disclosure, insecure cookie flags, CORS reflection with an untrusted Origin, and error/stack-trace disclosure. It flags signals for manual confirmation; it does not exploit, brute-force, or modify data.

8. API endpoint testing on API hosts.
   - Implemented as the `api-endpoint-testing` job: targets Step 4 `api-gateway` hosts plus Step 6 hosts exposing API-ish paths (`/api`, `/swagger`, `/graphql`, `/openapi`, `/actuator`).
   - Detects exposed debug endpoints (e.g., `/actuator/env`, `/v2/api-docs`) and whether they return data, GraphQL introspection, and unauthenticated access to documented endpoints parsed from an exposed OpenAPI/Swagger spec (bounded, read-only GETs).
   - All checks are non-destructive detection signals for manual review, not exploitation.

## Safety note on active testing (steps 3-8)

Steps 3 through 8 make live connections to targets and are therefore active, not passive. They are off by default and only run with the worker's `--allow-active` flag (the dashboard supplies this automatically for those steps). The application and API testing stages gather non-destructive detection signals only; confirmation and exploitation remain manual and must stay within the approved program scope and rules.

## Initial status

This repository has been initialized as a private, controlled workspace for approved bug bounty and security research workflows.
