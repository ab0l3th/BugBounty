# American Airlines Guardrails

## Program basis
This guardrail set is derived from the official American Airlines HackerOne program policy and the current scope export for the program.

## Core rules
- Stay within the approved assets and scope list only.
- Maintain compliance with the program's safety, disclosure, and testing rules.
- Do not exfiltrate data, access customer data, or retain sensitive production content.
- Do not conduct denial-of-service, service degradation, or disruption testing.
- Do not perform social engineering, physical access, or MITM attacks.
- Do not test assets outside the approved domain list.
- Do not disclose vulnerabilities publicly before the program rules allow it.

## Approved scope
- *.aa.com
- *.psaairlines.com
- *.envoyair.com
- *.piedmont-airlines.com
- *.cloud.aa.com
- *.maverick.aa.com
- *aavacations.com

## Safety boundaries
- Only interact with accounts you own or have explicit permission to use.
- Avoid privacy violations or any intentional access to data beyond what is necessary to prove a vulnerability.
- Keep all testing minimal and focused on proving the issue.
- Never collect or retain credentials, personal data, sensitive logs, or employee/customer information.

## Submission standards
- Provide a detailed and reproducible report with steps, impact, and remediation guidance.
- Keep one issue per report unless a chain is needed to show impact.
- Avoid low-volume, low-quality, duplicate submissions.
- If there is uncertainty about scope or legality, stop and escalate before proceeding.

## Automation guardrails
- Automated testing should be passive-only unless active testing is explicitly approved.
- Scope checks must run before any task is dispatched to a VM or worker.
- Results should be sanitized before storage or notification.
- Alerting should only trigger for in-scope assets and approved findings.

## Operational policy
- This repository is a controlled work environment for approved security research.
- Documentation should remain non-sensitive, reviewable, and aligned with official policy.
- Any exception to policy requires explicit written approval from the program owner or designated security contact.
