# Local LAN dashboard

This dashboard serves the latest JSON results from the repo over a private LAN connection.

## Run locally

```bash
cd /home/ab0l3th/BugBounty
source .venv/bin/activate
python3 automation/dashboard_app.py
```

Then open:

- http://localhost:8000
- or http://SERVER_PRIVATE_IP:8000 on the LAN

## Run as a systemd service

Install the app dependencies first:

```bash
source .venv/bin/activate
python3 -m pip install -r automation/requirements.txt
```

Then enable the service:

```bash
sudo cp /home/ab0l3th/BugBounty/automation/systemd/bugbounty-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bugbounty-dashboard.service
sudo systemctl status bugbounty-dashboard.service
```

The dashboard is intentionally private-only and should be accessed on your local network rather than exposed publicly.

## Background refresh

The refresh timer and Refresh data button update counters and workflow content in
place, without navigation or saving/restoring expanded sections. Existing detail
nodes, open/closed states, scroll position, focus, file selections, and in-progress
upload or guideline inputs remain intact. Approval, upload, and job-start actions
also refresh in place. Failed refreshes leave the current dashboard visible.

## Finding review

Use the review link inside a program or job. Review queues never combine findings
from different programs. Columns can be sorted, and the severity filter can show
only MEDIUM, HIGH, and CRITICAL scanner signals. Scanner severity and confidence
are independent, color-coded triage values, not confirmed impact ratings.

Every finding has a program-bound verification draft, including findings without
a saved scanner HTML report. Download the Markdown draft, independently verify
the observation, and fill in confirmed reproduction steps, demonstrated impact,
and eligibility before manually reporting. Drafts do not submit reports.

## Manual scope workflows

Checking the manual scope confirmation checkbox loads the current guidelines,
saves approval, and queues nine manual-only steps beneath the existing program
workflows. There is no separate approval button. Unchecking it revokes approval
without deleting saved results. Approval does not launch any step and does not
create jobs that the automatic runner can pick up. Dependencies, current
guidelines, and exact scope are checked again for each manual start.
Once approval and all nine queued steps are present, the program disappears from
manual scope review and is managed through its workflow below existing programs.
Other pending programs remain visible. Revoked approval, changed guidelines, or
an incomplete workflow make the review entry available again.

The manual workflow uses offline scope inventory, exact-host DNS, bounded HTTP
liveness and service checks, shared-IP checks of uploaded hosts, curated path
checks, application/API observations, and explicitly permitted TCP checks.
Follow-up active steps use only hosts confirmed live. URL-restricted assets never
expand into domain-wide or wildcard scope. App IDs remain inventory-only.

All manual HTTP requests, including redirect hops, are serialized at no more than
1 request per second. Redirects must remain in uploaded scope; login/SSO,
query-bearing, looping, excessive, and HTTPS-downgrade redirects are skipped.
Manual HTTP checks use GET/HEAD only, bounded response reads, and no external
scanners or POST probes. Standalone URL checks and workflow steps share a
per-program lock. Approval revocation or guideline changes stop further requests.

Explicit testing bans still block the relevant steps. TCP port scanning requires
explicit permission in the guidelines and exact-host scope. A request-rate limit
is not permission to run prohibited tests, and manually verifying a finding does
not make a prohibited scan compliant. Automated findings may also be ineligible
for reporting even when the requests themselves are permitted.
