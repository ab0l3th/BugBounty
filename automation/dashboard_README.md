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

Bounty groups start collapsed. Only a user expansion opens them; uploads,
approvals, and background updates never force a group open.

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

## Opt-In Auto-Run

For a new domain/wildcard bounty, select **Auto-run permitted stages** when
uploading scope and guidelines. This checkbox explicitly acknowledges the supplied
guidelines and starts a program-scoped pipeline without a second approval click.
Leave it unchecked to keep the existing passive discovery and approval workflow.
URL/app-only scope remains manual-only and cannot opt in through this checkbox.

Auto-run advances the canonical stages in dependency order. Recognized testing
bans mark stages blocked; stages requiring their results remain waiting. Defaults
are at most 1 request per second and 2 workers, with lower stated limits taking
precedence. External curl/nmap/whatweb probes are disabled. HTTP requests,
redirects, worker DNS lookups, and TCP checks share program pacing and a lock.
Redirects must remain in scope; login, excessive, and HTTPS-downgrade redirects
are skipped. Public passive lookups use the existing discovery providers.

Approval, guidelines, scope, and configuration are checked during execution.
Revocation or changes stop further requests. Reapproval under current guidelines
refreshes the policy and can resume the pipeline, without overlapping an existing
program run. Report drafts still require independent manual verification and
program eligibility review; missing rate limits do not authorize prohibited tests.

## Manual Scope Workflows

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
liveness and service checks, scoped Host-header tests, full wordlist path
checks, application/API observations, and TCP ports 1-65535 where permitted.
HTTP follow-up steps use hosts confirmed live; TCP enumeration also includes
authorized hosts that do not serve HTTP. URL-restricted assets never
expand into domain-wide or wildcard scope. App IDs remain inventory-only.

All manual HTTP requests, including redirect hops, are serialized at no more than
1 request per second. Redirects must remain in uploaded scope; login/SSO,
query-bearing, looping, excessive, and HTTPS-downgrade redirects are skipped.
Manual HTTP checks use GET/HEAD plus the fixed read-only GraphQL introspection
query, bounded response reads, and no external scanners or mutating API methods.
Standalone URL checks and workflow steps share a
per-program lock. Approval revocation or guideline changes stop further requests.

Explicit testing bans still block the relevant steps. TCP enumeration requires
full-host scope and guideline approval; path-only URLs do not authorize it. A request-rate limit
is not permission to run prohibited tests, and manually verifying a finding does
not make a prohibited scan compliant. Automated findings may also be ineligible
for reporting even when the requests themselves are permitted.

## Discovery Coverage

Directory discovery consumes the complete pinned SecLists common list. Wildcard
vhost discovery consumes the complete 5,000-label list only for hostnames matching
scope. Full-host inventories check their authorized names against scoped origins;
an exact domain does not implicitly authorize guessed subdomains or unrelated IPs.
Custom list files can be supplied through `BUGBOUNTY_DIRECTORIES_WORDLIST` and
`BUGBOUNTY_VHOSTS_WORDLIST`; entries have no artificial count cutoff.

API discovery includes configured/common API paths and all concrete documented
OpenAPI paths, with no 15-path truncation. Public JSON data is recorded as an
observation; unauthenticated findings require documented authentication. TCP
enumeration covers every port from 1 through 65535; unfamiliar open services are
informational observations rather than automatically high-severity bugs.

Later service, directory, application, API, and port stages do not drop hosts at
a count limit. Live-web confirmation retains batches for resource control, and
auto-run drains those batches before advancing. Thread/rate limits and explicit
testing bans remain enforced for exact and wildcard scope alike. Wildcards expand
eligible hostname coverage, not traffic rates, excluded assets, or permissions.
Large lists and full TCP enumeration can take many hours at low permitted rates;
progress counters and partial observations remain available during execution.
