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

## Phone Alerts With ntfy

The independent `bugbounty-ntfy.service` watches saved results every 10 seconds
and sends new HIGH/CRITICAL scanner signals. It reads the owner-only server file
`/home/ab0l3th/.ssh/ntfy_sh` without evaluating shell code. Keep that file mode
0600 and outside Git. Required assignments:

```ini
BUGBOUNTY_NTFY_URL=https://ntfy.sh
BUGBOUNTY_NTFY_TOPIC=your-topic
BUGBOUNTY_NTFY_TOKEN=your-private-access-token
BUGBOUNTY_DASHBOARD_URL=http://192.168.1.16:8001
```

First enablement baselines existing findings without alerting. A private SQLite
ledger under `results/.notifications/ntfy.sqlite3` deduplicates later findings
across restart/rescans and retries delivery failures. Alerts are grouped by bounty
and cooled down for 60 seconds per bounty; scanning is never blocked by delivery.

A token alone does not make a public topic private. The notifier verifies topic
reservation and denial of public reads through ntfy's account API. Unverified or
public topics receive only generic severity/count alerts, with no bounty, asset,
job, evidence, or dashboard link. Detailed metadata and the program review link
are enabled only for verified private topics. Response bodies, credentials,
query values, and sensitive evidence are never sent. Every signal is unverified
and still requires manual confirmation. The private dashboard link needs LAN/VPN.

Subscribe to the configured topic in the ntfy app and allow phone notifications.
To send a non-sensitive connection test directly on the server:

```bash
cd /home/ab0l3th/BugBounty
.venv/bin/python3 automation/ntfy_notifier.py --test
```

Install the supplied systemd unit as `bugbounty-ntfy.service`, enable it at boot,
and restart only that notifier service when changing its unit. The credential
file is reread automatically; topic privacy is rechecked at least every 5 minutes.
Do not restart scan services merely to enable alerts.

## Finding Review

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
For opted-in CSV scope, eligible URL/endpoints, domains, and wildcards are
partitioned per asset. The automatic subset starts immediately; in-scope assets
needing operator review remain in a separate manual queue under the same bounty.
App IDs, unsupported assets, and URLs carrying query/fragment data remain manual
verification inventory. Explicitly out-of-scope or unconfirmed rows are excluded,
never converted into scan targets. Bounty eligibility alone is not testing permission.

The automatic and manual jobs have separate result/dependency names. Manual work
requires an explicit individual stage start, and both queues share the program
run lock and traffic policy. Automatic requests cannot reach a manual/excluded
host or path through a broader wildcard. Full URLs retain their exact scheme,
host, port, and path; they do not silently become domain-wide scope.

Auto-run advances the canonical stages in dependency order. Recognized testing
bans mark stages blocked; stages requiring their results remain waiting. Defaults
are 1 request per second when no numeric limit is stated and 2 general workers.
An explicit numeric request limit is honored directly. Vhost/directory stages
use up to 8 discovery workers (subject to the server worker budget), with one
program-wide request-start limiter; network I/O does not hold the pacing lock.
Limits are not multiplied by the number of URLs/hosts. External curl/nmap/whatweb
probes are disabled. HTTP requests,
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

All manual HTTP requests, including redirect hops, share the stated program
aggregate request-start limit. Slow responses can overlap within the bounded
worker budget; directory/vhost checks can use up to 8 host workers. A per-host or
per-endpoint rate must be explicitly stated before it can replace an aggregate
limit. Redirects must remain in uploaded scope; login/SSO,
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

## Vhost Transport

Vhost requests use the candidate hostname for URL, Host, and TLS SNI while
connecting to the already scoped/resolved origin IP. TLS certificate verification
is not disabled. Unsupported proxy pinning is reported rather than bypassed.
EdgeSuite/Akamai "Invalid URL" pages and login redirects are rejected probe
observations, not confirmed vhosts; repeated edge errors are grouped by origin.
Known edge rejections are not retried over HTTP. Running jobs retain their loaded
code until they finish or are explicitly restarted.

## API Lists and Prefixes

API discovery includes the pinned SecLists Java-Spring-Boot list in
`automation/wordlists/api-endpoints.txt` and the project-maintained
`automation/wordlists/api-prefixes.txt`. Every endpoint is combined with every
prefix (including root) and deduplicated. Examples include
`/backend/actuator/env`, `/service/actuator/health`, and `/api/v1/v3/api-docs`.
Complete custom directory paths are also retained without an API-name filter.

Use `BUGBOUNTY_API_ENDPOINTS_WORDLIST` and `BUGBOUNTY_API_PREFIXES_WORDLIST` to
replace either list. Prefixed GraphQL locations use only the existing read-only
introspection query. Swagger/OpenAPI base paths and same-host server paths are
honored; external documentation servers are not followed automatically. All
generated requests still pass the program scope, approval, and rate guards.

## Stop and Restart Jobs

Queued and running jobs have a **Stop job** control. Stopping saves a durable
per-job hold marker, retains partial observations and checkpoints, and prevents
the scheduled worker from immediately picking up that job again. New workers
check for cancellation before network requests and checkpoints; an in-flight
request may finish or time out first. Older workers can be terminated only after
their scoped process identity and job locks are verified; unrelated processes
and reused PIDs are never intentionally signaled.

The UI shows **Stopping...** while an in-flight worker exits, then **Restart job**.
Restart explicitly clears the hold after the normal permission/run-lock checks.
The stopped result is also copied to `results/.stopped-results/<job>.json` before
the new attempt starts, so prior partial observations remain available on disk.
Some stages retain useful checkpoints, but restarting may repeat work: this is
not an exact, in-memory pause/resume guarantee. Independent jobs/bounties keep
their own stop markers. Deleting a bounty also removes its stop/owner sidecars.

## Delete and Reupload

Uploaded bounties have a **Delete bounty** action in their workflow or pending
manual-review entry. Type the exact program slug to confirm. The authenticated
DELETE action refuses live job locks and matching/global worker processes, then
removes only that bounty's scope/configuration, generated jobs, results, reports,
progress, and owned review decisions. Repository-owned built-in jobs and unsafe
symlinked paths are protected. Other programs and the upload draft remain intact.

After successful deletion, the same program name can be uploaded again. A fresh
upload identity prevents any old unmatched review records from applying to the
replacement bounty. Deletion refreshes the dashboard in place and never launches
or stops a scan implicitly.
