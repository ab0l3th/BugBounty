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

## Owned Shopify Account Comparison

`shopify_account_checks.py` is a local, operator-run tool, not a scheduled scan.
It compares isolated owner and App developer sessions on selected routes in your
own developer organization and owned shop. Basic-plan staff restrictions still
apply; App developer is not read-only staff. Keep store kind `unknown` unless
you have confirmed whether the selected store is production or development.

Install the optional browser dependency locally:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r automation/requirements-account-checks.txt
```

Microsoft Edge must be installed locally; this workflow does not use the VS Code
embedded browser or Playwright's bundled Chromium for authentication.

Prepare the matrix after confirming ownership and required HackerOne-alias signup:

```sh
.venv/bin/python automation/shopify_account_checks.py prepare \
	--shop YOUR-OWNED-SHOP.myshopify.com --organization YOUR-ORGANIZATION-ID \
	--confirm-owned --confirm-alias
```

Add `--store-kind production` only if confirmed. Billing is excluded unless
explicitly selected with `--include-billing` during preparation.

Capture each account separately. The first capture creates a separate persistent
profile for that role and opens a normal Microsoft Edge window:

```sh
.venv/bin/python automation/shopify_account_checks.py capture --role owner --browser edge
.venv/bin/python automation/shopify_account_checks.py capture --role appdev --browser edge
.venv/bin/python automation/shopify_account_checks.py run
```

The profiles are created under `.secrets/shopify-account-profiles/edge/owner`
and `.secrets/shopify-account-profiles/edge/appdev`. Log into the appropriate
account in each window, confirm the selected developer organization, then press
Enter in the terminal. Edge is started as a normal process with a debugger bound
only to `127.0.0.1`; Playwright attaches only after you confirm login. The profile
is reused by later `run` commands; cookies are not exported as JSON. You do not
need to create Edge profiles manually. Keep the profiles local, never copy/share/
commit them, and don't enable browser sync for them. They contain reusable auth
state under the ignored `.secrets/` directory.

`run` opens each role's normal Edge profile in turn, attaches locally, performs
the bounded checks, and closes that Edge process. No embedded browser session is
read or reused.

Login and MFA happen directly in the browser, with no credential entry in chat
or the terminal. Verify the account identity and assigned role before pressing
Enter; role labels are user attestations, not independently verified identities.
Capture permits your manual authentication flow; it is not an automated test.
Repeat `run` to refresh the comparison. If Shopify expires the session, rerun
`capture` for that role in the existing profile and complete login interactively;
the tool never bypasses passkeys, MFA, or CAPTCHA. Reports are owner-only JSON
and Markdown under
`results/shopify-owned-account-checks.*`, with no raw text, screenshots, cookies,
local storage, or token/query values. These observations are not scanner findings
and do not trigger alerts or enable the general Shopify scanner.

Checks observe only the top-level navigation response; page subresources are
aborted to keep the probe bounded and avoid login/UI load stalls. A 200 is recorded
as `reachable_unverified`, not proof of page data, action access, or a vulnerability.
Mutation/action requests, websockets, foreign store/org routes, and unknown
persisted GraphQL operations are blocked. The selected top-level requests share
a one-request-per-second limit. Login redirects and failed navigation are not
permission bypasses. Use the report to select manual verification against current
program criteria.
