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
.venv/bin/python -m playwright install chromium
```

Prepare the matrix after confirming ownership and required HackerOne-alias signup:

```sh
.venv/bin/python automation/shopify_account_checks.py prepare \
	--shop YOUR-OWNED-SHOP.myshopify.com --organization YOUR-ORGANIZATION-ID \
	--confirm-owned --confirm-alias
```

Add `--store-kind production` only if confirmed. Billing is excluded unless
explicitly selected with `--include-billing` during preparation.

Capture each account separately:

```sh
.venv/bin/python automation/shopify_account_checks.py capture --role owner
.venv/bin/python automation/shopify_account_checks.py capture --role appdev
.venv/bin/python automation/shopify_account_checks.py run
```

On macOS with Microsoft Edge installed, add `--browser edge` to either capture
command to use the Edge channel instead of Playwright's bundled Chromium.

Login and MFA happen directly in the browser, with no credential entry in chat
or the terminal. Verify the account identity and assigned role before pressing
Enter; role labels are user attestations, not independently verified identities.
Capture permits your manual authentication flow; it is not an automated test.
Session JSON contains authentication material: keep it local and never share it,
commit it, or upload it to the scanner server. Default files are ignored by Git
under `.secrets/`; sessions use a private directory and owner-only files.

Repeat `run` to refresh the comparison, or capture again after session expiry.
`--headed` shows the test browser. Reports are owner-only JSON and Markdown under
`results/shopify-owned-account-checks.*`, with no raw text, screenshots, cookies,
local storage, or token/query values. These observations are not scanner findings
and do not trigger alerts or enable the general Shopify scanner.

The runner blocks mutation/action requests, websockets, foreign store/org routes,
unknown backend endpoints, and unknown persisted GraphQL operations. First-party
requests share a one-request-per-second limit. Rendering may therefore be partial;
blocked requests, failed navigation, or login redirects are not permission bypasses.
Reachability/HTTP 200 alone never confirms protected-data access or a vulnerability.
Use the report to select manual verification against the current program criteria.
