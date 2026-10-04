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

Edge uses the installed Microsoft Edge application. To use the optional bundled
Chromium fallback instead, install its browser binary:

```sh
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

Capture each account separately. Edge is the default; the first capture creates a
separate persistent profile for that role and opens a visible Edge window:

```sh
.venv/bin/python automation/shopify_account_checks.py capture --role owner --browser edge
.venv/bin/python automation/shopify_account_checks.py capture --role appdev --browser edge
.venv/bin/python automation/shopify_account_checks.py run
```

The profiles are created under `.secrets/shopify-account-profiles/edge/owner`
and `.secrets/shopify-account-profiles/edge/appdev`. Log into the appropriate
account in each window, confirm the selected developer organization, then press
Enter in the terminal. The profile is reused by later `run` commands; it is not
exported as a cookie/storage-state JSON file. You do not need to create Edge
profiles manually. Keep the profile directories local, don't enable browser
sync for them, and never copy, share, or commit them. They contain reusable
authentication state and are owner-only under the ignored `.secrets/` directory.

Use `--browser chromium` only if you want Playwright's bundled Chromium instead.
Microsoft Edge must be installed for `--browser edge`; install the Playwright
Chromium binary only for the Chromium option. `run --headed` opens visible test
windows; otherwise checks use headless Edge with the same persistent profiles.

Login and MFA happen directly in the browser, with no credential entry in chat
or the terminal. Verify the account identity and assigned role before pressing
Enter; role labels are user attestations, not independently verified identities.
Capture permits your manual authentication flow; it is not an automated test.
Repeat `run` to refresh the comparison. If Shopify expires the session, rerun
`capture` for that role in the existing profile and complete login interactively;
the tool never bypasses passkeys, MFA, or CAPTCHA. Reports are owner-only JSON and Markdown under
`results/shopify-owned-account-checks.*`, with no raw text, screenshots, cookies,
local storage, or token/query values. These observations are not scanner findings
and do not trigger alerts or enable the general Shopify scanner.

The runner blocks mutation/action requests, websockets, foreign store/org routes,
unknown backend endpoints, and unknown persisted GraphQL operations. First-party
requests share a one-request-per-second limit. Rendering may therefore be partial;
blocked requests, failed navigation, or login redirects are not permission bypasses.
Reachability/HTTP 200 alone never confirms protected-data access or a vulnerability.
Use the report to select manual verification against the current program criteria.
