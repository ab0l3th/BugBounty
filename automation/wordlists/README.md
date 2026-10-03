# Discovery data

Vendored from [SecLists](https://github.com/danielmiessler/SecLists) at revision
`63802eeee4d5cb8791587bab59d78862ce381a32` under the included MIT license.

- `directories.txt`: `Discovery/Web-Content/common.txt`
- `vhosts.txt`: `Discovery/DNS/subdomains-top1million-5000.txt`
- `api-endpoints.txt`: `Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt`
- `api-prefixes.txt`: project-maintained application/API base paths, including root.

All valid entries are consumed without a count cutoff. Operators can replace
these lists using `BUGBOUNTY_DIRECTORIES_WORDLIST` and
`BUGBOUNTY_VHOSTS_WORDLIST` file paths. API lists can be replaced with
`BUGBOUNTY_API_ENDPOINTS_WORDLIST` and `BUGBOUNTY_API_PREFIXES_WORDLIST`.
Endpoints are combined with every prefix, then deduplicated. Custom directory
full paths are retained without an API-name filter. Wildcard vhost candidates must match
program scope; these lists never authorize additional domains or traffic rates.