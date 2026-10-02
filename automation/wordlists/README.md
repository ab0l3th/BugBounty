# Discovery data

Vendored from [SecLists](https://github.com/danielmiessler/SecLists) at revision
`63802eeee4d5cb8791587bab59d78862ce381a32` under the included MIT license.

- `directories.txt`: `Discovery/Web-Content/common.txt`
- `vhosts.txt`: `Discovery/DNS/subdomains-top1million-5000.txt`

All valid entries are consumed without a count cutoff. Operators can replace
these lists using `BUGBOUNTY_DIRECTORIES_WORDLIST` and
`BUGBOUNTY_VHOSTS_WORDLIST` file paths. Wildcard vhost candidates must match
program scope; these lists never authorize additional domains or traffic rates.