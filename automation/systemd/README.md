# Systemd scheduling

This directory contains example systemd service and timer definitions for the BugBounty worker.

## Install

1. Copy the service and timer files into `/etc/systemd/system/`.
2. Reload systemd:
   ```bash
   sudo systemctl daemon-reload
   ```
3. Enable the timer:
   ```bash
   sudo systemctl enable --now bugbounty-worker.timer
   ```
4. Check status:
   ```bash
   sudo systemctl status bugbounty-worker.timer
   ```

## Notes

- The service calls the worker runner from the repo.
- The runner only accepts in-scope targets and writes results to `results/`.
- Notification is only emitted when results differ from the previous run.
- Do not enable active testing without explicit approval.
