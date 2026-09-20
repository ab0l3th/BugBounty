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
