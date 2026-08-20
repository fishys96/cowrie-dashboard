# Cowrie Attack Dashboard

A live, dark-themed operations dashboard for a [Cowrie](https://github.com/cowrie/cowrie)
SSH/Telnet honeypot: a 3D globe animates each incoming attack as an arc from the attacker's
geolocated IP to your honeypot, alongside a live event feed, top attackers, top credentials,
a 24h attack timeline, command activity, and a geo breakdown.

- **Backend:** FastAPI + WebSocket, tails `cowrie.json` in real time, geolocates IPs locally
  via MaxMind GeoLite2 (fully offline, no external API calls), keeps aggregates in memory and
  persists events to SQLite so a restart doesn't lose history.
- **Frontend:** a single static page (`globe.gl` + `Chart.js` via CDN, vanilla JS) served by
  the same backend.
- **Exposure:** binds to `127.0.0.1` by default -- view it over an SSH tunnel. No public web
  server required (an optional nginx/TLS snippet is included in `deploy/` if you later want
  public access).

New events appear on the globe and in every panel within ~2-3 seconds of hitting the log.

## Detection layer

The dashboard is passive telemetry -- it shows what the honeypot saw. [`wazuh/`](wazuh/) adds
the detection half: a Wazuh manager on a **separate** VM, a custom rule set that classifies
Cowrie activity by severity along the attacker's kill chain, and brute-force correlation.
Start at [`wazuh/README.md`](wazuh/README.md).

## 1. Prerequisites

- Python 3.10+
- Cowrie already running with JSON logging enabled (default: `cowrie.json`)
- A free [MaxMind](https://www.maxmind.com/en/geolite2/signup) account for GeoLite2 databases

## 2. Get the GeoLite2 databases

Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` (via the MaxMind account portal, or
`geoipupdate` if you have it configured) and place them in `geoip/`:

```
geoip/GeoLite2-City.mmdb
geoip/GeoLite2-ASN.mmdb
```

Without these files, the backend still runs -- attacks just won't have coordinates, so they'll
show up in the live feed but not on the globe.

## 3. Install dependencies

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 4. Configure

```bash
cp .env.example .env
```

Edit `.env`:

- `COWRIE_LOG_PATH` -- path to Cowrie's JSON log (e.g. `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`)
- `HONEYPOT_LAT` / `HONEYPOT_LON` / `HONEYPOT_LABEL` -- your Azure VPS's approximate location
  (used as the arc destination on the globe)
- `GEOIP_CITY_DB` / `GEOIP_ASN_DB` -- paths to the `.mmdb` files from step 2

## 5. Grant log read access

Cowrie's log is normally owned by the `cowrie` user. Give the account running the dashboard
read access, e.g.:

```bash
sudo usermod -aG cowrie <dashboard-user>
sudo chmod g+rx /home/cowrie/cowrie/var/log/cowrie
```

## 6. Run it

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8080
```

From your workstation, open an SSH tunnel to the VPS and browse locally:

```bash
ssh -L 8080:127.0.0.1:8080 user@your-vps
```

Then visit `http://localhost:8080`.

## 7. Try it without waiting for real attacks

`tools/simulate.py` appends realistic fake Cowrie events to a test log so you can see the
globe and panels light up immediately:

```bash
# terminal 1
COWRIE_LOG_PATH=./test_cowrie.json uvicorn backend.main:app --host 127.0.0.1 --port 8080

# terminal 2
python tools/simulate.py --log ./test_cowrie.json --interval 1.5
```

(On Windows, set the env var with `$env:COWRIE_LOG_PATH = "./test_cowrie.json"` in PowerShell,
or just set it in `.env`.)

## 8. Run as a systemd service (production)

See [`deploy/cowrie-dashboard.service`](deploy/cowrie-dashboard.service) -- copy it to
`/etc/systemd/system/`, adjust the paths/user, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-dashboard
journalctl -u cowrie-dashboard -f
```

The same file has a commented-out nginx + TLS + basic-auth block at the bottom, for anyone who
later wants the dashboard reachable outside an SSH tunnel.

## Project layout

```
backend/
  main.py      FastAPI app: static serving, /api/snapshot, /ws, startup tail task
  config.py    Settings loaded from .env
  parser.py    Raw Cowrie JSON line -> normalized event dict (+ eventid -> attack type/color)
  geo.py       MaxMind GeoLite2 City+ASN lookups (LRU-cached)
  tailer.py    Async log tail, tolerant of logrotate
  store.py     In-memory aggregates + SQLite persistence
frontend/
  index.html   Dashboard layout
  app.js       Globe (globe.gl), charts (Chart.js), WebSocket client, panel rendering
  style.css    Dark ops-display theme
tools/
  simulate.py  Fake attack traffic generator for local testing
deploy/
  cowrie-dashboard.service   systemd unit (+ optional nginx appendix)
wazuh/
  manager/     Wazuh rule set + Docker overrides for the SIEM VM
  agent/       Wazuh agent install/enrollment for the honeypot VM
  scripts/     stack setup, rule tests, end-to-end replay validation
  docs/        Azure VM provisioning + NSG rules
sample_cowrie.json           Example of real Cowrie event shapes
```

## Notes

- Single-worker by design (`uvicorn` default) -- aggregates live in one process's memory.
  This keeps resource use minimal, appropriate for running alongside Cowrie on a small VPS.
- Events without a resolvable public IP (private/reserved ranges, or missing GeoLite2 DBs)
  still appear in the feed and tables but are skipped on the globe.
- All configuration is via `.env` -- nothing is hardcoded, no secrets in source.
