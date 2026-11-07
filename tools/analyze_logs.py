#!/usr/bin/env python3
"""Generates a polished HTML report breaking down Cowrie honeypot activity across the FULL log
history: the current cowrie.json plus any rotated/compressed siblings (cowrie.json.1,
cowrie.json.2.gz, cowrie.json-20260701.gz, ...) sitting next to it.

This reads the raw log files directly rather than the dashboard's SQLite DB, because the DB only
contains events ingested while the dashboard process happened to be running -- over several weeks
of manual start/stop that has gaps. The log files (current + rotated) are the complete record.

Usage:
    python tools/analyze_logs.py                          # last 30 days, auto-detect log path
    python tools/analyze_logs.py --days 0                  # full available history, no cutoff
    python tools/analyze_logs.py --log /path/to/cowrie.json --out reports/my_report.html
    python tools/analyze_logs.py --no-geo                  # skip GeoLite2 lookups (faster)
    python tools/analyze_logs.py --days 0 --checkup        # full history + sensor health checks

Alongside the HTML it writes a same-named .json with the headline numbers, and (when the wazuh/
rule set is present) a retroactive pass of every event through those detection rules.
"""

import argparse
import gzip
import html
import importlib.util
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend import geo, parser  # noqa: E402
from backend.config import settings  # noqa: E402

TYPE_LABELS = {
    "connect": "Connect",
    "bruteforce": "Brute force",
    "login_success": "Login success",
    "command": "Command exec",
    "malware": "Malware / file",
    "other": "Other",
}
TYPE_COLORS = {t: c for t, c in ((v[0], v[1]) for v in parser.EVENT_TYPE_MAP.values())}
TYPE_COLORS[parser.DEFAULT_TYPE[0]] = parser.DEFAULT_TYPE[1]


class Report:
    def __init__(self):
        self.total_lines = 0
        self.total_events = 0
        self.first_ts: datetime | None = None
        self.last_ts: datetime | None = None

        self.attack_type_counts: Counter = Counter()
        self.daily_counts: dict[str, int] = defaultdict(int)
        self.hourly_counts: dict[int, int] = defaultdict(int)

        self.attacker_counts: Counter = Counter()
        self.attacker_types: dict[str, Counter] = defaultdict(Counter)
        self.attacker_first_seen: dict[str, str] = {}
        self.attacker_last_seen: dict[str, str] = {}

        self.credential_counts: Counter = Counter()
        self.username_counts: Counter = Counter()
        self.password_counts: Counter = Counter()
        self.command_counts: Counter = Counter()

        self.country_counts: Counter = Counter()
        self.country_names: dict[str, str] = {}
        self.asn_counts: Counter = Counter()

        self.protocol_counts: Counter = Counter()
        self.client_version_counts: Counter = Counter()
        self.session_durations: list[float] = []

        self.login_success = 0
        self.login_failed = 0

        self.download_urls: Counter = Counter()
        self.files_seen = 0

        # Long-horizon breakdowns (only meaningful once the sensor has months of history).
        self.monthly: dict[str, Counter] = defaultdict(Counter)
        self.monthly_ips: dict[str, set] = defaultdict(set)
        self.weekly_ips: dict[str, set] = defaultdict(set)  # keyed by ISO week's Monday
        self.ip_days: dict[str, set] = defaultdict(set)
        self.dow_hour: Counter = Counter()  # (weekday 0=Mon, hour) -> events
        self.success_credentials: Counter = Counter()
        self.malware_hashes: dict[str, dict] = {}

        # Retroactive detection: every event run through the Wazuh rule tree in
        # wazuh/manager/rules/local_rules.xml (see load_detection()).
        self.rule_counts: Counter = Counter()
        self.mitre_counts: Counter = Counter()
        self.bruteforce_alerts = 0
        self.bruteforce_ips: Counter = Counter()
        self._bf_windows: dict[str, deque] = defaultdict(deque)

        self._geo_cache: dict[str, dict] = {}


def discover_log_files(base_path: str) -> list[Path]:
    """Find the current log file plus any rotated/compressed siblings next to it."""
    base = Path(base_path)
    directory = base.parent
    if not directory.exists():
        return []
    return sorted(p for p in directory.glob(f"{base.name}*") if p.is_file())


def open_log_file(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Retroactive detection
# ---------------------------------------------------------------------------
# The Wazuh rule set is the single source of truth for "what counts as an alert". Rather than
# re-encoding it here, this reuses the same tree walker the offline rule test uses, so the
# report's detection numbers can never drift from the deployed rules.
RULES_XML = PROJECT_ROOT / "wazuh" / "manager" / "rules" / "local_rules.xml"
RULE_LOGIC = PROJECT_ROOT / "wazuh" / "scripts" / "test_rule_logic.py"

# Mirrors rule 100210: more than 8 failures from one source inside 120 seconds.
BF_FREQUENCY = 8
BF_TIMEFRAME = timedelta(seconds=120)
BF_SID = "100210"


class Detection:
    def __init__(self) -> None:
        spec = importlib.util.spec_from_file_location("wazuh_rule_logic", RULE_LOGIC)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.rules = mod.load_rules()
        self.resolve = mod.resolve

        self.meta: dict[str, dict] = {}
        for el in ET.parse(RULES_XML).getroot().findall("rule"):
            desc = el.findtext("description", "")
            self.meta[el.get("id")] = {
                "level": int(el.get("level")),
                # "$(src_ip)" placeholders are filled per-alert by Wazuh; show them generically.
                "description": re.sub(r"\$\((\w+)\)", r"<\1>", desc),
                "mitre": [m.text for m in el.findall("mitre/id")],
            }


def load_detection() -> "Detection | None":
    if not (RULES_XML.exists() and RULE_LOGIC.exists()):
        return None
    try:
        return Detection()
    except Exception as e:  # noqa: BLE001 - a broken rule file must not kill the report
        print(f"  ! detection section disabled, could not load rules: {e}")
        return None


def detect(raw: dict, ts: datetime, report: "Report", det: Detection) -> None:
    rule = det.resolve(raw, det.rules)
    if rule is not None and rule.level > 0:
        sid = str(rule.sid)
        report.rule_counts[sid] += 1
        for tid in det.meta.get(sid, {}).get("mitre", []):
            report.mitre_counts[tid] += 1

    # Stateful correlation the static walker can't do. Windows are reset per log file (see
    # main), so out-of-order files can't produce negative time deltas. Firing clears the
    # window, matching how Wazuh resets a frequency rule's counter after it alerts.
    if raw.get("eventid") == "cowrie.login.failed" and raw.get("src_ip"):
        window = report._bf_windows[raw["src_ip"]]
        window.append(ts)
        while window and ts - window[0] > BF_TIMEFRAME:
            window.popleft()
        if len(window) > BF_FREQUENCY:
            report.bruteforce_alerts += 1
            report.bruteforce_ips[raw["src_ip"]] += 1
            for tid in det.meta.get(BF_SID, {}).get("mitre", []):
                report.mitre_counts[tid] += 1
            window.clear()


# ---------------------------------------------------------------------------
# Health checks (--checkup)
# ---------------------------------------------------------------------------
# Every check degrades to "info: not available" rather than raising: the report must still
# render when run on a laptop, or as a user who can't read some of Cowrie's files.

def _run(cmd: list[str], timeout: float = 5) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _dir_size(path: Path) -> tuple[int, int] | None:
    try:
        total = count = 0
        for p in path.rglob("*"):
            if p.is_file():
                total += p.stat().st_size
                count += 1
        return total, count
    except OSError:
        return None


def _bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _listening(port: int) -> bool | None:
    out = _run(["ss", "-ltnH"])
    if out is None:
        return None
    return any(line.split()[3].endswith(f":{port}") for line in out.splitlines() if len(line.split()) > 3)


def _service_state(unit: str) -> str | None:
    """'active', 'inactive', 'failed', ..., or None when the unit doesn't exist / no systemd."""
    if shutil.which("systemctl") is None:
        return None
    exists = _run(["systemctl", "list-unit-files", f"{unit}.service", "--no-legend"])
    if not exists:
        return None
    return _run(["systemctl", "is-active", unit]) or "unknown"


def run_health_checks(log_path: str, files: list[Path], report: "Report") -> list[dict]:
    checks: list[dict] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    on_linux = sys.platform.startswith("linux")
    log_dir = Path(log_path).parent
    # .../cowrie/var/log/cowrie/cowrie.json -> .../cowrie
    cowrie_root = Path(log_path).resolve().parents[3] if len(Path(log_path).resolve().parents) > 3 else None

    # 1. Is the sensor still being hit? A public SSH honeypot that goes quiet for hours is
    #    almost always broken (Cowrie crashed, port remapped, NSG changed), not "no attackers".
    if report.last_ts:
        age = datetime.now(timezone.utc) - report.last_ts
        hours = age.total_seconds() / 3600
        when = f"last event {report.last_ts.strftime('%Y-%m-%d %H:%M UTC')} ({fmt_duration(age.total_seconds())} ago)"
        if hours < 1:
            add("Traffic freshness", "ok", when)
        elif hours < 6:
            add("Traffic freshness", "warn", when + " - unusually quiet for an exposed honeypot")
        else:
            add("Traffic freshness", "fail", when + " - Cowrie is likely down or unreachable")

    # 2. Cowrie process + its listener.
    if on_linux:
        pid = None
        pidfile = cowrie_root / "var" / "run" / "cowrie.pid" if cowrie_root else None
        try:
            if pidfile and pidfile.exists():
                pid = int(pidfile.read_text().strip())
                if not Path(f"/proc/{pid}").exists():
                    pid = None
        except (OSError, ValueError):
            pid = None
        if pid is None:
            # twistd is Cowrie's runner; matching "cowrie" would also match this very process.
            pids = [p for p in (_run(["pgrep", "-f", "twistd"]) or "").split() if p != str(os.getpid())]
            pid = int(pids[0]) if pids else None
        listening22 = _listening(22)
        if pid and listening22 is not False:
            add("Cowrie process", "ok", f"running (pid {pid}), port 22 listening")
        elif pid:
            add("Cowrie process", "warn", f"running (pid {pid}) but nothing is listening on port 22")
        else:
            add("Cowrie process", "fail", "no Cowrie/twistd process found")
    else:
        add("Cowrie process", "info", "not available on this system")

    # 3. Disk headroom, and how long it lasts at the observed log growth rate.
    try:
        du = shutil.disk_usage(log_dir)
        used_pct = du.used / du.total * 100
        status = "ok" if used_pct < 80 else "warn" if used_pct < 90 else "fail"
        add("Disk usage", status, f"{used_pct:.0f}% used, {_bytes(du.free)} free of {_bytes(du.total)}")
    except OSError:
        du = None
        add("Disk usage", "info", "could not stat the log filesystem")

    log_bytes = sum(f.stat().st_size for f in files if f.exists())
    span_days = max(1, (report.last_ts - report.first_ts).days + 1) if report.first_ts and report.last_ts else 1
    per_day = log_bytes / span_days
    detail = f"{len(files)} file(s), {_bytes(log_bytes)} total, ~{_bytes(per_day)}/day"
    if du and per_day > 0:
        runway = du.free / per_day
        detail += f" - ~{runway:,.0f} days of disk left at this rate"
        status = "ok" if runway > 90 else "warn" if runway > 30 else "fail"
    else:
        status = "info"
    oldest = report.first_ts.strftime("%Y-%m-%d") if report.first_ts else "?"
    add("Log storage", status, f"{detail}. Oldest retained event: {oldest}")

    # 4. Captured payloads.
    dl = cowrie_root / "var" / "lib" / "cowrie" / "downloads" if cowrie_root else None
    if dl and dl.exists():
        size = _dir_size(dl)
        if size:
            add("Captured payloads", "info", f"{size[1]:,} file(s), {_bytes(size[0])} in {dl}")
        else:
            add("Captured payloads", "info", f"{dl} exists but is not readable by this user")
    else:
        add("Captured payloads", "info", "downloads directory not found")

    # 5. Live dashboard. Not running is only a warning: the backlog catch-up replays whatever
    #    it missed the next time it starts.
    if on_linux:
        state = _service_state("cowrie-dashboard")
        port = _listening(8080)
        if state == "active" or port:
            how = "systemd service active" if state == "active" else "listening on 8080 (not a systemd service)"
            add("Live dashboard", "ok", how)
        else:
            add("Live dashboard", "warn", "not running - it will catch up on missed events when restarted")
    db = PROJECT_ROOT / "data" / "dashboard.db"
    if db.exists():
        add("Dashboard database", "info", f"{_bytes(db.stat().st_size)} at {db}")

    # 6. Detection layer.
    if on_linux:
        state = _service_state("wazuh-agent")
        if state is None:
            add("Wazuh agent", "info", "not installed - detection layer not deployed yet (see wazuh/README.md)")
        elif state == "active":
            add("Wazuh agent", "ok", "active - confirm it shows connected in the Wazuh dashboard")
        else:
            add("Wazuh agent", "fail", f"installed but {state}")

    # 7. Host.
    if on_linux:
        try:
            uptime_s = float(Path("/proc/uptime").read_text().split()[0])
            load1, load5, load15 = os.getloadavg()
            mem = {k: int(v.split()[0]) for k, v in
                   (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())}
            avail_pct = mem["MemAvailable"] / mem["MemTotal"] * 100
            status = "ok" if avail_pct > 15 else "warn"
            add("Host", status, f"up {fmt_duration(uptime_s)}, load {load1:.2f}/{load5:.2f}/{load15:.2f}, "
                                f"{avail_pct:.0f}% memory available")
        except (OSError, KeyError, ValueError):
            add("Host", "info", "could not read /proc")
        if Path("/var/run/reboot-required").exists():
            add("Pending reboot", "warn", "the OS has installed updates that need a reboot")

    return checks

def process_line(raw_line: str, report: Report, cutoff_ts: datetime | None, do_geo: bool,
                 det: Detection | None = None) -> None:
    line = raw_line.strip()
    if not line:
        return
    report.total_lines += 1

    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return

    ts_raw = raw.get("timestamp")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else None
    except (ValueError, AttributeError):
        ts = None
    if ts is None:
        return
    if cutoff_ts is not None and ts < cutoff_ts:
        return

    if report.first_ts is None or ts < report.first_ts:
        report.first_ts = ts
    if report.last_ts is None or ts > report.last_ts:
        report.last_ts = ts

    eventid = raw.get("eventid", "")

    if det is not None:
        detect(raw, ts, report, det)

    # Bonus fields not surfaced by the live dashboard, but valuable in a historical report.
    if eventid == "cowrie.session.closed":
        dur = raw.get("duration")
        if isinstance(dur, (int, float)):
            report.session_durations.append(float(dur))
        return

    if eventid == "cowrie.client.version":
        version = raw.get("version")
        if version:
            report.client_version_counts[version] += 1
        return

    if eventid not in parser.DISPLAYED_EVENTS:
        return

    src_ip = raw.get("src_ip")
    if not src_ip:
        return

    attack_type, _color = parser.EVENT_TYPE_MAP.get(eventid, parser.DEFAULT_TYPE)

    report.total_events += 1
    report.attack_type_counts[attack_type] += 1
    report.daily_counts[ts.strftime("%Y-%m-%d")] += 1
    report.hourly_counts[ts.hour] += 1

    day = ts.strftime("%Y-%m-%d")
    month = ts.strftime("%Y-%m")
    report.monthly[month]["events"] += 1
    report.monthly_ips[month].add(src_ip)
    report.weekly_ips[(ts.date() - timedelta(days=ts.weekday())).isoformat()].add(src_ip)
    report.ip_days[src_ip].add(day)
    report.dow_hour[(ts.weekday(), ts.hour)] += 1

    report.attacker_counts[src_ip] += 1
    report.attacker_types[src_ip][attack_type] += 1
    ts_iso = ts.isoformat()
    if src_ip not in report.attacker_first_seen or ts_iso < report.attacker_first_seen[src_ip]:
        report.attacker_first_seen[src_ip] = ts_iso
    if src_ip not in report.attacker_last_seen or ts_iso > report.attacker_last_seen[src_ip]:
        report.attacker_last_seen[src_ip] = ts_iso

    if eventid == "cowrie.session.connect":
        protocol = raw.get("protocol")
        if protocol:
            report.protocol_counts[protocol] += 1

    if eventid in ("cowrie.login.failed", "cowrie.login.success"):
        username, password = raw.get("username") or "", raw.get("password") or ""
        report.credential_counts[(username, password)] += 1
        report.username_counts[username] += 1
        report.password_counts[password] += 1
        if eventid == "cowrie.login.failed":
            report.login_failed += 1
            report.monthly[month]["login_failed"] += 1
        else:
            report.login_success += 1
            report.monthly[month]["login_success"] += 1
            report.success_credentials[(username, password)] += 1

    if eventid == "cowrie.command.input":
        cmd = raw.get("input")
        if cmd:
            report.command_counts[cmd] += 1
            report.monthly[month]["commands"] += 1

    if eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        report.files_seen += 1
        report.monthly[month]["files"] += 1
        url = raw.get("url")
        if url:
            report.download_urls[url] += 1
        sha = raw.get("shasum")
        if sha:
            entry = report.malware_hashes.setdefault(
                sha, {"count": 0, "first_seen": ts.isoformat(), "source": url or raw.get("filename") or "", "ips": set()}
            )
            entry["count"] += 1
            entry["ips"].add(src_ip)
            if ts.isoformat() < entry["first_seen"]:
                entry["first_seen"] = ts.isoformat()

    if do_geo:
        g = report._geo_cache.get(src_ip)
        if g is None:
            g = geo.lookup(src_ip) or {}
            report._geo_cache[src_ip] = g
        if g.get("country_code"):
            report.country_counts[g["country_code"]] += 1
            report.country_names[g["country_code"]] = g.get("country") or g["country_code"]
        if g.get("asn"):
            report.asn_counts[(g["asn"], g.get("as_org") or "")] += 1


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def js(value) -> str:
    """JSON-encode for embedding in a <script> tag, safe against premature tag closure."""
    return json.dumps(value).replace("</script>", "<\\/script>")


def pct(n: int, total: int) -> str:
    return f"{(n / total * 100):.1f}%" if total else "0.0%"


def fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


MITRE_NAMES = {
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1078": "Valid Accounts",
    "T1059.004": "Command & Scripting: Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1082": "System Information Discovery",
    "T1087": "Account Discovery",
    "T1070.003": "Clear Command History",
    "T1053": "Scheduled Task/Job",
}

# Status palette (dataviz reference): reserved for state, always paired with icon + label.
STATUS_STYLE = {
    "ok": ("#0ca30c", "✓", "OK"),
    "warn": ("#fab219", "!", "Warning"),
    "fail": ("#d03b3b", "✕", "Problem"),
    "info": ("#898781", "i", "Info"),
}

# Dark-mode sequential blue ramp, near-zero -> max. Near-zero recedes toward the dark surface.
HEAT_RAMP = ["#0d366b", "#104281", "#184f95", "#1c5cab", "#256abf", "#2a78d6",
             "#3987e5", "#5598e7", "#6da7ec", "#86b6ef", "#9ec5f4", "#b7d3f6"]
DOW = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def severity_band(level: int) -> tuple[str, str]:
    """Wazuh level -> (label, status color). Low severity is deliberately neutral, not 'good'."""
    if level >= 12:
        return "critical", STATUS_STYLE["fail"][0]
    if level >= 10:
        return "high", "#ec835a"
    if level >= 5:
        return "medium", STATUS_STYLE["warn"][0]
    return "low", STATUS_STYLE["info"][0]


def month_days_covered(month: str, first: datetime, last: datetime) -> float:
    """Observed time within the month, in fractional days. Counting a few hours of today as a
    whole day would make the current month look artificially quiet."""
    start = datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
    nxt = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    lo, hi = max(start, first), min(nxt, last)
    return max(1 / 24, (hi - lo).total_seconds() / 86400)


def build_monthly(report: Report) -> list[dict]:
    rows = []
    prev_rate = None
    for month in sorted(report.monthly):
        c = report.monthly[month]
        days = month_days_covered(month, report.first_ts, report.last_ts)
        rate = c["events"] / days
        start = datetime.strptime(month, "%Y-%m").date()
        full_days = ((start.replace(day=28) + timedelta(days=4)).replace(day=1) - start).days
        rows.append({
            "month": month,
            "label": start.strftime("%b %Y"),
            "partial": days < full_days - 0.5,
            "days": round(days, 1),
            "events": c["events"],
            "per_day": rate,
            "change": None if prev_rate in (None, 0) else (rate - prev_rate) / prev_rate * 100,
            "unique_ips": len(report.monthly_ips[month]),
            "login_failed": c["login_failed"],
            "login_success": c["login_success"],
            "commands": c["commands"],
            "files": c["files"],
        })
        prev_rate = rate
    return rows


def build_weekly(report: Report) -> list[dict]:
    first_week = {}
    for ip, iso in report.attacker_first_seen.items():
        d = datetime.fromisoformat(iso).date()
        first_week[ip] = (d - timedelta(days=d.weekday())).isoformat()
    rows = []
    for week in sorted(report.weekly_ips):
        ips = report.weekly_ips[week]
        new = sum(1 for ip in ips if first_week.get(ip) == week)
        rows.append({"week": week, "new": new, "returning": len(ips) - new})
    return rows


def render_health(health: list[dict] | None) -> str:
    if not health:
        return ""
    counts = Counter(h["status"] for h in health)
    worst = "fail" if counts["fail"] else "warn" if counts["warn"] else "ok"
    color, icon, _ = STATUS_STYLE[worst]
    headline = {"ok": "All checks passed", "warn": f"{counts['warn']} warning(s)",
                "fail": f"{counts['fail']} problem(s) need attention"}[worst]
    items = []
    for h in health:
        c, i, label = STATUS_STYLE[h["status"]]
        items.append(
            f'<div class="check"><span class="status-chip" style="border-color:{c}">'
            f'<span class="status-icon" style="background:{c}">{i}</span>{label}</span>'
            f'<div><div class="check-name">{esc(h["name"])}</div>'
            f'<div class="check-detail">{esc(h["detail"])}</div></div></div>'
        )
    return f"""
<div class="section">
  <h2>Sensor health</h2>
  <div class="panel">
    <div class="health-headline"><span class="status-icon big" style="background:{color}">{icon}</span>{esc(headline)}</div>
    <div class="checks">{''.join(items)}</div>
  </div>
</div>"""


def render_heatmap(report: Report) -> str:
    peak = max(report.dow_hour.values(), default=0)
    cells = ['<div class="hm-corner"></div>'] + [f'<div class="hm-hour">{h:02d}</div>' for h in range(24)]
    for d in range(7):
        cells.append(f'<div class="hm-day">{DOW[d]}</div>')
        for h in range(24):
            v = report.dow_hour.get((d, h), 0)
            if v == 0 or peak == 0:
                bg = "#202020"
            else:
                bg = HEAT_RAMP[min(len(HEAT_RAMP) - 1, int(v / peak * len(HEAT_RAMP)))]
            cells.append(f'<div class="hm-cell" style="background:{bg}" title="{DOW[d]} {h:02d}:00 UTC - {v:,} events"></div>')
    legend = "".join(f'<span style="background:{c}"></span>' for c in HEAT_RAMP)
    return (f'<div class="heatmap">{"".join(cells)}</div>'
            f'<div class="hm-legend">fewer <span class="hm-ramp">{legend}</span> more · hover a cell for its count</div>')


def render_detection(report: Report, det: Detection | None) -> str:
    if det is None:
        return ""
    total_alerts = sum(report.rule_counts.values()) + report.bruteforce_alerts
    high = sum(c for sid, c in report.rule_counts.items() if det.meta[sid]["level"] >= 10) + report.bruteforce_alerts

    rows = []
    counts = dict(report.rule_counts)
    counts[BF_SID] = report.bruteforce_alerts
    for sid, meta in sorted(det.meta.items(), key=lambda kv: (-kv[1]["level"], kv[0])):
        if meta["level"] == 0:
            continue
        n = counts.get(sid, 0)
        band, color = severity_band(meta["level"])
        mitre = ", ".join(meta["mitre"]) or "—"
        rows.append(
            f'<tr><td class="mono">{sid}</td>'
            f'<td><span class="sev-chip" style="border-color:{color}"><span class="sev-dot" style="background:{color}"></span>L{meta["level"]} · {band}</span></td>'
            f'<td>{esc(meta["description"])}</td><td class="mono">{esc(mitre)}</td>'
            f'<td class="num">{n:,}</td><td class="num">{pct(n, total_alerts)}</td></tr>'
        )

    mitre_rows = "".join(
        f'<tr><td class="mono">{esc(tid)}</td><td>{esc(MITRE_NAMES.get(tid, ""))}</td><td class="num">{c:,}</td></tr>'
        for tid, c in report.mitre_counts.most_common()
    ) or '<tr><td colspan="3" class="empty">No technique hits</td></tr>'

    bf_rows = "".join(
        f'<tr><td>{i}</td><td class="mono">{esc(ip)}</td><td class="num">{c:,}</td>'
        f'<td class="num">{report.attacker_counts.get(ip, 0):,}</td></tr>'
        for i, (ip, c) in enumerate(report.bruteforce_ips.most_common(15), 1)
    ) or '<tr><td colspan="4" class="empty">No source crossed the brute-force threshold</td></tr>'

    return f"""
<div class="section">
  <h2>Detection coverage — Wazuh rule set, run retroactively</h2>
  <p class="note">Every historical event replayed through the rules in <span class="mono">wazuh/manager/rules/local_rules.xml</span>,
  using the same tree walk as the offline rule test. These are the alerts the detection layer <em>would</em> have raised —
  not alerts Wazuh actually produced. Level-0 events (connections closing, client banners, key exchange) are matched but never alert.
  Brute force uses the same &gt;{BF_FREQUENCY}-in-{int(BF_TIMEFRAME.total_seconds())}s window as rule {BF_SID}.</p>
  <div class="stat-row">
    <div class="stat-tile"><div class="value">{total_alerts:,}</div><div class="label">Alerts that would fire</div></div>
    <div class="stat-tile"><div class="value">{high:,}</div><div class="label">High or critical (L10+)</div></div>
    <div class="stat-tile"><div class="value">{report.bruteforce_alerts:,}</div><div class="label">Brute-force alerts</div></div>
    <div class="stat-tile"><div class="value">{len(report.bruteforce_ips):,}</div><div class="label">IPs that brute-forced</div></div>
  </div>
  <div class="panel table-scroll"><table>
    <thead><tr><th>Rule</th><th>Severity</th><th>Description</th><th>MITRE</th><th>Hits</th><th>Share</th></tr></thead>
    <tbody>{''.join(rows)}</tbody></table></div>
</div>
<div class="section grid-2">
  <div><h2>MITRE ATT&amp;CK techniques observed</h2>
    <div class="panel table-scroll"><table><thead><tr><th>ID</th><th>Technique</th><th>Hits</th></tr></thead><tbody>{mitre_rows}</tbody></table></div></div>
  <div><h2>Most brute-force alerts by source</h2>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>IP</th><th>Alerts</th><th>Events</th></tr></thead><tbody>{bf_rows}</tbody></table></div></div>
</div>"""


def render_html(report: Report, period_days: int | None, health: list[dict] | None = None,
                det: Detection | None = None) -> str:
    total = report.total_events
    unique_attackers = len(report.attacker_counts)
    period_start = report.first_ts.strftime("%Y-%m-%d") if report.first_ts else "—"
    period_end = report.last_ts.strftime("%Y-%m-%d") if report.last_ts else "—"
    span_days = (report.last_ts - report.first_ts).days + 1 if report.first_ts and report.last_ts else 0

    # Continuous daily timeline (zero-filled gaps) for an honest line chart.
    daily_labels: list[str] = []
    daily_values: list[int] = []
    if report.first_ts and report.last_ts:
        d = report.first_ts.date()
        end = report.last_ts.date()
        while d <= end:
            key = d.strftime("%Y-%m-%d")
            daily_labels.append(d.strftime("%b %d"))
            daily_values.append(report.daily_counts.get(key, 0))
            d += timedelta(days=1)

    type_rows = sorted(report.attack_type_counts.items(), key=lambda kv: kv[1], reverse=True)
    type_labels_js = [TYPE_LABELS.get(t, t) for t, _ in type_rows]
    type_values_js = [c for _, c in type_rows]
    type_colors_js = [TYPE_COLORS.get(t, "#898781") for t, _ in type_rows]

    hourly_values = [report.hourly_counts.get(h, 0) for h in range(24)]
    hourly_labels = [f"{h:02d}" for h in range(24)]

    top_attackers = report.attacker_counts.most_common(30)
    top_credentials = report.credential_counts.most_common(20)
    top_usernames = report.username_counts.most_common(15)
    top_passwords = report.password_counts.most_common(15)
    top_commands = report.command_counts.most_common(25)
    top_countries = report.country_counts.most_common(20)
    top_asns = report.asn_counts.most_common(15)
    top_versions = report.client_version_counts.most_common(15)
    top_downloads = report.download_urls.most_common(15)

    cred_chart_labels = [f"{u or '(blank)'} / {p or '(blank)'}"[:40] for (u, p), _ in top_credentials[:15]]
    cred_chart_values = [c for _, c in top_credentials[:15]]

    country_chart_labels = [report.country_names.get(cc, cc) for cc, _ in top_countries[:12]]
    country_chart_values = [c for _, c in top_countries[:12]]

    dur_count = len(report.session_durations)
    dur_avg = statistics.mean(report.session_durations) if dur_count else 0
    dur_median = statistics.median(report.session_durations) if dur_count else 0
    dur_max = max(report.session_durations) if dur_count else 0

    login_total = report.login_success + report.login_failed

    def attacker_rows_html() -> str:
        rows = []
        max_count = top_attackers[0][1] if top_attackers else 1
        for i, (ip, count) in enumerate(top_attackers, 1):
            top_type = report.attacker_types[ip].most_common(1)[0][0] if report.attacker_types[ip] else "other"
            color = TYPE_COLORS.get(top_type, "#898781")
            width = max(4, round(count / max_count * 100))
            rows.append(
                f'<tr><td>{i}</td><td class="mono">{esc(ip)}</td>'
                f'<td><span class="type-chip" style="background:{color}22;color:{color}">{esc(TYPE_LABELS.get(top_type, top_type))}</span></td>'
                f'<td>{esc(report.attacker_first_seen.get(ip, "—")[:19])}</td>'
                f'<td>{esc(report.attacker_last_seen.get(ip, "—")[:19])}</td>'
                f'<td class="num">{count:,}<div class="mini-bar"><div style="width:{width}%;background:{color}"></div></div></td></tr>'
            )
        return "\n".join(rows) if rows else '<tr><td colspan="6" class="empty">No attacker data</td></tr>'

    def simple_table(rows, cols) -> str:
        if not rows:
            return '<tr><td colspan="99" class="empty">No data</td></tr>'
        out = []
        for cells in cols(rows):
            out.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
        return "\n".join(out)

    credential_rows = simple_table(
        top_credentials,
        lambda rows: [
            (i, f'<span class="mono">{esc(u or "(blank)")}</span>', f'<span class="mono">{esc(p or "(blank)")}</span>', f'<span class="num">{c:,}</span>')
            for i, ((u, p), c) in enumerate(rows, 1)
        ],
    )
    username_rows = simple_table(
        top_usernames,
        lambda rows: [(i, f'<span class="mono">{esc(u or "(blank)")}</span>', f'<span class="num">{c:,}</span>') for i, (u, c) in enumerate(rows, 1)],
    )
    password_rows = simple_table(
        top_passwords,
        lambda rows: [(i, f'<span class="mono">{esc(p or "(blank)")}</span>', f'<span class="num">{c:,}</span>') for i, (p, c) in enumerate(rows, 1)],
    )
    command_rows = simple_table(
        top_commands,
        lambda rows: [(i, f'<span class="mono">{esc(cmd)}</span>', f'<span class="num">{c:,}</span>') for i, (cmd, c) in enumerate(rows, 1)],
    )
    country_rows = simple_table(
        top_countries,
        lambda rows: [
            (i, esc(report.country_names.get(cc, cc)), esc(cc), f'<span class="num">{c:,}</span>')
            for i, (cc, c) in enumerate(rows, 1)
        ],
    )
    asn_rows = simple_table(
        top_asns,
        lambda rows: [
            (i, f'<span class="mono">AS{asn}</span>', esc(org or "—"), f'<span class="num">{c:,}</span>')
            for i, ((asn, org), c) in enumerate(rows, 1)
        ],
    )
    version_rows = simple_table(
        top_versions,
        lambda rows: [(i, f'<span class="mono">{esc(v)}</span>', f'<span class="num">{c:,}</span>') for i, (v, c) in enumerate(rows, 1)],
    )
    download_rows = simple_table(
        top_downloads,
        lambda rows: [(i, f'<span class="mono">{esc(u)}</span>', f'<span class="num">{c:,}</span>') for i, (u, c) in enumerate(rows, 1)],
    )
    protocol_rows = simple_table(
        report.protocol_counts.most_common(),
        lambda rows: [(esc(p.upper()), f'<span class="num">{c:,}</span>', pct(c, sum(report.protocol_counts.values()))) for p, c in rows],
    )

    # --- long-horizon sections ---------------------------------------------------------
    monthly = build_monthly(report)
    max_month_rate = max((m["per_day"] for m in monthly), default=1) or 1
    month_rows = []
    for m in monthly:
        change = "—" if m["change"] is None else f'{"+" if m["change"] >= 0 else ""}{m["change"]:.0f}%'
        width = max(4, round(m["per_day"] / max_month_rate * 100))
        partial = f' <span class="muted">(partial, {m["days"]}d)</span>' if m["partial"] else ""
        month_rows.append(
            f'<tr><td>{esc(m["label"])}{partial}</td>'
            f'<td class="num">{m["events"]:,}</td>'
            f'<td class="num">{m["per_day"]:,.0f}<div class="mini-bar"><div style="width:{width}%;background:#3987e5"></div></div></td>'
            f'<td class="num">{change}</td>'
            f'<td class="num">{m["unique_ips"]:,}</td><td class="num">{m["login_failed"]:,}</td>'
            f'<td class="num">{m["login_success"]:,}</td><td class="num">{m["commands"]:,}</td><td class="num">{m["files"]:,}</td></tr>'
        )
    month_rows_html = "\n".join(month_rows) or '<tr><td colspan="9" class="empty">No data</td></tr>'

    weekly = build_weekly(report)
    week_labels = [datetime.fromisoformat(w["week"]).strftime("%b %d") for w in weekly]
    week_new = [w["new"] for w in weekly]
    week_returning = [w["returning"] for w in weekly]
    total_returning_share = pct(sum(week_returning), sum(week_new) + sum(week_returning))

    days_observed = len(report.daily_counts)
    per_day_avg = total / days_observed if days_observed else 0
    busiest_day = max(report.daily_counts.items(), key=lambda kv: kv[1]) if report.daily_counts else ("—", 0)

    persistent = sorted(report.ip_days.items(), key=lambda kv: (len(kv[1]), report.attacker_counts[kv[0]]), reverse=True)[:20]
    one_day_share = pct(sum(1 for d in report.ip_days.values() if len(d) == 1), len(report.ip_days))
    persistent_rows = simple_table(
        persistent,
        lambda rows: [
            (i, f'<span class="mono">{esc(ip)}</span>',
             esc(report.country_names.get((report._geo_cache.get(ip) or {}).get("country_code", ""), "—")),
             f'<span class="num">{len(days):,}</span>',
             esc(report.attacker_first_seen.get(ip, "—")[:10]), esc(report.attacker_last_seen.get(ip, "—")[:10]),
             f'<span class="num">{report.attacker_counts[ip]:,}</span>')
            for i, (ip, days) in enumerate(rows, 1)
        ],
    )

    success_rows = simple_table(
        report.success_credentials.most_common(15),
        lambda rows: [
            (i, f'<span class="mono">{esc(u or "(blank)")}</span>', f'<span class="mono">{esc(p or "(blank)")}</span>', f'<span class="num">{c:,}</span>')
            for i, ((u, p), c) in enumerate(rows, 1)
        ],
    )

    hashes = sorted(report.malware_hashes.items(), key=lambda kv: kv[1]["count"], reverse=True)[:25]
    hash_rows = simple_table(
        hashes,
        lambda rows: [
            (i, f'<span class="mono" title="{esc(sha)}">{esc(sha[:16])}…</span>',
             esc(info["first_seen"][:10]), f'<span class="num">{info["count"]:,}</span>',
             f'<span class="num">{len(info["ips"]):,}</span>', f'<span class="mono">{esc(info["source"][:70])}</span>')
            for i, (sha, info) in enumerate(rows, 1)
        ],
    )

    window_label = f"last {period_days} days" if period_days else "full available history"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Cowrie Attack Report — {esc(period_start)} to {esc(period_end)}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%9B%B0%EF%B8%8F%3C/text%3E%3C/svg%3E" />
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
:root {{
  --page-plane: #0d0d0d;
  --surface-1: #1a1a19;
  --surface-2: #202020;
  --text-primary: #ffffff;
  --text-secondary: #c3c2b7;
  --text-muted: #898781;
  --gridline: #2c2c2a;
  --border: rgba(255,255,255,0.10);
  --font: system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; background: var(--page-plane); color: var(--text-primary); font-family: var(--font); }}
.wrap {{ max-width: 1280px; margin: 0 auto; padding: 28px 20px 60px; }}
header {{ margin-bottom: 28px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }}
.subtitle {{ color: var(--text-muted); font-size: 13px; }}
.stat-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 22px 0; }}
.stat-tile {{ background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }}
.stat-tile .value {{ font-size: 24px; font-weight: 700; font-variant-numeric: tabular-nums; }}
.stat-tile .label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: .04em; margin-top: 2px; }}
.section {{ margin: 34px 0; }}
.section h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: .05em; color: var(--text-secondary); border-bottom: 1px solid var(--gridline); padding-bottom: 8px; margin-bottom: 14px; }}
.grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
.grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }}
@media (max-width: 900px) {{ .grid-2, .grid-3 {{ grid-template-columns: 1fr; }} }}
.panel {{ background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }}
.chart-box {{ position: relative; height: 280px; }}
.chart-box.tall {{ height: 360px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
th {{ text-align: left; color: var(--text-muted); font-weight: 500; text-transform: uppercase; font-size: 10.5px; letter-spacing: .04em; padding: 6px 8px; border-bottom: 1px solid var(--gridline); }}
td {{ padding: 6px 8px; border-bottom: 1px solid var(--gridline); color: var(--text-secondary); }}
.mono {{ font-family: var(--mono); color: var(--text-primary); }}
.num {{ text-align: right; color: var(--text-primary); font-variant-numeric: tabular-nums; white-space: nowrap; }}
.mini-bar {{ height: 3px; background: var(--gridline); border-radius: 2px; margin-top: 4px; overflow: hidden; }}
.mini-bar div {{ height: 100%; }}
.type-chip {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }}
.table-scroll {{ max-height: 420px; overflow-y: auto; }}
.empty {{ color: var(--text-muted); text-align: center; padding: 16px; }}
footer {{ margin-top: 40px; color: var(--text-muted); font-size: 11.5px; text-align: center; }}
.muted {{ color: var(--text-muted); font-size: 11px; }}
.note {{ color: var(--text-muted); font-size: 12.5px; line-height: 1.55; max-width: 900px; margin: -4px 0 14px; }}
.health-headline {{ display: flex; align-items: center; gap: 10px; font-size: 15px; font-weight: 600; margin-bottom: 14px; }}
.checks {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 10px 22px; }}
.check {{ display: flex; gap: 12px; align-items: flex-start; padding: 8px 0; border-top: 1px solid var(--gridline); }}
.check-name {{ font-weight: 600; font-size: 13px; }}
.check-detail {{ color: var(--text-secondary); font-size: 12.5px; margin-top: 2px; line-height: 1.45; }}
.status-chip, .sev-chip {{ display: inline-flex; align-items: center; gap: 6px; border: 1px solid; border-radius: 10px; padding: 2px 8px 2px 3px; font-size: 11px; font-weight: 600; color: var(--text-primary); white-space: nowrap; min-width: 84px; }}
.sev-chip {{ padding-left: 7px; min-width: 0; }}
.status-icon {{ display: inline-grid; place-items: center; width: 16px; height: 16px; border-radius: 50%; color: #0d0d0d; font-size: 10px; font-weight: 800; }}
.status-icon.big {{ width: 22px; height: 22px; font-size: 13px; }}
.sev-dot {{ width: 8px; height: 8px; border-radius: 50%; }}
.heatmap {{ display: grid; grid-template-columns: 34px repeat(24, 1fr); gap: 2px; }}
.hm-cell {{ aspect-ratio: 1.6; border-radius: 3px; min-height: 14px; }}
.hm-hour, .hm-day {{ color: var(--text-muted); font-size: 10px; text-align: center; align-self: center; }}
.hm-day {{ text-align: left; }}
.hm-legend {{ color: var(--text-muted); font-size: 11px; margin-top: 10px; display: flex; align-items: center; gap: 6px; }}
.hm-ramp {{ display: inline-flex; gap: 1px; }}
.hm-ramp span {{ width: 12px; height: 8px; border-radius: 2px; }}
.chart-scroll {{ overflow-x: auto; }}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>🛰 Cowrie Attack Report</h1>
  <div class="subtitle">{esc(period_start)} → {esc(period_end)} ({span_days} day span, {esc(window_label)}) · generated {esc(generated_at)}</div>
</header>

<div class="stat-row">
  <div class="stat-tile"><div class="value">{total:,}</div><div class="label">Total events</div></div>
  <div class="stat-tile"><div class="value">{unique_attackers:,}</div><div class="label">Unique attackers</div></div>
  <div class="stat-tile"><div class="value">{report.login_failed:,}</div><div class="label">Login attempts</div></div>
  <div class="stat-tile"><div class="value">{pct(report.login_success, login_total)}</div><div class="label">Login success rate</div></div>
  <div class="stat-tile"><div class="value">{len(report.command_counts):,}</div><div class="label">Unique commands</div></div>
  <div class="stat-tile"><div class="value">{report.files_seen:,}</div><div class="label">Malware/file events</div></div>
</div>
<div class="stat-row">
  <div class="stat-tile"><div class="value">{days_observed:,}</div><div class="label">Days observed</div></div>
  <div class="stat-tile"><div class="value">{per_day_avg:,.0f}</div><div class="label">Avg events / day</div></div>
  <div class="stat-tile"><div class="value">{busiest_day[1]:,}</div><div class="label">Busiest day ({esc(busiest_day[0])})</div></div>
  <div class="stat-tile"><div class="value">{report.login_success:,}</div><div class="label">Successful logins</div></div>
  <div class="stat-tile"><div class="value">{len(report.malware_hashes):,}</div><div class="label">Unique payload hashes</div></div>
  <div class="stat-tile"><div class="value">{total_returning_share}</div><div class="label">Weekly activity from repeat IPs</div></div>
</div>

{render_health(health)}

<div class="section">
  <h2>Attack volume over time</h2>
  <div class="panel"><div class="chart-box tall"><canvas id="chart-timeline"></canvas></div></div>
</div>

<div class="section">
  <h2>Month over month</h2>
  <p class="note">Partial months are compared on events per day, so a half-observed month isn't mistaken for a quiet one.
  Change is per-day rate versus the previous month.</p>
  <div class="panel table-scroll"><table>
    <thead><tr><th>Month</th><th>Events</th><th>Per day</th><th>Change</th><th>Unique IPs</th><th>Failed logins</th><th>Successful</th><th>Commands</th><th>Files</th></tr></thead>
    <tbody>{month_rows_html}</tbody></table></div>
</div>

<div class="section">
  <h2>New vs. returning attackers per week</h2>
  <p class="note">An attacker is <em>new</em> in the week its IP was first ever seen by this sensor, and <em>returning</em> in every later week it shows up.
  Across the whole period, {total_returning_share} of weekly attacker appearances were repeat visitors.</p>
  <div class="panel"><div class="chart-box"><canvas id="chart-weekly"></canvas></div></div>
</div>

<div class="section grid-2">
  <div>
    <h2>Attack type breakdown</h2>
    <div class="panel"><div class="chart-box"><canvas id="chart-types"></canvas></div></div>
  </div>
  <div>
    <h2>Activity by hour of day (UTC)</h2>
    <div class="panel"><div class="chart-box"><canvas id="chart-hourly"></canvas></div></div>
  </div>
</div>

<div class="section">
  <h2>When attacks land — day of week × hour (UTC)</h2>
  <div class="panel chart-scroll">{render_heatmap(report)}</div>
</div>

<div class="section">
  <h2>Top attackers ({unique_attackers:,} total)</h2>
  <div class="panel table-scroll">
    <table>
      <thead><tr><th>#</th><th>IP</th><th>Primary type</th><th>First seen</th><th>Last seen</th><th>Events</th></tr></thead>
      <tbody>{attacker_rows_html()}</tbody>
    </table>
  </div>
</div>

<div class="section">
  <h2>Most persistent attackers — distinct days active</h2>
  <p class="note">Volume rewards noisy one-off scanners; persistence surfaces the infrastructure that keeps coming back.
  {one_day_share} of all attacker IPs were only ever seen on a single day.</p>
  <div class="panel table-scroll"><table>
    <thead><tr><th>#</th><th>IP</th><th>Country</th><th>Days active</th><th>First seen</th><th>Last seen</th><th>Events</th></tr></thead>
    <tbody>{persistent_rows}</tbody></table></div>
</div>

<div class="section grid-2">
  <div>
    <h2>Top credentials tried</h2>
    <div class="panel"><div class="chart-box"><canvas id="chart-credentials"></canvas></div></div>
  </div>
  <div>
    <h2>Top countries</h2>
    <div class="panel"><div class="chart-box"><canvas id="chart-countries"></canvas></div></div>
  </div>
</div>

<div class="section grid-3">
  <div>
    <h2>Credential pairs</h2>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>User</th><th>Pass</th><th>Count</th></tr></thead><tbody>{credential_rows}</tbody></table></div>
  </div>
  <div>
    <h2>Usernames</h2>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>Username</th><th>Count</th></tr></thead><tbody>{username_rows}</tbody></table></div>
  </div>
  <div>
    <h2>Passwords</h2>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>Password</th><th>Count</th></tr></thead><tbody>{password_rows}</tbody></table></div>
  </div>
</div>

<div class="section">
  <h2>Commands executed after login ({len(report.command_counts):,} unique)</h2>
  <div class="panel table-scroll"><table><thead><tr><th>#</th><th>Command</th><th>Count</th></tr></thead><tbody>{command_rows}</tbody></table></div>
</div>

<div class="section grid-2">
  <div>
    <h2>Credentials that got in</h2>
    <p class="note">Cowrie accepts these on purpose (its userdb) to lure attackers into the fake shell.</p>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>User</th><th>Pass</th><th>Logins</th></tr></thead><tbody>{success_rows}</tbody></table></div>
  </div>
  <div>
    <h2>Captured payloads — unique SHA-256 ({len(report.malware_hashes):,})</h2>
    <p class="note">Hover a hash for the full value. Look these up yourself on a malware-intel site; nothing here is sent anywhere.</p>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>SHA-256</th><th>First seen</th><th>Seen</th><th>IPs</th><th>Source</th></tr></thead><tbody>{hash_rows}</tbody></table></div>
  </div>
</div>

{render_detection(report, det)}

<div class="section grid-2">
  <div>
    <h2>Geo breakdown</h2>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>Country</th><th>Code</th><th>Events</th></tr></thead><tbody>{country_rows}</tbody></table></div>
  </div>
  <div>
    <h2>Top ISPs / ASNs</h2>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>ASN</th><th>Organization</th><th>Events</th></tr></thead><tbody>{asn_rows}</tbody></table></div>
  </div>
</div>

<div class="section grid-3">
  <div>
    <h2>Protocol</h2>
    <div class="panel table-scroll"><table><thead><tr><th>Protocol</th><th>Count</th><th>Share</th></tr></thead><tbody>{protocol_rows}</tbody></table></div>
  </div>
  <div>
    <h2>Session duration</h2>
    <div class="panel">
      <div class="stat-row" style="grid-template-columns: 1fr 1fr; margin: 0;">
        <div class="stat-tile"><div class="value">{fmt_duration(dur_avg)}</div><div class="label">Average ({dur_count:,} sessions)</div></div>
        <div class="stat-tile"><div class="value">{fmt_duration(dur_median)}</div><div class="label">Median</div></div>
        <div class="stat-tile"><div class="value">{fmt_duration(dur_max)}</div><div class="label">Longest</div></div>
        <div class="stat-tile"><div class="value">{login_total:,}</div><div class="label">Total login attempts</div></div>
      </div>
    </div>
  </div>
  <div>
    <h2>Client fingerprints</h2>
    <div class="panel table-scroll"><table><thead><tr><th>#</th><th>Client version</th><th>Count</th></tr></thead><tbody>{version_rows}</tbody></table></div>
  </div>
</div>

{"" if not top_downloads else f'''
<div class="section">
  <h2>Files downloaded/uploaded by attackers</h2>
  <div class="panel table-scroll"><table><thead><tr><th>#</th><th>URL</th><th>Count</th></tr></thead><tbody>{download_rows}</tbody></table></div>
</div>
'''}

<footer>Generated by tools/analyze_logs.py from {report.total_lines:,} raw log lines · Cowrie Attack Dashboard</footer>
</div>

<script>
Chart.defaults.font.family = "system-ui, -apple-system, 'Segoe UI', sans-serif";
Chart.defaults.color = "#898781";
const tooltipStyle = {{ backgroundColor: "#202020", titleColor: "#c3c2b7", bodyColor: "#ffffff", borderColor: "#2c2c2a", borderWidth: 1, padding: 8, displayColors: false }};
const gridStyle = {{ color: "#2c2c2a" }};
const tickStyle = {{ color: "#898781" }};

new Chart(document.getElementById('chart-timeline'), {{
  type: 'line',
  data: {{ labels: {js(daily_labels)}, datasets: [{{ data: {js(daily_values)}, borderColor: '#3987e5', backgroundColor: 'rgba(57,135,229,0.10)', borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, fill: true, tension: 0.2 }}] }},
  options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }}, tooltip: tooltipStyle }},
    scales: {{ x: {{ grid: {{ ...gridStyle, drawTicks: false }}, ticks: {{ ...tickStyle, maxTicksLimit: 12, autoSkip: true }} }}, y: {{ beginAtZero: true, grid: gridStyle, ticks: {{ ...tickStyle, precision: 0 }} }} }} }}
}});

new Chart(document.getElementById('chart-types'), {{
  type: 'bar',
  data: {{ labels: {js(type_labels_js)}, datasets: [{{ data: {js(type_values_js)}, backgroundColor: {js(type_colors_js)}, borderRadius: 4, maxBarThickness: 26 }}] }},
  options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }}, tooltip: tooltipStyle }},
    scales: {{ x: {{ beginAtZero: true, grid: gridStyle, ticks: {{ ...tickStyle, precision: 0 }} }}, y: {{ grid: {{ display: false }}, ticks: {{ color: '#c3c2b7' }} }} }} }}
}});

new Chart(document.getElementById('chart-hourly'), {{
  type: 'bar',
  data: {{ labels: {js(hourly_labels)}, datasets: [{{ data: {js(hourly_values)}, backgroundColor: '#3987e5', borderRadius: 3, maxBarThickness: 16 }}] }},
  options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }}, tooltip: tooltipStyle }},
    scales: {{ x: {{ grid: {{ display: false }}, ticks: {{ ...tickStyle, maxTicksLimit: 12 }} }}, y: {{ beginAtZero: true, grid: gridStyle, ticks: {{ ...tickStyle, precision: 0 }} }} }} }}
}});

new Chart(document.getElementById('chart-credentials'), {{
  type: 'bar',
  data: {{ labels: {js(cred_chart_labels)}, datasets: [{{ data: {js(cred_chart_values)}, backgroundColor: '#3987e5', borderRadius: 4, maxBarThickness: 18 }}] }},
  options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }}, tooltip: tooltipStyle }},
    scales: {{ x: {{ beginAtZero: true, grid: gridStyle, ticks: {{ ...tickStyle, precision: 0 }} }}, y: {{ grid: {{ display: false }}, ticks: {{ color: '#c3c2b7', font: {{ family: 'ui-monospace, monospace', size: 10.5 }} }} }} }} }}
}});

new Chart(document.getElementById('chart-countries'), {{
  type: 'bar',
  data: {{ labels: {js(country_chart_labels)}, datasets: [{{ data: {js(country_chart_values)}, backgroundColor: '#d95926', borderRadius: 4, maxBarThickness: 18 }}] }},
  options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }}, tooltip: tooltipStyle }},
    scales: {{ x: {{ beginAtZero: true, grid: gridStyle, ticks: {{ ...tickStyle, precision: 0 }} }}, y: {{ grid: {{ display: false }}, ticks: {{ color: '#c3c2b7' }} }} }} }}
}});

// Two series, categorical slots 1 and 2. The 1px surface-colored border on each segment
// produces the 2px gap between stacked fills and between adjacent bars.
new Chart(document.getElementById('chart-weekly'), {{
  type: 'bar',
  data: {{ labels: {js(week_labels)}, datasets: [
    {{ label: 'New IPs', data: {js(week_new)}, backgroundColor: '#3987e5', borderColor: '#1a1a19', borderWidth: 1, borderRadius: 0, maxBarThickness: 28 }},
    {{ label: 'Returning IPs', data: {js(week_returning)}, backgroundColor: '#d95926', borderColor: '#1a1a19', borderWidth: 1, borderRadius: {{ topLeft: 4, topRight: 4 }}, maxBarThickness: 28 }}
  ] }},
  options: {{ responsive: true, maintainAspectRatio: false, interaction: {{ mode: 'index', intersect: false }},
    plugins: {{ legend: {{ display: true, position: 'top', align: 'start', labels: {{ color: '#c3c2b7', boxWidth: 10, boxHeight: 10, useBorderRadius: true, borderRadius: 2 }} }},
      tooltip: {{ ...tooltipStyle, displayColors: true, callbacks: {{ title: (items) => 'Week of ' + items[0].label }} }} }},
    scales: {{ x: {{ stacked: true, grid: {{ display: false }}, ticks: {{ ...tickStyle, maxTicksLimit: 14, autoSkip: true }} }},
      y: {{ stacked: true, beginAtZero: true, grid: gridStyle, ticks: {{ ...tickStyle, precision: 0 }} }} }} }}
}});
</script>
</body>
</html>
"""


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a full-history breakdown report of Cowrie honeypot activity")
    ap.add_argument("--log", default=None, help="Path to the current cowrie.json (default: COWRIE_LOG_PATH from .env)")
    ap.add_argument("--days", type=int, default=30, help="Only include events from the last N days (0 = full history)")
    ap.add_argument("--out", default=None, help="Output HTML path (default: reports/attack_report_<timestamp>.html)")
    ap.add_argument("--no-geo", action="store_true", help="Skip GeoLite2 lookups (faster, no country/ASN breakdown)")
    ap.add_argument("--checkup", action="store_true",
                    help="Also run sensor health checks (Cowrie process, disk runway, dashboard, Wazuh agent, host)")
    ap.add_argument("--no-detection", action="store_true",
                    help="Skip the retroactive Wazuh rule pass (faster on very large histories)")
    args = ap.parse_args()

    log_path = args.log or settings.cowrie_log_path
    files = discover_log_files(log_path)
    if not files:
        print(f"No log files found matching {log_path}* -- check the path.")
        sys.exit(1)

    print(f"Found {len(files)} log file(s):")
    for f in files:
        print(f"  {f}  ({f.stat().st_size:,} bytes)")

    cutoff_ts = None
    if args.days > 0:
        cutoff_ts = datetime.now(timezone.utc) - timedelta(days=args.days)
        print(f"Including events since {cutoff_ts.date()} ({args.days} days)")
    else:
        print("Including full available history (no day cutoff)")

    do_geo = not args.no_geo
    if do_geo:
        print("Geolocating attacker IPs via local GeoLite2 DB...")

    det = None if args.no_detection else load_detection()
    if det is not None:
        print(f"Replaying history through {len(det.meta)} Wazuh rules for the detection section...")

    report = Report()
    started = time.monotonic()
    for path in files:
        # Brute-force windows are per-file: rotated files aren't read in time order, and a
        # window spanning two files would compare timestamps from unrelated periods.
        report._bf_windows.clear()
        try:
            with open_log_file(path) as fh:
                for line in fh:
                    process_line(line, report, cutoff_ts, do_geo, det)
                    if report.total_lines % 1_000_000 == 0 and report.total_lines:
                        print(f"  ... {report.total_lines:,} lines ({time.monotonic() - started:.0f}s)", flush=True)
        except OSError as e:
            print(f"  ! skipping {path}: {e}")

    print(f"Processed {report.total_lines:,} log lines -> {report.total_events:,} attack events "
          f"from {len(report.attacker_counts):,} unique attacker IPs in {time.monotonic() - started:.0f}s")

    if report.total_events == 0:
        print("No events found in the selected window -- nothing to report.")
        sys.exit(0)

    health = None
    if args.checkup:
        print("Running health checks...")
        health = run_health_checks(log_path, files, report)
        for h in health:
            print(f"  [{h['status'].upper():>4}] {h['name']}: {h['detail']}")

    out_path = Path(args.out) if args.out else Path("reports") / f"attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(report, args.days if args.days > 0 else None, health, det), encoding="utf-8")

    summary_path = out_path.with_suffix(".json")
    summary_path.write_text(json.dumps(build_summary(report, health, det), indent=2), encoding="utf-8")

    print(f"\nReport written to  {out_path.resolve()}")
    print(f"Summary written to {summary_path.resolve()}")
    print("Download both to your computer (run this on your computer, not the VM):")
    print(f"  scp -P 2244 -i <key> \"honeypotadmin@<vps-ip>:{out_path.resolve().parent}/{out_path.stem}.*\" .")


def build_summary(report: Report, health: list[dict] | None, det: Detection | None) -> dict:
    """Small machine-readable digest of the report -- the headline numbers without the HTML."""
    login_total = report.login_success + report.login_failed
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period": {
            "first_event": report.first_ts.isoformat() if report.first_ts else None,
            "last_event": report.last_ts.isoformat() if report.last_ts else None,
            "days_observed": len(report.daily_counts),
        },
        "totals": {
            "raw_lines": report.total_lines,
            "events": report.total_events,
            "unique_attackers": len(report.attacker_counts),
            "login_failed": report.login_failed,
            "login_success": report.login_success,
            "login_success_rate_pct": round(report.login_success / login_total * 100, 2) if login_total else 0,
            "unique_commands": len(report.command_counts),
            "file_events": report.files_seen,
            "unique_payload_hashes": len(report.malware_hashes),
            "sessions": len(report.session_durations),
            "median_session_s": round(statistics.median(report.session_durations), 1) if report.session_durations else 0,
            "single_day_attacker_pct": round(sum(1 for d in report.ip_days.values() if len(d) == 1)
                                             / len(report.ip_days) * 100, 1) if report.ip_days else 0,
        },
        "monthly": [{k: v for k, v in m.items() if k != "label"} for m in build_monthly(report)],
        "weekly_new_vs_returning": build_weekly(report),
        "busiest_days": sorted(report.daily_counts.items(), key=lambda kv: kv[1], reverse=True)[:5],
        "top_attackers": [{"ip": ip, "events": c, "days_active": len(report.ip_days[ip]),
                           "country": report.country_names.get((report._geo_cache.get(ip) or {}).get("country_code", ""))}
                          for ip, c in report.attacker_counts.most_common(10)],
        "most_persistent": [{"ip": ip, "days_active": len(d), "events": report.attacker_counts[ip]}
                            for ip, d in sorted(report.ip_days.items(), key=lambda kv: len(kv[1]), reverse=True)[:10]],
        "top_credentials": [{"username": u, "password": p, "count": c} for (u, p), c in report.credential_counts.most_common(10)],
        "top_usernames": report.username_counts.most_common(10),
        "top_passwords": report.password_counts.most_common(10),
        "success_credentials": [{"username": u, "password": p, "count": c} for (u, p), c in report.success_credentials.most_common(10)],
        "top_commands": report.command_counts.most_common(15),
        "top_countries": [{"code": cc, "name": report.country_names.get(cc, cc), "events": c} for cc, c in report.country_counts.most_common(10)],
        "top_asns": [{"asn": a, "org": o, "events": c} for (a, o), c in report.asn_counts.most_common(10)],
        "protocols": dict(report.protocol_counts),
        "client_versions": report.client_version_counts.most_common(10),
        "payloads": [{"sha256": sha, "count": i["count"], "first_seen": i["first_seen"], "ips": len(i["ips"]), "source": i["source"]}
                     for sha, i in sorted(report.malware_hashes.items(), key=lambda kv: kv[1]["count"], reverse=True)[:15]],
        "detection": None if det is None else {
            "rule_hits": dict(report.rule_counts),
            "bruteforce_alerts": report.bruteforce_alerts,
            "bruteforce_ips": len(report.bruteforce_ips),
            "mitre": dict(report.mitre_counts),
        },
        "health": health,
    }


if __name__ == "__main__":
    main()
