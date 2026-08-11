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
"""

import argparse
import gzip
import html
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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


def process_line(raw_line: str, report: Report, cutoff_ts: datetime | None, do_geo: bool) -> None:
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
        else:
            report.login_success += 1

    if eventid == "cowrie.command.input":
        cmd = raw.get("input")
        if cmd:
            report.command_counts[cmd] += 1

    if eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        report.files_seen += 1
        url = raw.get("url")
        if url:
            report.download_urls[url] += 1

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


def render_html(report: Report, period_days: int | None) -> str:
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

<div class="section">
  <h2>Attack volume over time</h2>
  <div class="panel"><div class="chart-box tall"><canvas id="chart-timeline"></canvas></div></div>
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
  <h2>Top attackers ({unique_attackers:,} total)</h2>
  <div class="panel table-scroll">
    <table>
      <thead><tr><th>#</th><th>IP</th><th>Primary type</th><th>First seen</th><th>Last seen</th><th>Events</th></tr></thead>
      <tbody>{attacker_rows_html()}</tbody>
    </table>
  </div>
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

    report = Report()
    for path in files:
        try:
            with open_log_file(path) as fh:
                for line in fh:
                    process_line(line, report, cutoff_ts, do_geo)
        except OSError as e:
            print(f"  ! skipping {path}: {e}")

    print(f"Processed {report.total_lines:,} log lines -> {report.total_events:,} attack events "
          f"from {len(report.attacker_counts):,} unique attacker IPs")

    if report.total_events == 0:
        print("No events found in the selected window -- nothing to report.")
        sys.exit(0)

    out_path = Path(args.out) if args.out else Path("reports") / f"attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(report, args.days if args.days > 0 else None), encoding="utf-8")

    print(f"\nReport written to {out_path.resolve()}")
    print("View it, e.g.:")
    print(f"  scp -P 2244 -i <key> honeypotadmin@<vps-ip>:{out_path.resolve()} .   # then open locally")
    print(f"  # or: python3 -m http.server 8090 --directory {out_path.parent}   (tunnel port 8090)")


if __name__ == "__main__":
    main()
