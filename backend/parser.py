"""Normalize raw Cowrie JSON log lines into a flat event dict used throughout the pipeline."""

import json
from datetime import datetime, timezone
from typing import Any, Optional

# eventid -> (attack_type, color). Color drives the arc/legend color on the globe.
# Palette validated for dark-surface CVD/contrast via the dataviz skill's validate_palette.js
# (categorical slots, fixed order; "other" uses muted ink rather than a vivid slot since it's a
# residual bucket, not a real category).
EVENT_TYPE_MAP: dict[str, tuple[str, str]] = {
    "cowrie.session.connect": ("connect", "#3987e5"),  # blue
    "cowrie.login.failed": ("bruteforce", "#e66767"),  # red
    "cowrie.login.success": ("login_success", "#008300"),  # green
    "cowrie.command.input": ("command", "#d95926"),  # orange
    "cowrie.session.file_download": ("malware", "#d55181"),  # magenta
    "cowrie.session.file_upload": ("malware", "#d55181"),  # magenta
}
DEFAULT_TYPE = ("other", "#898781")  # muted ink

# Only these eventids produce a visible arc + feed entry. Others (client.version, kex, closed, ...)
# are noise for a live ops view and are dropped.
DISPLAYED_EVENTS = set(EVENT_TYPE_MAP.keys())


def parse_line(line: str) -> Optional[dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    eventid = raw.get("eventid", "")
    if eventid not in DISPLAYED_EVENTS:
        return None

    src_ip = raw.get("src_ip")
    if not src_ip:
        return None

    attack_type, color = EVENT_TYPE_MAP.get(eventid, DEFAULT_TYPE)

    ts_raw = raw.get("timestamp")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)
    except (ValueError, AttributeError):
        ts = datetime.now(timezone.utc)

    return {
        "timestamp": ts.isoformat(),
        "eventid": eventid,
        "attack_type": attack_type,
        "color": color,
        "src_ip": src_ip,
        "session": raw.get("session", ""),
        "protocol": raw.get("protocol", ""),
        "dst_port": raw.get("dst_port"),
        "username": raw.get("username"),
        "password": raw.get("password"),
        "command": raw.get("input"),
        "url": raw.get("url"),
    }
