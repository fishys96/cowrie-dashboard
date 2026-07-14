"""Pipeline: parse -> geo enrich -> update in-memory aggregates -> persist to SQLite.

Aggregates are kept in plain in-process structures (single uvicorn worker, so this is safe
and avoids any external cache/DB). SQLite exists purely so a restart doesn't lose history --
on startup we rebuild the in-memory aggregates from the last TIMELINE_HOURS of events.
"""

import logging
import sqlite3
import threading
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from backend import geo, parser
from backend.config import settings

logger = logging.getLogger("dashboard.store")

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

feed: deque = deque(maxlen=settings.feed_limit)
attacker_stats: dict[str, dict] = {}
credential_counter: Counter = Counter()
command_counter: Counter = Counter()
country_counter: Counter = Counter()
country_names: dict[str, str] = {}
timeline: dict[str, int] = {}
total_events = 0

_EVENT_COLUMNS = (
    "timestamp", "eventid", "attack_type", "color", "src_ip", "session", "protocol", "dst_port",
    "username", "password", "command", "url", "lat", "lon", "city", "country", "country_code",
    "asn", "as_org",
)


def _minute_bucket(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:00Z")


def init_db() -> None:
    global _conn
    _conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute(
        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp TEXT NOT NULL, eventid TEXT NOT NULL, attack_type TEXT NOT NULL, color TEXT NOT NULL, "
        "src_ip TEXT NOT NULL, session TEXT, protocol TEXT, dst_port INTEGER, "
        "username TEXT, password TEXT, command TEXT, url TEXT, "
        "lat REAL, lon REAL, city TEXT, country TEXT, country_code TEXT, asn INTEGER, as_org TEXT)"
    )
    _conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
    _conn.commit()

    if settings.replay_on_start:
        _rebuild_aggregates()


def _rebuild_aggregates() -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=settings.timeline_hours)).isoformat()
    cur = _conn.execute(
        f"SELECT {', '.join(_EVENT_COLUMNS)} FROM events WHERE timestamp >= ? ORDER BY timestamp ASC",
        (cutoff,),
    )
    rows = [dict(zip(_EVENT_COLUMNS, row)) for row in cur.fetchall()]
    for event in rows:
        _apply_to_aggregates(event)
    logger.info("Rebuilt aggregates from %d historical events", len(rows))


def _apply_to_aggregates(event: dict) -> None:
    global total_events
    total_events += 1
    feed.append(event)

    ip = event["src_ip"]
    stats = attacker_stats.get(ip)
    if stats is None:
        stats = {
            "ip": ip,
            "count": 0,
            "first_seen": event["timestamp"],
            "geo": {
                "country": event.get("country"),
                "country_code": event.get("country_code"),
                "city": event.get("city"),
                "asn": event.get("asn"),
                "as_org": event.get("as_org"),
            },
            "attack_types": Counter(),
        }
        attacker_stats[ip] = stats
    stats["count"] += 1
    stats["last_seen"] = event["timestamp"]
    stats["attack_types"][event["attack_type"]] += 1
    if event.get("country_code") and not stats["geo"]["country_code"]:
        stats["geo"] = {
            "country": event.get("country"),
            "country_code": event.get("country_code"),
            "city": event.get("city"),
            "asn": event.get("asn"),
            "as_org": event.get("as_org"),
        }

    if event["eventid"] in ("cowrie.login.failed", "cowrie.login.success"):
        credential_counter[(event.get("username") or "", event.get("password") or "")] += 1

    if event["attack_type"] == "command" and event.get("command"):
        command_counter[event["command"]] += 1

    if event.get("country_code"):
        country_counter[event["country_code"]] += 1
        country_names[event["country_code"]] = event.get("country") or event["country_code"]

    bucket = _minute_bucket(datetime.fromisoformat(event["timestamp"]))
    timeline[bucket] = timeline.get(bucket, 0) + 1


def _prune_timeline() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.timeline_hours)
    stale = [
        b for b in timeline
        if datetime.strptime(b, "%Y-%m-%dT%H:%M:00Z").replace(tzinfo=timezone.utc) < cutoff
    ]
    for b in stale:
        del timeline[b]


def _persist_event(event: dict) -> None:
    placeholders = ", ".join("?" for _ in _EVENT_COLUMNS)
    _conn.execute(
        f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) VALUES ({placeholders})",
        tuple(event.get(c) for c in _EVENT_COLUMNS),
    )
    _conn.commit()


async def ingest_line(raw_line: str) -> Optional[dict]:
    event = parser.parse_line(raw_line)
    if event is None:
        return None

    geo_data = geo.lookup(event["src_ip"])
    if geo_data:
        event.update(geo_data)
    else:
        event.update({
            "lat": None, "lon": None, "city": None,
            "country": None, "country_code": None, "asn": None, "as_org": None,
        })

    with _lock:
        _apply_to_aggregates(event)
        _persist_event(event)
        _prune_timeline()

    return event


def get_stats() -> dict:
    with _lock:
        ranked_attackers = sorted(attacker_stats.values(), key=lambda s: s["count"], reverse=True)[:20]
        top_attackers = [
            {
                "ip": s["ip"],
                "count": s["count"],
                "first_seen": s["first_seen"],
                "last_seen": s["last_seen"],
                "geo": s["geo"],
                "top_attack_type": s["attack_types"].most_common(1)[0][0] if s["attack_types"] else None,
            }
            for s in ranked_attackers
        ]
        top_credentials = [
            {"username": u, "password": p, "count": c}
            for (u, p), c in credential_counter.most_common(15)
        ]
        top_commands = [{"command": c, "count": n} for c, n in command_counter.most_common(25)]
        top_countries = [
            {"country_code": cc, "country": country_names.get(cc, cc), "count": n}
            for cc, n in country_counter.most_common(15)
        ]
        timeline_sorted = [{"bucket": b, "count": n} for b, n in sorted(timeline.items())]

        return {
            "total_events": total_events,
            "unique_attackers": len(attacker_stats),
            "top_attackers": top_attackers,
            "top_credentials": top_credentials,
            "top_commands": top_commands,
            "top_countries": top_countries,
            "timeline": timeline_sorted,
        }


def get_snapshot() -> dict:
    with _lock:
        snapshot = get_stats()
        snapshot["honeypot"] = {
            "lat": settings.honeypot_lat,
            "lon": settings.honeypot_lon,
            "label": settings.honeypot_label,
        }
        snapshot["feed"] = list(feed)[::-1]
        return snapshot
