#!/usr/bin/env python3
"""Tier 2 validation: replay real historical Cowrie events through the live
agent -> manager -> indexer -> dashboard path.

Run on the COWRIE VM, after verify_rules.sh passes on the manager.

Tier 1 (verify_rules.sh) proves the rules are correct. It does not prove the
agent is shipping, the manager is receiving, or the dashboard is displaying.
This script closes that gap using real attacker traffic already on disk.

    sudo python3 replay_to_agent.py --install-localfile
    sudo python3 replay_to_agent.py --count 40
    # ... confirm alerts in the Wazuh dashboard ...
    sudo python3 replay_to_agent.py --cleanup

WHY A SEPARATE LOG FILE
-----------------------
Replayed events are written to a dedicated replay log, never appended to
cowrie.json. cowrie.json is evidence, and it is also what the live dashboard
tails -- injecting synthetic timestamps into it would corrupt both.

WHY TIMESTAMPS ARE REWRITTEN
----------------------------
Wazuh stamps alerts with *reception* time, not the event timestamp field, so
replayed history shows up as "now" either way. Rewriting them keeps the replay
log internally consistent and keeps the brute-force burst inside rule 100210's
120s correlation window. That same reception-time behaviour is the central
constraint any future retroactive-reporting project has to design around --
Wazuh cannot be made to backdate alerts by replaying old logs.
"""

import argparse
import json
import os
import random
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Reuse the rotated/gzipped log discovery the analysis tool already solved.
# Falls back to a local copy because this script runs under bare system python3
# via sudo, which does not have the dashboard venv's pydantic/geoip2 deps.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from tools.analyze_logs import discover_log_files, open_log_file  # type: ignore
except Exception:  # noqa: BLE001 - any import failure means use the fallback
    import gzip

    def discover_log_files(base_path: str) -> list[Path]:
        base = Path(base_path)
        if not base.parent.exists():
            return []
        return sorted(p for p in base.parent.glob(f"{base.name}*") if p.is_file())

    def open_log_file(path: Path):
        if path.suffix == ".gz":
            return gzip.open(path, "rt", encoding="utf-8", errors="replace")
        return open(path, "r", encoding="utf-8", errors="replace")


DEFAULT_COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_REPLAY_LOG = "/var/log/cowrie-replay.json"
OSSEC_CONF = Path("/var/ossec/etc/ossec.conf")

BEGIN_MARK = "<!-- BEGIN cowrie-replay (temporary, added by replay_to_agent.py) -->"
END_MARK = "<!-- END cowrie-replay -->"

# Every rule the replay should exercise. Sampling is stratified across these so a
# run always covers the full tree instead of returning 40 login failures.
WANTED = [
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
]


def collect(cowrie_log: str, per_type: int) -> dict[str, list[dict]]:
    """Read the honeypot history and bucket a sample of events by eventid."""
    files = discover_log_files(cowrie_log)
    if not files:
        sys.exit(f"[x] no Cowrie logs found next to {cowrie_log}")

    print(f"[*] scanning {len(files)} log file(s):")
    for f in files:
        print(f"      {f}")

    buckets: dict[str, list[dict]] = defaultdict(list)
    scanned = 0
    for path in files:
        with open_log_file(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                scanned += 1
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                eid = ev.get("eventid")
                if eid in WANTED and len(buckets[eid]) < per_type * 4:
                    buckets[eid].append(ev)

    print(f"[*] scanned {scanned:,} lines")
    for eid in WANTED:
        print(f"      {eid:<32} {len(buckets[eid]):>5} available")
    return buckets


def build_replay(buckets: dict[str, list[dict]], count: int) -> list[dict]:
    """Stratified sample plus a deliberate brute-force burst, timestamps rewritten."""
    per_type = max(1, count // len(WANTED))
    events: list[dict] = []
    for eid in WANTED:
        pool = buckets.get(eid, [])
        if pool:
            events.extend(random.sample(pool, min(per_type, len(pool))))

    # Rule 100210 needs more than 8 failures from ONE source inside 120s. A random
    # sample of historical failures comes from many different IPs and correctly
    # fails to correlate, so the burst is constructed explicitly.
    failures = buckets.get("cowrie.login.failed", [])
    if failures:
        seed = dict(failures[0])
        burst_ip = seed.get("src_ip", "203.0.113.99")
        for i in range(10):
            ev = dict(seed)
            ev["src_ip"] = burst_ip
            ev["session"] = f"replay{i:04d}"
            ev["password"] = f"replaypw{i}"
            events.append(ev)
        print(f"[*] added a 10-failure burst from {burst_ip} (exercises rule 100210)")
    else:
        print("[!] no historical login failures found - rule 100210 will not be exercised")

    base = datetime.now(timezone.utc)
    for i, ev in enumerate(events):
        ev["timestamp"] = (base + timedelta(milliseconds=i * 200)).isoformat().replace("+00:00", "Z")
        ev["replay"] = True  # distinguishes these from live traffic inside the SIEM
    return events


def install_localfile(replay_log: str) -> None:
    conf = OSSEC_CONF.read_text(encoding="utf-8")
    if BEGIN_MARK in conf:
        print("[*] replay localfile block already present")
        return
    block = (
        f"\n{BEGIN_MARK}\n"
        "<ossec_config>\n"
        "  <localfile>\n"
        "    <log_format>json</log_format>\n"
        f"    <location>{replay_log}</location>\n"
        "  </localfile>\n"
        "</ossec_config>\n"
        f"{END_MARK}\n"
    )
    OSSEC_CONF.write_text(conf + block, encoding="utf-8")
    Path(replay_log).touch()
    os.chmod(replay_log, 0o640)
    print(f"[+] added temporary localfile for {replay_log}")
    restart_agent()


def cleanup(replay_log: str) -> None:
    conf = OSSEC_CONF.read_text(encoding="utf-8")
    if BEGIN_MARK in conf and END_MARK in conf:
        start = conf.index(BEGIN_MARK)
        end = conf.index(END_MARK) + len(END_MARK)
        OSSEC_CONF.write_text(conf[:start].rstrip() + "\n" + conf[end:].lstrip(), encoding="utf-8")
        print("[+] removed temporary localfile block")
        restart_agent()
    else:
        print("[*] no replay localfile block to remove")

    p = Path(replay_log)
    if p.exists():
        p.unlink()
        print(f"[+] deleted {replay_log}")
    print("[*] cleanup complete - the agent is back to watching only cowrie.json")


def restart_agent() -> None:
    print("[*] restarting wazuh-agent")
    subprocess.run(["systemctl", "restart", "wazuh-agent"], check=False)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--log", default=DEFAULT_COWRIE_LOG,
                    help="Cowrie JSON log (rotated siblings found automatically)")
    ap.add_argument("--replay-log", default=DEFAULT_REPLAY_LOG,
                    help="dedicated replay log the agent tails")
    ap.add_argument("--count", type=int, default=30,
                    help="approximate number of sampled events (a brute-force burst is added on top)")
    ap.add_argument("--install-localfile", action="store_true",
                    help="add the temporary <localfile> block and restart the agent")
    ap.add_argument("--cleanup", action="store_true",
                    help="remove the replay log and its <localfile> block, then restart the agent")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[x] run as root (sudo python3 replay_to_agent.py ...)")

    if Path(args.replay_log).resolve() == Path(args.log).resolve():
        sys.exit("[x] refusing to replay into cowrie.json itself - that log is evidence")

    if args.cleanup:
        cleanup(args.replay_log)
        return

    if args.install_localfile:
        install_localfile(args.replay_log)
        return

    if BEGIN_MARK not in OSSEC_CONF.read_text(encoding="utf-8"):
        sys.exit("[x] the agent is not watching the replay log yet. Run with --install-localfile first.")

    events = build_replay(collect(args.log, max(1, args.count // len(WANTED))), args.count)
    with open(args.replay_log, "a", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
        fh.flush()

    by_type: dict[str, int] = defaultdict(int)
    for ev in events:
        by_type[ev.get("eventid", "?")] += 1

    print(f"\n[+] wrote {len(events)} replayed events to {args.replay_log}")
    for eid, n in sorted(by_type.items()):
        print(f"      {eid:<32} {n:>4}")
    print(
        "\nNow check the Wazuh dashboard (Threat Hunting, filter rule.groups:cowrie).\n"
        "Expect within ~30s: 100203 login success, 100204/100211/100212 commands,\n"
        "100205/100206 file transfer, and 100210 brute force.\n"
        "\nWhen finished:  sudo python3 replay_to_agent.py --cleanup"
    )


if __name__ == "__main__":
    main()
