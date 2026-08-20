#!/usr/bin/env bash
#
# verify_rules.sh - offline, deterministic assertions for the Cowrie rule set.
#
# Run on the MANAGER VM. Needs no attacker, no agent, and no live traffic: it
# feeds fixture events straight into wazuh-logtest inside the manager container
# and asserts the expected rule id and severity come back.
#
# This is the regression test for detection content. Re-run it after every edit
# to manager/rules/local_rules.xml.
#
#   sudo ./verify_rules.sh
#
set -uo pipefail

WAZUH_DOCKER_DIR="${WAZUH_DOCKER_DIR:-/opt/wazuh-docker}"
SINGLE_NODE="${WAZUH_DOCKER_DIR}/single-node"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="${REPO_DIR}/scripts/fixtures/cowrie_fixtures.jsonl"

PASS=0; FAIL=0
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
head1() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die()   { red "[x] $*"; exit 1; }

[[ -f "$FIXTURES" ]] || die "fixtures not found: $FIXTURES"

CID="$( (cd "$SINGLE_NODE" 2>/dev/null && docker compose ps -q wazuh.manager) 2>/dev/null || true)"
[[ -n "$CID" ]] || CID="$(docker ps -q --filter 'name=wazuh.manager' | head -1)"
[[ -n "$CID" ]] || die "wazuh.manager container not running (checked $SINGLE_NODE and 'docker ps')"

# logtest() - feed newline-delimited raw logs into one wazuh-logtest session and
# return everything it printed. A single session is required for the correlation
# tests: frequency/if_matched_sid state only accumulates within one session.
logtest() {
  docker exec -i "$CID" /var/ossec/bin/wazuh-logtest 2>&1
}

# --------------------------------------------------------------------------
head1 "Preflight: ruleset compiles"
# --------------------------------------------------------------------------
# analysisd -t parses every rule file. If local_rules.xml has a bad regex or an
# unknown MITRE id, it surfaces here rather than as a silently missing detection.
if PRE="$(docker exec "$CID" /var/ossec/bin/wazuh-analysisd -t 2>&1)"; then
  green "  [pass] ruleset parses cleanly"; PASS=$((PASS+1))
else
  red "  [FAIL] ruleset did not compile:"; echo "$PRE" | sed 's/^/         /'
  FAIL=$((FAIL+1))
  die "fix the ruleset before continuing - nothing below will be meaningful"
fi

if docker exec "$CID" test -f /var/ossec/etc/rules/local_rules.xml; then
  if docker exec "$CID" grep -q 'id="100200"' /var/ossec/etc/rules/local_rules.xml; then
    green "  [pass] local_rules.xml is mounted and contains the Cowrie block"; PASS=$((PASS+1))
  else
    red "  [FAIL] local_rules.xml is mounted but has no Cowrie rules - check COWRIE_RULES_PATH in ${SINGLE_NODE}/.env"
    FAIL=$((FAIL+1))
  fi
else
  red "  [FAIL] /var/ossec/etc/rules/local_rules.xml missing in the container"; FAIL=$((FAIL+1))
fi

# --------------------------------------------------------------------------
head1 "Tier 1a: one event per rule"
# --------------------------------------------------------------------------
while IFS=$'\t' read -r NAME SID LEVEL LOGLINE; do
  [[ -n "${NAME:-}" ]] || continue
  OUT="$(printf '%s\n' "$LOGLINE" | logtest)"
  # sed rather than `grep -oP`: PCRE grep is not universally available (it fails
  # outright under some locales), and this needs to work on whatever the manager has.
  GOT_SID="$(printf '%s' "$OUT"   | sed -n "s/.*id: '\([0-9]\{1,\}\)'.*//p"    | tail -1)"
  GOT_LEVEL="$(printf '%s' "$OUT" | sed -n "s/.*level: '\([0-9]\{1,\}\)'.*//p" | tail -1)"

  if [[ "$GOT_SID" == "$SID" && "$GOT_LEVEL" == "$LEVEL" ]]; then
    green "  [pass] ${NAME}  ->  ${GOT_SID} (level ${GOT_LEVEL})"
    PASS=$((PASS+1))
  else
    red   "  [FAIL] ${NAME}"
    red   "         expected sid=${SID} level=${LEVEL}   got sid=${GOT_SID:-none} level=${GOT_LEVEL:-none}"
    FAIL=$((FAIL+1))
  fi
done < <(python3 - "$FIXTURES" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    f = json.loads(line)
    print("\t".join([f["name"], str(f["expect_sid"]), str(f["expect_level"]),
                     json.dumps(f["log"], separators=(",", ":"))]))
PY
)

# --------------------------------------------------------------------------
head1 "Tier 1b: brute-force correlation (100210)"
# --------------------------------------------------------------------------
# Positive: 10 failures from ONE source inside the 120s window must escalate.
BF_SAME="$(python3 - <<'PY'
import json
for i in range(10):
    print(json.dumps({"eventid":"cowrie.login.failed","username":"root",
                      "password":f"pw{i}","src_ip":"185.220.101.45",
                      "session":"bfsame01","sensor":"fishhoney",
                      "message":"login attempt failed",
                      "timestamp":"2026-08-20T11:00:00.000000Z"},
                     separators=(",",":")))
PY
)"
if printf '%s\n' "$BF_SAME" | logtest | grep -q "id: '100210'"; then
  green "  [pass] 10 failures from one ip escalated to 100210"; PASS=$((PASS+1))
else
  red "  [FAIL] brute-force rule 100210 did not fire for 10 failures from one ip"
  red "         check <frequency>/<timeframe>, and that <same_field>src_ip</same_field>"
  red "         is accepted by this Wazuh version (see README: correlation fallback)"
  FAIL=$((FAIL+1))
fi

# Negative: the same volume spread across DIFFERENT sources must NOT escalate.
# This is the test that actually proves <same_field>src_ip</same_field> works.
# Without it the rule would still "pass" above while silently merging unrelated
# attackers into one brute-force alert.
BF_DIFF="$(python3 - <<'PY'
import json
for i in range(10):
    print(json.dumps({"eventid":"cowrie.login.failed","username":"root",
                      "password":"toor","src_ip":f"203.0.113.{i+10}",
                      "session":f"bfdiff{i:02d}","sensor":"fishhoney",
                      "message":"login attempt failed",
                      "timestamp":"2026-08-20T11:05:00.000000Z"},
                     separators=(",",":")))
PY
)"
if printf '%s\n' "$BF_DIFF" | logtest | grep -q "id: '100210'"; then
  red "  [FAIL] 100210 fired for 10 failures from 10 DIFFERENT ips"
  red "         same_field is not correlating - the rule is merging unrelated attackers"
  FAIL=$((FAIL+1))
else
  green "  [pass] 10 failures from 10 different ips correctly did NOT escalate"; PASS=$((PASS+1))
fi

# --------------------------------------------------------------------------
printf '\n\033[1m--------------------------------------------------\033[0m\n'
if [[ $FAIL -eq 0 ]]; then
  green " ALL ${PASS} CHECKS PASSED"
  printf '\033[1m--------------------------------------------------\033[0m\n'
  echo " Next: end-to-end validation from the Cowrie VM ->"
  echo "   sudo python3 wazuh/scripts/replay_to_agent.py --count 40"
  exit 0
else
  red " ${FAIL} FAILED, ${PASS} passed"
  printf '\033[1m--------------------------------------------------\033[0m\n'
  exit 1
fi
