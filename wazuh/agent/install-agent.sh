#!/usr/bin/env bash
#
# install-agent.sh - install and enroll the Wazuh agent on the COWRIE VM, and
# point it at cowrie.json.
#
# Run this on the honeypot VM (the one running Cowrie), not on the manager.
#
#   sudo WAZUH_MANAGER=10.0.0.x ./install-agent.sh
#
# Optional overrides:
#   COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
#   WAZUH_AGENT_VERSION=4.14.7-1
#
# Idempotent - safe to re-run after changing the manager address or log path.
#
set -euo pipefail

WAZUH_MANAGER="${WAZUH_MANAGER:-}"
WAZUH_AGENT_VERSION="${WAZUH_AGENT_VERSION:-4.14.7-1}"
COWRIE_LOG_PATH="${COWRIE_LOG_PATH:-/home/cowrie/cowrie/var/log/cowrie/cowrie.json}"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo WAZUH_MANAGER=<private-ip> $0)"
[[ -n "$WAZUH_MANAGER" ]] || die "WAZUH_MANAGER is required. Use the manager's PRIVATE ip, e.g. sudo WAZUH_MANAGER=10.0.0.5 $0"

# ---------------------------------------------------------------------------
log "1/5  Verify the Cowrie log before touching anything"
# ---------------------------------------------------------------------------
# Configuring a <localfile> for a path that does not exist, or that the collector
# cannot read, produces exactly the same symptom as a broken rule set: silence.
# Fail loudly here instead.
[[ -f "$COWRIE_LOG_PATH" ]] || die "Cowrie log not found: $COWRIE_LOG_PATH  (set COWRIE_LOG_PATH=...)"
head -c 1 "$COWRIE_LOG_PATH" >/dev/null 2>&1 \
  || die "Cannot read $COWRIE_LOG_PATH as root - check ownership and any ACLs"
if head -n 1 "$COWRIE_LOG_PATH" | python3 -c 'import json,sys; json.loads(sys.stdin.readline())' 2>/dev/null; then
  echo "    $COWRIE_LOG_PATH is readable and the first line parses as JSON"
else
  warn "first line of $COWRIE_LOG_PATH did not parse as JSON - confirm Cowrie's json logger is enabled"
fi

# wazuh-logcollector runs as root, so the setfacl grants added for the dashboard
# user are not required here. Verified above rather than assumed.

# ---------------------------------------------------------------------------
log "2/5  Wazuh apt repository"
# ---------------------------------------------------------------------------
if [[ ! -f /usr/share/keyrings/wazuh.gpg ]]; then
  apt-get install -y -qq curl gnupg apt-transport-https
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 644 /usr/share/keyrings/wazuh.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq

# ---------------------------------------------------------------------------
log "3/5  Install agent ${WAZUH_AGENT_VERSION}"
# ---------------------------------------------------------------------------
if ! apt-cache madison wazuh-agent | grep -q " ${WAZUH_AGENT_VERSION} "; then
  warn "version ${WAZUH_AGENT_VERSION} is not in the repository. Available:"
  apt-cache madison wazuh-agent | head -10
  die "Pick one with WAZUH_AGENT_VERSION=... and re-run (it must match the manager's major.minor)"
fi

if dpkg -s wazuh-agent >/dev/null 2>&1; then
  echo "    already installed: $(dpkg-query -W -f='${Version}' wazuh-agent)"
  echo "    repointing agent at ${WAZUH_MANAGER}"
  systemctl stop wazuh-agent || true
  # <address> lives inside the <client><server> block of the shipped config.
  sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|" "$OSSEC_CONF"
else
  apt-mark unhold wazuh-agent >/dev/null 2>&1 || true
  # WAZUH_MANAGER at install time writes the server address and enrols the agent
  # against the manager's authd on 1515.
  WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y -qq "wazuh-agent=${WAZUH_AGENT_VERSION}"
fi
# Pin: an unattended-upgrade that drifts the agent past the manager's version is a
# silent ingestion failure waiting to happen.
apt-mark hold wazuh-agent >/dev/null

# ---------------------------------------------------------------------------
log "4/5  Point the agent at cowrie.json"
# ---------------------------------------------------------------------------
if grep -qF "<location>${COWRIE_LOG_PATH}</location>" "$OSSEC_CONF"; then
  echo "    localfile block for ${COWRIE_LOG_PATH} already present"
else
  cp -n "$OSSEC_CONF" "${OSSEC_CONF}.pre-cowrie"
  # Wazuh allows multiple top-level <ossec_config> blocks, so appending is clean
  # and does not require surgery on the shipped configuration.
  cat >> "$OSSEC_CONF" <<LOCALFILE

<!-- Cowrie honeypot - added by wazuh/agent/install-agent.sh -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>${COWRIE_LOG_PATH}</location>
  </localfile>
</ossec_config>
LOCALFILE
  echo "    appended localfile block (original saved as ${OSSEC_CONF}.pre-cowrie)"
fi

# ---------------------------------------------------------------------------
log "5/5  Start and verify"
# ---------------------------------------------------------------------------
systemctl daemon-reload
systemctl enable --now wazuh-agent >/dev/null
systemctl restart wazuh-agent

echo "    waiting for the agent to report a connection (up to 60s)"
CONNECTED=0
for _ in $(seq 1 20); do
  if grep -q 'Connected to the server' /var/ossec/logs/ossec.log 2>/dev/null; then
    CONNECTED=1; break
  fi
  sleep 3
done

cat <<SUMMARY

------------------------------------------------------------------------------
 Agent:    $(dpkg-query -W -f='${Version}' wazuh-agent)  (held at this version)
 Manager:  ${WAZUH_MANAGER}
 Watching: ${COWRIE_LOG_PATH}
 Service:  $(systemctl is-active wazuh-agent)
SUMMARY

if [[ $CONNECTED -eq 1 ]]; then
  echo " Status:   connected to the manager"
else
  warn "no 'Connected to the server' line yet. Check, in this order:"
  echo "     tail -50 /var/ossec/logs/ossec.log"
  echo "     nc -zv ${WAZUH_MANAGER} 1514      # NSG must allow this VM's private ip"
  echo "     nc -zv ${WAZUH_MANAGER} 1515      # required for first enrollment"
fi
cat <<'SUMMARY2'

 NEXT: confirm the agent shows Active in the Wazuh dashboard under Agents,
 then run wazuh/scripts/verify_rules.sh on the manager.
------------------------------------------------------------------------------
SUMMARY2
