#!/usr/bin/env bash
#
# setup-manager.sh - stand up the Wazuh single-node stack on the MANAGER VM.
#
# Run this on the dedicated Wazuh VM. Do NOT run it on the Cowrie VM: the whole
# point of the architecture is that the SIEM does not share a host with an
# intentionally internet-exposed honeypot.
#
# Idempotent - safe to re-run. Re-running after editing manager/rules/local_rules.xml
# is in fact how you deploy a rule change.
#
#   sudo ./setup-manager.sh
#
set -euo pipefail

WAZUH_DOCKER_TAG="${WAZUH_DOCKER_TAG:-v4.14.7}"
WAZUH_DOCKER_DIR="${WAZUH_DOCKER_DIR:-/opt/wazuh-docker}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_FILE="${REPO_DIR}/manager/rules/local_rules.xml"
OVERRIDE_FILE="${REPO_DIR}/manager/docker-compose.override.yml"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo $0)"
[[ -f "$RULES_FILE" ]] || die "Rule file not found: $RULES_FILE"

# ---------------------------------------------------------------------------
log "1/7  Docker"
# ---------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "    docker + compose plugin already present: $(docker --version)"
else
  echo "    installing Docker CE from the official repository"
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$(. /etc/os-release && echo "$VERSION_CODENAME")" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi

# ---------------------------------------------------------------------------
log "2/7  Kernel tuning (vm.max_map_count)"
# ---------------------------------------------------------------------------
# The indexer creates a very large number of virtual memory areas; the Linux
# default of 65530 is far below what it needs and the container will refuse to
# start without this. Persisted so it survives a reboot.
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-wazuh-indexer.conf
sysctl -q -w vm.max_map_count=262144
echo "    vm.max_map_count = $(sysctl -n vm.max_map_count)"

# ---------------------------------------------------------------------------
log "3/7  wazuh-docker @ ${WAZUH_DOCKER_TAG}"
# ---------------------------------------------------------------------------
# Pinned to an explicit tag, never 'latest'. The agent on the Cowrie VM is pinned
# to the matching major.minor - version drift between agent and manager is a
# classic source of silent ingestion failure.
if [[ -d "${WAZUH_DOCKER_DIR}/.git" ]]; then
  echo "    already cloned, ensuring tag ${WAZUH_DOCKER_TAG}"
  git -C "$WAZUH_DOCKER_DIR" fetch --tags --quiet
  git -C "$WAZUH_DOCKER_DIR" checkout --quiet "tags/${WAZUH_DOCKER_TAG}"
else
  apt-get install -y -qq git
  git clone --quiet --depth 1 --branch "$WAZUH_DOCKER_TAG" \
    https://github.com/wazuh/wazuh-docker.git "$WAZUH_DOCKER_DIR"
fi
SINGLE_NODE="${WAZUH_DOCKER_DIR}/single-node"
[[ -d "$SINGLE_NODE" ]] || die "single-node/ missing in $WAZUH_DOCKER_DIR"

# ---------------------------------------------------------------------------
log "4/7  Manager config: enable JSON archives"
# ---------------------------------------------------------------------------
# See manager/wazuh_manager.conf.snippet for the reasoning. Without this, an
# empty dashboard is ambiguous between "agent not shipping", "decoder not
# parsing" and "rules not matching".
MGR_CONF="${SINGLE_NODE}/config/wazuh_cluster/wazuh_manager.conf"
if [[ -f "$MGR_CONF" ]]; then
  if grep -q '<logall_json>yes</logall_json>' "$MGR_CONF"; then
    echo "    logall_json already enabled"
  else
    cp -n "$MGR_CONF" "${MGR_CONF}.orig"
    sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' "$MGR_CONF"
    grep -q '<logall_json>yes</logall_json>' "$MGR_CONF" \
      && echo "    logall_json enabled (original saved as ${MGR_CONF}.orig)" \
      || warn "could not enable logall_json automatically - set it by hand in $MGR_CONF"
  fi
else
  warn "manager config not found at $MGR_CONF - skipping archive setup"
fi

# ---------------------------------------------------------------------------
log "5/7  Deploy Cowrie rules as a read-only bind mount"
# ---------------------------------------------------------------------------
cp "$OVERRIDE_FILE" "${SINGLE_NODE}/docker-compose.override.yml"
# Compose resolves ${COWRIE_RULES_PATH} from this .env, so the committed override
# file stays free of machine-specific absolute paths.
printf 'COWRIE_RULES_PATH=%s\n' "$RULES_FILE" > "${SINGLE_NODE}/.env"
echo "    rules: ${RULES_FILE}"
echo "    -> /var/ossec/etc/rules/local_rules.xml (ro)"

# ---------------------------------------------------------------------------
log "6/7  Certificates"
# ---------------------------------------------------------------------------
CERT_DIR="${SINGLE_NODE}/config/wazuh_indexer_ssl_certs"
if compgen -G "${CERT_DIR}/*.pem" >/dev/null 2>&1; then
  echo "    certificates already generated, leaving them alone"
else
  (cd "$SINGLE_NODE" && docker compose -f generate-indexer-certs.yml run --rm generator)
fi

# ---------------------------------------------------------------------------
log "7/7  Bring up the stack"
# ---------------------------------------------------------------------------
(cd "$SINGLE_NODE" && docker compose up -d)

echo
echo "    waiting for the manager to accept agent connections on 1514 (up to 5 min)"
for i in $(seq 1 60); do
  if (cd "$SINGLE_NODE" && docker compose exec -T wazuh.manager \
        /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'wazuh-remoted is running'); then
    echo "    manager is up after ~$((i*5))s"
    break
  fi
  [[ $i -eq 60 ]] && warn "manager did not report ready in time - check: cd $SINGLE_NODE && docker compose logs wazuh.manager"
  sleep 5
done

(cd "$SINGLE_NODE" && docker compose ps)

PUBLIC_IP="$(curl -s --max-time 5 https://api.ipify.org || echo '<manager-public-ip>')"
PRIVATE_IP="$(hostname -I | awk '{print $1}')"

cat <<SUMMARY

------------------------------------------------------------------------------
 Wazuh manager is up.

   Dashboard   https://${PUBLIC_IP}       (must be NSG-restricted to your IP)
   Agent port  ${PRIVATE_IP}:1514         <- give this PRIVATE ip to install-agent.sh
   Enrollment  ${PRIVATE_IP}:1515

 NEXT
   1. Confirm NSG rules are in place  -> wazuh/docs/azure-nsg.md
   2. CHANGE THE DEFAULT PASSWORD. The stack ships with admin/SecretPassword.
      https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
   3. Install the agent on the COWRIE VM:
        sudo WAZUH_MANAGER=${PRIVATE_IP} ./wazuh/agent/install-agent.sh
   4. Once the agent is Active, validate the rules:
        sudo ./wazuh/scripts/verify_rules.sh
------------------------------------------------------------------------------
SUMMARY
