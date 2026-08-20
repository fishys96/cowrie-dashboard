# Azure networking for the SOC lab

Everything here runs from your workstation with the Azure CLI (`az login` first).
Replace the `<...>` placeholders once, at the top, and the rest copy-pastes.

```bash
RG=<resource-group>
COWRIE_VM=<existing-cowrie-vm-name>
MGR_VM=wazuh-mgr
MY_IP=$(curl -s https://api.ipify.org)     # your workstation's public ip
```

---

## 1. Discover before you create

The manager must land in the **same VNet** as the honeypot so the two can talk over
private IPs. Find out what the Cowrie VM is actually attached to — don't assume.

```bash
az vm show -g "$RG" -n "$COWRIE_VM" --show-details \
  --query "{location:location, privateIps:privateIps, publicIps:publicIps, nics:networkProfile.networkInterfaces[].id}" -o json
```

```bash
az network vnet list -g "$RG" -o table
az network vnet subnet list -g "$RG" --vnet-name <vnet-name> -o table
```

Record these — the rest of the build depends on them:

| Value | Where it's used |
|---|---|
| Cowrie VM **private** IP | source restriction on the manager's 1514/1515 rules |
| VNet + subnet name | where the manager VM gets created |
| Location | must match, for same-VNet placement |

---

## 2. Create the manager VM

```bash
az vm create \
  -g "$RG" -n "$MGR_VM" \
  --image Ubuntu2204 \
  --size Standard_B2ms \
  --os-disk-size-gb 64 \
  --vnet-name <vnet-name> --subnet <subnet-name> \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-sku Standard \
  --nsg-rule NONE
```

Notes on each non-obvious flag:

- **`--size Standard_B2ms`** — 2 vCPU / 8 GiB burstable. Wazuh publishes 4 vCPU / 8 GiB as the
  all-in-one minimum for 1–25 agents. With exactly one agent this is fine, and the indexer heap
  is pinned to 1 GB in `manager/docker-compose.override.yml` to keep it inside the RAM budget.
  It is a documented compromise, not an accident. If `docker stats` shows sustained pressure
  after a day of real ingestion, `az vm resize --size Standard_D4s_v3`.
- **`--os-disk-size-gb 64`** — the default 30 GB will not survive the indexer plus
  `archives.json`. See the archive note in `manager/wazuh_manager.conf.snippet`.
- **`--nsg-rule NONE`** — suppresses Azure's default "SSH open to the internet" rule. Rules are
  added explicitly below. This is deliberate: an accidental `0.0.0.0/0` on the SIEM is exactly
  the failure this whole two-VM architecture exists to avoid.

Then capture the addresses:

```bash
MGR_PRIVATE=$(az vm show -g "$RG" -n "$MGR_VM" --show-details --query privateIps -o tsv)
MGR_PUBLIC=$(az vm show  -g "$RG" -n "$MGR_VM" --show-details --query publicIps  -o tsv)
COWRIE_PRIVATE=$(az vm show -g "$RG" -n "$COWRIE_VM" --show-details --query privateIps -o tsv)
NSG=$(az network nsg list -g "$RG" --query "[?contains(name,'${MGR_VM}')].name" -o tsv)
echo "manager  private=$MGR_PRIVATE public=$MGR_PUBLIC nsg=$NSG"
echo "cowrie   private=$COWRIE_PRIVATE"
```

---

## 3. NSG rules — manager VM only

Four rules, each source-restricted to a single `/32`. Nothing here is open to the internet.

```bash
# Agent -> manager event channel. Private ip only; this never traverses the internet.
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-wazuh-agent-events \
  --priority 100 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "${COWRIE_PRIVATE}/32" --destination-port-ranges 1514

# Agent enrollment (authd). Only needed for the first registration - see step 5.
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-wazuh-agent-enroll \
  --priority 110 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "${COWRIE_PRIVATE}/32" --destination-port-ranges 1515

# Wazuh dashboard. This one is NOT a honeypot - lock it to your workstation.
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-wazuh-dashboard \
  --priority 120 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "${MY_IP}/32" --destination-port-ranges 443

# Admin SSH.
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n allow-admin-ssh \
  --priority 130 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "${MY_IP}/32" --destination-port-ranges 22
```

### What is deliberately *not* here

| | Why not |
|---|---|
| **No rule for 55000** (Wazuh API) | The dashboard container reaches the manager over the internal Docker bridge network. Nothing outside the VM needs the API, so it gets no path in. |
| **No new inbound rules on the Cowrie VM** | The agent *initiates* the connection outbound to the manager. Azure allows outbound by default. Adding an inbound rule to the honeypot for this would widen its attack surface for no reason. |
| **No `0.0.0.0/0` anywhere** | If your workstation IP is dynamic, re-run the `MY_IP` capture and `az network nsg rule update ... --source-address-prefixes`. Do not "fix" this by opening it up. |

---

## 4. Verify the rules actually do what you think

```bash
# From the COWRIE VM - both must connect:
nc -zv "$MGR_PRIVATE" 1514
nc -zv "$MGR_PRIVATE" 1515

# From the COWRIE VM - must NOT connect (dashboard is not for the honeypot):
nc -zv -w 3 "$MGR_PRIVATE" 443

# From your workstation - must load:
curl -kI "https://$MGR_PUBLIC"

# From anywhere else (phone hotspot, or an external port checker) - must be refused/filtered:
#   https://$MGR_PUBLIC   -> timeout
```

Confirm the honeypot gained nothing new:

```bash
az network nsg rule list -g "$RG" \
  --nsg-name "$(az network nsg list -g "$RG" --query "[?contains(name,'${COWRIE_VM}')].name" -o tsv)" \
  -o table
```

---

## 5. After the agent is enrolled

Enrollment (1515) is a one-time handshake. Once the agent shows **Active** in the dashboard,
close it — the event channel on 1514 is all that's needed from then on:

```bash
az network nsg rule update -g "$RG" --nsg-name "$NSG" -n allow-wazuh-agent-enroll --access Deny
```

Re-enable it temporarily if you ever rebuild the agent or reset the manager's agent database.

---

## Fallback: the VMs ended up in different VNets

Peer them rather than routing manager traffic over public IPs:

```bash
az network vnet peering create -g "$RG" -n cowrie-to-wazuh \
  --vnet-name <cowrie-vnet> --remote-vnet <wazuh-vnet-id> --allow-vnet-access
az network vnet peering create -g "$RG" -n wazuh-to-cowrie \
  --vnet-name <wazuh-vnet> --remote-vnet <cowrie-vnet-id> --allow-vnet-access
```

Peering is bidirectional only when both directions exist — creating one side silently gives you
a half-open path that fails in a confusing way. The private IPs and NSG rules above are
unchanged afterwards.
