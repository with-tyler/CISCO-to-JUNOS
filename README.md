# Cisco to Junos Converter

**Convert Cisco IOS switch configurations to Juniper Mist templates with a single command.**

This tool automates the migration from Cisco IOS switches to Juniper Mist-managed switches by parsing your existing Cisco `show run` configurations and generating ready-to-deploy Mist JSON templates.

## What Does This Tool Do?

### Input: Cisco IOS Configuration Files
Place your Cisco switch configurations in a directory:
```
configs/
├── switch1-show-run.txt
├── switch2-show-run.txt
└── switch3-show-run.txt
```

### Output: Mist-Ready JSON Template
Get a complete Mist network template with:
- ✅ All VLANs configured as networks
- ✅ Port profiles for access/trunk ports
- ✅ Switch matching rules with proper port assignments
- ✅ Spanning tree settings (portfast, BPDU guard)
- ✅ DNS, NTP, and RADIUS configuration
- ✅ Ready to import into Mist dashboard

### Why Use This Tool?

**Manual Migration Pain Points:**
- 🔴 Hours spent manually recreating switch configs in Mist
- 🔴 Typos and configuration errors during manual entry
- 🔴 Inconsistent VLAN/port naming across switches
- 🔴 Difficulty merging configs from multiple switches

**This Tool Solves:**
- ✅ **Automated parsing** - Reads Cisco `show run` output directly
- ✅ **Intelligent merging** - Combines multiple switch configs into one template
- ✅ **Conflict resolution** - Interactive prompts when configs differ
- ✅ **Schema validation** - Ensures Mist API compliance
- ✅ **Time savings** - Minutes instead of hours

## Key Features

### 🔍 Comprehensive Cisco Config Parsing (95% API Coverage)

**Core Switching (4 features):**
- **VLANs**: ID, name, state (active/suspend), pruning eligibility
- **Interfaces**: FastEthernet, GigabitEthernet, TenGigabit, automatic range expansion
- **Access Ports**: VLAN assignment, portfast, BPDU guard, voice VLAN
- **Trunk Ports**: Native VLAN, allowed VLANs list, encapsulation (dot1q)

**Advanced Interface Features (8 features):**
- **Voice VLAN**: Separate voice network for IP phones
- **Speed & Duplex**: Port speed (10/100/1000/10000/auto) and duplex (full/half/auto)
- **PoE Configuration**: Power inline settings, priority (critical/high/low)
- **Port Security**: MAC address limiting, maximum MAC addresses per port
- **802.1X Authentication**: Dot1x PAE, port-control (auto/force-authorized/force-unauthorized), MAB, periodic reauthentication
- **DHCP Snooping Trust**: Per-port trusted DHCP server setting
- **Storm Control**: Broadcast, multicast, and unknown unicast thresholds
- **Port Descriptions**: Interface description text preserved

**Routing & Network Services (4 features):**
- **Static Routes**: IPv4 and IPv6 routes with next-hop, administrative distance, null routes
- **OSPF**: Areas, networks, passive interfaces, per-interface authentication/timers/cost
- **DHCP Snooping**: Global enable, per-VLAN configuration, MAC verification
- **VRF Instances**: VRF definitions with route distinguisher, IPv4/IPv6 address families

**Security & Access Control (3 features):**
- **RADIUS**: Authentication/accounting servers, timeout, retries, source interface, per-server keys
- **ACL Policies**: Extended access lists with permit/deny rules, protocol/source/destination filtering
- **TACACS+**: Server configuration with authentication keys

**Monitoring & Management (3 features):**
- **SNMP**: Communities (RO/RW), location, contact, trap hosts with versioning
- **Remote Syslog**: Multiple syslog servers with severity and facility settings
- **Port Mirroring (SPAN)**: Monitor sessions with source/destination ports and VLANs

**Switch Management (3 features):**
- **Banners**: Login, MOTD, and exec banners preserved
- **Local Users**: Username/privilege/password with role mapping (admin/helpdesk/read)
- **Line Configuration**: VTY timeout, console settings

**Spanning Tree (1 feature):**
- **Advanced STP**: Mode (RSTP/MSTP), per-VLAN priorities, portfast/BPDU guard defaults

**Total: 26 features fully implemented** ✅

### 🔄 Intelligent Merging
- Combines multiple switch configs into single template
- Detects and prompts for conflicting settings
- Maintains per-switch port configurations

### ⚙️ Interactive Configuration
- DNS servers (with Mist template variables)
- NTP servers
- RADIUS authentication and accounting
- Switch matching role selection (access, core, distribution, edge)
- Custom Junos CLI commands
- Timezone settings

### 🎯 Mist Integration
- Generates schema-compliant JSON
- Switch matching with port ranges (ge-1/0/1-15)
- Port profiles grouped by configuration
- Template variables for multi-site deployment
- Direct API submission or export to file

---

## Quick Start

### 1. Install Dependencies

```bash
# Clone or download the repository
cd "CISCO to JUNOS"

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

**Requirements:**
- Python 3.8+
- `mistapi>=0.10.0` - Mist API integration
- `python-dotenv>=1.0.0` - Credentials management
- `questionary>=2.0.0` - Interactive prompts

### 2. Set Up Mist Credentials

The tool supports **two authentication methods**:

#### Option A: API Token (Recommended)

Create a `.env` file in the project root:

```bash
# Get your API token from the Mist dashboard:
# https://manage.mist.com/admin/?org_id=YOUR_ORG_ID#!api
MIST_API_KEY=your-mist-api-token
MIST_HOST=api.mist.com
```

**How to Generate a Mist API Token:**

1. Log into the Mist dashboard: https://manage.mist.com
2. Navigate to **Organization > Settings**
3. Click on **API Tokens** in the left menu
4. Click **Create New Token**
5. Give it a name (e.g., "Cisco to Junos Converter")
6. Copy the token and paste it into your `.env` file

> **Security Note:** API tokens have the same permissions as your user account. Keep them secure and don't commit them to version control.

#### Option B: Email/Password (Supports 2FA)

Alternatively, use email and password authentication:

```bash
MIST_EMAIL=your-email@example.com
MIST_PASSWORD=your-password
MIST_HOST=api.mist.com
```

This method supports **two-factor authentication (2FA)**. If your account has 2FA enabled, you'll be prompted during login.

> **Note:** Password is stored in plaintext in `.env`. For better security, use API tokens or interactive login.

#### Option C: Interactive Login

If you skip the `.env` file, the tool uses **mistapi's interactive login** which prompts for credentials:

```
⚠️  No .env file found

🔐 Interactive Login

Mist supports two authentication methods:
  1. Email/Password (supports 2FA)
  2. API Token (from Mist dashboard)

Please follow the prompts...

? Mist Host: api.mist.com
# mistapi will then prompt for your preferred auth method
✓ Authentication successful
```

**Benefits of Interactive Login:**
- ✅ Choose authentication method at runtime (email/password or API token)
- ✅ Automatic 2FA handling
- ✅ No credentials stored in files
- ✅ Powered by mistapi's battle-tested login flow


### 3. Prepare Your Cisco Configs

Put your Cisco `show run` output files in a directory:

```bash
mkdir my-switches
# Copy your Cisco config files here (*.txt or *.cfg)
cp switch1-config.txt my-switches/
cp switch2-config.txt my-switches/
```

### 4. Run the Converter

**Start with dry-run mode** (recommended for first use):

```bash
python -m cisco_to_junos.cli my-switches/ --dry-run
```

This will:
1. Parse all Cisco configs in `my-switches/`
2. Merge them into a single template
3. Prompt for DNS, NTP, RADIUS settings
4. Prompt for switch matching role
5. Save output to `mist_template.json`
6. **Not submit** to Mist (just validate credentials)

**Review and submit when ready:**

```bash
# Review the generated template
cat mist_template.json

# Submit to Mist
python -m cisco_to_junos.cli my-switches/ --org-id YOUR_ORG_ID
```

---

## Usage Examples

### Basic Workflow

```bash
# 1. Test conversion without submitting
python -m cisco_to_junos.cli configs/ --dry-run

# 2. Review generated template
cat mist_template.json

# 3. Submit to Mist when satisfied
python -m cisco_to_junos.cli configs/ --org-id abc123def456
```

### Skip Interactive Prompts

```bash
# Use defaults for everything (fully automated)
python -m cisco_to_junos.cli configs/ --no-interactive --dry-run

# Skip only DNS/NTP/RADIUS prompts (keep conflict resolution)
python -m cisco_to_junos.cli configs/ --skip-additional-config --dry-run
```

### Custom Output File

```bash
# Export to specific file
python -m cisco_to_junos.cli configs/ -o campus-switches.json --dry-run
```

### Complete Command Reference

| Flag | Description | Default |
|------|-------------|---------|
| `config_dir` | Directory with Cisco configs (`.txt`, `.cfg`) | **Required** |
| `-o, --output` | Output JSON file path | `mist_template.json` |
| `--dry-run` | Validate and export without submitting | Submit to Mist |
| `--no-interactive` | Skip all prompts, use defaults | Interactive |
| `--skip-additional-config` | Skip DNS/NTP/RADIUS/role prompts | Prompt for all |
| `--org-id` | Mist organization ID | Prompt if needed |
| `--env-file` | Path to credentials file | `.env` |

---

## Understanding the Conversion

### What Gets Converted

#### From Cisco Config:
```cisco
vlan 10
 name Engineering

interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable

interface GigabitEthernet1/0/23
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 10,20,30-40
```

#### To Mist Template:
```json
{
  "networks": {
    "Engineering": {
      "vlan_id": 10,
      "subnet": ""
    }
  },
  "port_usages": {
    "Access-VLAN10-Portfast-BPDUGuard": {
      "mode": "access",
      "networks": ["Engineering"],
      "stp_edge": true,
      "enable_bpdu_guard": true,
      "disable_autoneg": true
    },
    "Trunk-VLANs-10-40": {
      "mode": "trunk",
      "all_networks": false,
      "networks": ["Engineering", "VLAN20", "VLAN30-40"],
      "native_network": "VLAN1"
    }
  },
  "switch_matching": {
    "enable": true,
    "rules": [{
      "match_role": "access",
      "port_config": {
        "ge-1/0/5": {
          "usage": "Access-VLAN10-Portfast-BPDUGuard"
        },
        "ge-1/0/23": {
          "usage": "Trunk-VLANs-10-40"
        }
      }
    }]
  }
}
```

### Supported Cisco Features

**Core Layer 2 Switching:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `vlan X` + `name Y` | `networks: {"Y": {"vlan_id": X}}` | Suspended VLANs skipped |
| `interface range Gi1/0/1 - 15` | Expanded to individual ports | Each port gets same config |
| `switchport mode access` | `"mode": "access"` | Port profile mode |
| `switchport access vlan X` | `"networks": ["VLAN-Name"]` | Uses VLAN name |
| `switchport voice vlan X` | `"voip_network": "VLAN-X"` | Voice VLAN for IP phones |
| `switchport mode trunk` | `"mode": "trunk"` | Port profile mode |
| `switchport trunk allowed vlan 10,20,30-40` | `"networks": [...]` | Expands ranges |
| `switchport trunk native vlan X` | `"native_network": "..."` | Native VLAN reference |
| `switchport nonegotiate` | `"disable_autoneg": true` | Disable DTP negotiation |
| `shutdown` | `"disabled": true` | Port disabled |
| `description <text>` | `"description": "<text>"` | Port description |

**Interface Speed & PoE:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `speed 10\|100\|1000\|10000\|auto` | `"speed": "100m"\|"1g"\|"10g"\|"auto"` | Port speed setting |
| `duplex full\|half\|auto` | `"duplex": "full"\|"half"\|"auto"` | Duplex mode |
| `power inline never` | `"poe_disabled": true` | Disable PoE on port |
| `power inline static priority <level>` | PoE priority (additional_config_cmds) | Critical/high/low priority |

**Port Security & Authentication:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `switchport port-security` | `"mac_limit": X` | Enable port security |
| `switchport port-security maximum X` | `"mac_limit": X` | Max MAC addresses |
| `dot1x pae authenticator` | `"port_auth": {"enable": true}` | Enable 802.1X |
| `authentication port-control auto` | `"port_auth": {"control": "auto"}` | Port control mode |
| `mab` | `"port_auth": {"enable_mab": true}` | MAC Authentication Bypass |
| `authentication periodic` | `"port_auth": {"reauth_enabled": true}` | Periodic reauthentication |
| `authentication timer reauthenticate X` | `"port_auth": {"reauth_interval": X}` | Reauth timer (seconds) |
| `ip dhcp snooping trust` | `"allow_dhcpd": true` | Trusted DHCP port |

**Spanning Tree Protocol:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `spanning-tree mode rapid-pvst` | `"stp_config": {"mode": "rstp"}` | RSTP mode |
| `spanning-tree mode mst` | `"stp_config": {"mode": "mstp"}` | MSTP mode |
| `spanning-tree vlan X priority Y` | `"stp_config": {"vlan_config": {...}}` | Per-VLAN priority |
| `spanning-tree portfast` | `"stp_edge": true` | Portfast on interface |
| `spanning-tree bpduguard enable` | `"enable_bpdu_guard": true` | BPDU guard on interface |
| `spanning-tree portfast default` | `"stp_config": {...}` | Global portfast default |

**Storm Control:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `storm-control broadcast level X` | `"storm_control": {"no_broadcast": false, "percentage": X}` | Broadcast storm control |
| `storm-control multicast level X` | `"storm_control": {"no_multicast": false}` | Multicast storm control |
| `storm-control unicast level X` | `"storm_control": {"no_unknown_unicast": false}` | Unknown unicast storm control |

**Routing (IPv4 & IPv6):**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `ip route <net> <mask> <next-hop>` | `"extra_routes": [{"via": "..."}]` | Static IPv4 routes |
| `ip route <net> <mask> <next-hop> <distance>` | `"extra_routes": [{"via": "...", "preference": X}]` | With admin distance |
| `ip route <net> <mask> Null0` | `"extra_routes": [{"discard": true}]` | Null route (blackhole) |
| `ipv6 route <net>/<len> <next-hop>` | `"extra_routes6": [{"via": "..."}]` | Static IPv6 routes |
| `router ospf <id>` | `"ospf_areas": {...}` | OSPF configuration |
| `network <net> <wildcard> area <area>` | `"ospf_areas": {"<area>": {"networks": [...]}}` | OSPF networks |
| `passive-interface <if>` | OSPF passive interfaces | Parsed but limited API support |
| `ip ospf authentication message-digest` | Per-interface OSPF auth | Parsed but limited API support |

**Network Services:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `ip dhcp snooping` | `"dhcp_snooping": {"enabled": true}` | Global DHCP snooping |
| `ip dhcp snooping vlan X,Y` | `"dhcp_snooping": {"networks": ["X", "Y"]}` | Per-VLAN snooping |
| `ip dhcp snooping verify mac-address` | `"dhcp_snooping": {"enable_arp_spoof_check": true}` | MAC verification |
| `vrf definition <name>` | `"vrf_instances": {"<name>": {...}}` | VRF configuration |
| `rd <route-distinguisher>` | VRF route distinguisher | Parsed |
| `vrf forwarding <name>` | VRF interface assignment | Parsed |

**Security & AAA:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `radius-server host <ip>` | `"radius_config": {"auth_servers": [...]}` | RADIUS authentication |
| `radius-server host <ip> acct-port <port>` | `"radius_config": {"acct_servers": [...]}` | RADIUS accounting |
| `radius-server timeout <sec>` | `"radius_config": {"auth_servers_timeout": X}` | RADIUS timeout |
| `radius-server retransmit <count>` | `"radius_config": {"auth_servers_retries": X}` | RADIUS retries |
| `radius-server key <key>` | `"radius_config": {"auth_servers": [{"secret": "..."}]}` | RADIUS secret |
| `ip radius source-interface <if>` | `"radius_config": {"source_ip": "..."}` | RADIUS source IP |
| `tacacs-server host <ip>` | `"switch_mgmt": {"tacacs": {"auth_servers": [...]}}` | TACACS+ servers |
| `ip access-list extended <name>` | `"acl_policies": [{"name": "<name>", "actions": [...]}]` | Extended ACLs |
| `permit\|deny <proto> <src> <dst>` | ACL actions with protocol filtering | Full ACL entry support |

**Monitoring:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `snmp-server community <string> RO\|RW` | `"snmp_config": {"v2c_config": [...]}` | SNMP communities |
| `snmp-server location <text>` | `"snmp_config": {"location": "<text>"}` | SNMP location |
| `snmp-server contact <text>` | `"snmp_config": {"contact": "<text>"}` | SNMP contact |
| `snmp-server host <ip>` | `"snmp_config": {"trap_groups": [...]}` | SNMP trap hosts |
| `snmp-server enable traps` | SNMP trap categories | Trap enablement |
| `logging host <ip>` | `"remote_syslog": {"servers": [{"host": "<ip>"}]}` | Remote syslog |
| `monitor session <id> source interface <if>` | `"port_mirroring": {"<id>": {...}}` | Port mirroring (SPAN) |
| `monitor session <id> destination interface <if>` | Port mirror destination | SPAN destination |

**Switch Management:**

| Cisco Command | Mist Equivalent | Notes |
|---------------|-----------------|-------|
| `banner login ^...^` | `"switch_mgmt": {"cli_banner": "..."}` | Login banner |
| `banner motd ^...^` | Login banner (MOTD) | MOTD preserved as login banner |
| `username <name> privilege <level> secret <pass>` | `"switch_mgmt": {"local_accounts": {...}}` | Local user accounts |
| `privilege 15` → | `"role": "admin"` | Privilege 15 = admin role |
| `privilege 7-14` → | `"role": "helpdesk"` | Privilege 7-14 = helpdesk |
| `privilege 0-6` → | `"role": "read"` | Privilege 0-6 = read-only |
| `line vty 0 4` + `exec-timeout <min>` | `"switch_mgmt": {"cli_idle_timeout": X}` | VTY idle timeout |

---

### Features NOT Supported

These Cisco features **cannot be converted** due to lack of Mist API schema support:

❌ **QoS (Quality of Service)**
- `mls qos`, `priority-queue`, `class-map`, `policy-map`
- **Reason**: No QoS configuration schema in Mist Network Templates API

❌ **EtherChannel / Port-Channel (LAG)**
- `interface port-channel`, `channel-group`
- **Reason**: Limited LAG support in templates (per-switch configuration only)

❌ **HSRP / VRRP (First Hop Redundancy)**
- `standby`, `vrrp`
- **Reason**: No FHRP schema in Mist API

❌ **Policy-Based Routing (PBR)**
- `route-map`, `ip policy route-map`
- **Reason**: No route-map or PBR schema in templates

❌ **IP SLA**
- `ip sla`, `track`
- **Reason**: No IP SLA monitoring schema

❌ **Multicast Routing**
- `ip multicast-routing`, `ip pim`
- **Reason**: No multicast routing schema in templates

❌ **Dynamic ARP Inspection (DAI)**
- `ip arp inspection`
- **Reason**: No DAI schema (DHCP snooping is supported, but not ARP inspection)

❌ **IP Source Guard**
- `ip verify source`
- **Reason**: No IP source guard schema (parsed but not converted)

**Workaround**: Many unsupported features can be configured per-switch via:
- `additional_config_cmds` in template (Junos CLI commands)
- Per-switch configuration in Mist dashboard
- Custom scripts applied after template deployment

### Interface Range Expansion

The tool automatically expands Cisco interface ranges:

**Input:**
```cisco
interface range GigabitEthernet1/0/1 - 15
 switchport mode access
 switchport access vlan 10
```

**Result:** 15 individual port configs (Gi1/0/1, Gi1/0/2, ..., Gi1/0/15) all assigned to same port profile

### Port Name Conversion

Cisco interface names are converted to Juniper EX format:

| Cisco | Mist (Juniper) | Type |
|-------|----------------|------|
| `FastEthernet0/24` | `ge-0/0/24` | GigabitEthernet (normalized) |
| `GigabitEthernet1/0/5` | `ge-1/0/5` | GigabitEthernet |
| `TenGigabitEthernet0/1` | `xe-0/0/1` | 10 Gigabit Ethernet |

**Important Notes:**
- ⚠️ **Juniper switches do NOT use `fe-` prefix** - FastEthernet ports are mapped to `ge-` (GigabitEthernet) since modern Juniper EX switches start at Gigabit speeds
- The only Juniper interface with an `f` prefix is `fxp` (management interface), which is not used for switchports
- Cisco slot/port numbering (e.g., `1/0/5`) is normalized to Juniper fpc/pic/port format
- Two-part Cisco ports (e.g., `0/24`) are expanded to three parts with pic=0 (e.g., `ge-0/0/24`)

---

## Interactive Prompts Explained

### Switch Matching Role

**When:** During conversion, before additional config

**Prompt:**
```
🔀 Switch Matching Role
Select the role for switch matching rules:
? Switch role: (Use arrow keys)
  ❯ access
    core
    distribution
    edge
```

**Purpose:** Defines how switches are matched to this template in Mist
- **access**: Edge/access layer switches (most common)
- **core**: Core switches
- **distribution**: Distribution layer switches  
- **edge**: Edge switches

**Result:** Sets `match_role` in switch matching rules

### DNS Configuration

**When:** After conversion (if not skipped)

**Prompt:**
```
📡 DNS Servers
Examples: {{pridns}}, {{altdns}}, 8.8.8.8, 1.1.1.1
? Configure DNS servers? (y/N)
? Primary DNS server: 
? Secondary DNS server (optional):
```

**Options:**
- Enter template variables: `{{pridns}}`, `{{altdns}}`
- Enter actual IPs: `8.8.8.8`, `1.1.1.1`
- Press Enter to skip

**Result:** Adds `dns_servers` array to template

### NTP Configuration

**When:** After DNS prompts

**Prompt:**
```
🕐 NTP Servers
Examples: {{ntp1}}, {{ntp2}}, time.google.com, pool.ntp.org
? Configure NTP servers? (y/N)
? Primary NTP server:
? Secondary NTP server (optional):
```

**Options:**
- Template variables: `{{ntp1}}`, `{{ntp2}}`
- Hostnames: `time.google.com`, `pool.ntp.org`
- IPs: `132.163.96.1`

**Result:** Adds `ntp_servers` array to template

### RADIUS Configuration

**When:** After NTP prompts

**Prompt:**
```
🔐 RADIUS Configuration
? Configure RADIUS authentication? (y/N)

Authentication Servers:
Examples: {{radius_server}}, 10.1.1.100, radius.example.com
? RADIUS auth server (IP or hostname):
? RADIUS secret (example: {{radius_secret}}):
? Port: (1812)
```

**Features:**
- Multiple auth servers supported
- Optional accounting servers
- Advanced settings (timeouts, retries, CoA)
- Password fields hidden during input

**Result:** Adds complete `radius_config` object

### Custom Junos Commands

**When:** After RADIUS prompts

**Prompt:**
```
⚙️  Additional Junos Commands
These will be applied directly to switches via CLI.
? Add custom Junos CLI commands? (y/N)

Examples:
  - set system root-authentication ssh-rsa "key..."
  - set system services ssh root-login allow
  - set interfaces vlan unit 0 description "Management VLAN"

? Junos command:
```

**Use Cases:**
- SSH key configuration
- Enable SSH/HTTP services
- Interface descriptions
- Custom routing policies
- Static routes

**Result:** Adds to `additional_config_cmds` array

### Timezone

**When:** After custom commands

**Prompt:**
```
? Configure timezone? (y/N)
? Timezone (e.g., America/Los_Angeles, Europe/London): (America/New_York)
```

**Format:** Standard timezone names (America/Los_Angeles, Europe/London, Asia/Tokyo)

**Result:** Adds `set system time-zone <timezone>` to `additional_config_cmds`

---

## Template Variables for Multi-Site Deployment

Mist supports template variables that can be customized per-site deployment.

### Why Use Template Variables?

**Without Variables** (separate template per site):
```json
"dns_servers": ["8.8.8.8", "8.8.4.4"],
"networks": {
  "Management": {"vlan_id": 100, "subnet": "192.168.100.0/24"}
}
```

**With Variables** (one template for all sites):
```json
"dns_servers": ["{{pridns}}", "{{altdns}}"],
"networks": {
  "Management": {"vlan_id": "{{mgmt_vlan}}", "subnet": "{{mgmt_net}}.0/24"}
}
```

Then define per-site:
- **Site A**: `pridns=8.8.8.8`, `mgmt_vlan=100`, `mgmt_net=192.168.100`
- **Site B**: `pridns=1.1.1.1`, `mgmt_vlan=200`, `mgmt_net=10.10.200`

### Common Template Variables

| Variable | Purpose | Example Value |
|----------|---------|---------------|
| `{{pridns}}` | Primary DNS | `8.8.8.8` |
| `{{altdns}}` | Secondary DNS | `8.8.4.4` |
| `{{ntp1}}` | Primary NTP | `time.google.com` |
| `{{ntp2}}` | Secondary NTP | `pool.ntp.org` |
| `{{radius_server}}` | RADIUS server | `10.1.1.100` |
| `{{radius_secret}}` | RADIUS secret | `MySecretKey123` |
| `{{mgmt_vlan}}` | Management VLAN ID | `100` |
| `{{mgmt_net}}` | Management subnet prefix | `192.168.100` |
| `{{client_vlan}}` | Client VLAN ID | `10` |
| `{{guest_vlan}}` | Guest VLAN ID | `20` |

### Defining Variables in Mist

1. Log into Mist dashboard
2. Navigate to **Organization > Settings > Template Variables**
3. Click **Add Variable**
4. Enter variable name (e.g., `pridns`) and default value
5. Override per-site when assigning template

---

## Conflict Resolution

When merging multiple Cisco configs, the tool detects conflicts and prompts for resolution.

### Example: Different Management VLANs

**Switch 1:**
```cisco
interface Vlan100
 ip address 192.168.100.1 255.255.255.0
```

**Switch 2:**
```cisco
interface Vlan200
 ip address 10.10.200.1 255.255.255.0
```

**Prompt:**
```
⚠️  Conflict: Management VLAN

Source 1: VLAN 100, IP 192.168.100.1
Source 2: VLAN 200, IP 10.10.200.1

? Which configuration should be used?
  ❯ Source 1 (switch1.txt)
    Source 2 (switch2.txt)
```

**Result:** Selected configuration used in final template

### Conflict Types Detected

- **VLAN Definitions**: Same VLAN ID with different names
- **Interface Configs**: Same interface with different settings
- **Management Settings**: Different management IPs/gateways

### Non-Interactive Mode

Use `--no-interactive` to automatically choose first source for all conflicts:

```bash
python -m cisco_to_junos.cli configs/ --no-interactive --dry-run
```

---

## Validation and Export

### Automatic Validation

The tool validates templates against Mist API requirements:

```
✅ Validating template...
   ✓ Template is valid
```

**Checks:**
- Required fields present (name, device_type)
- Networks have valid VLAN IDs
- Port profiles reference valid networks
- Switch matching rules properly formatted

### Export Options

**Default export:**
```bash
python -m cisco_to_junos.cli configs/ --dry-run
# Creates: mist_template.json
```

**Custom file:**
```bash
python -m cisco_to_junos.cli configs/ -o campus-template.json --dry-run
```

**Review before submission:**
```bash
# Generate template
python -m cisco_to_junos.cli configs/ --dry-run -o review.json

# Inspect
cat review.json | jq .

# Submit when ready
python -m cisco_to_junos.cli configs/ --org-id YOUR_ORG_ID
```

---

## Troubleshooting

### Parsing Issues

**Problem:** Interface ranges not parsing
```
Error parsing switch1.txt: interface range not recognized
```

**Solution:** Check Cisco IOS format. Supported patterns:
```cisco
interface range GigabitEthernet1/0/1 - 15
interface range Gi1/0/1-15
interface range FastEthernet0/1 - 24
```

**Problem:** VLAN list parsing fails
```
Error: Could not parse allowed VLANs
```

**Solution:** Ensure no unsupported characters after VLAN list:
```cisco
# Good:
switchport trunk allowed vlan 10,20,30-40

# Also works (comment stripped automatically):
switchport trunk allowed vlan 10,20,30 ! Production VLANs
```

### Authentication Issues

**Problem:** Authentication failed
```
❌ Authentication failed
```

**Solutions:**
1. Check `.env` file exists and has correct credentials
2. Verify API key is valid in Mist dashboard
3. Try interactive login: delete `.env` temporarily
4. Use specific env file: `--env-file /path/to/.env`

**Problem:** Can't connect to Mist API
```
Error: Could not reach api.mist.com
```

**Solutions:**
1. Check internet connectivity
2. Verify firewall allows HTTPS to api.mist.com
3. Check `MIST_HOST` in `.env` is correct

### Template Issues

**Problem:** Missing VLAN references in port profiles
```
⚠️  Validation warnings:
  - Port profile 'Access-VLAN10' references non-existent network 'VLAN10'
```

**Solution:** Check if VLAN was marked as "suspend" in Cisco config (suspended VLANs are skipped)

**Problem:** Duplicate DNS servers in output
```json
"dns_servers": ["1.1.1.1", "1.1.1.1"]
```

**Solution:** Enter different values for primary and secondary, or press Enter to skip secondary

---

## Project Structure

```
cisco_to_junos/
├── __init__.py
├── parser.py                    # Core Cisco IOS parser
│   ├── CiscoConfigParser
│   ├── 17 dataclasses (VLANConfig, InterfaceConfig, StaticRoute, OSPFConfig, etc.)
│   ├── Parse VLANs, interfaces, trunks, STP
│   ├── Expand interface ranges
│   └── 25+ interface fields (mode, VLANs, voice, speed, duplex, PoE, 802.1X, etc.)
├── parser_extensions.py         # Extended parsing (~800 lines)
│   ├── parse_static_routes()   # IPv4/IPv6 static routes
│   ├── parse_ospf()            # OSPF configuration
│   ├── parse_ospf_interfaces() # Per-interface OSPF settings
│   ├── parse_radius()          # RADIUS servers and settings
│   ├── parse_snmp()            # SNMP communities, traps, location
│   ├── parse_dhcp_snooping()   # DHCP snooping configuration
│   ├── parse_vrfs()            # VRF definitions
│   ├── parse_access_lists()    # Extended ACLs
│   ├── parse_port_mirroring()  # SPAN/monitor sessions
│   ├── parse_syslog()          # Remote syslog servers
│   ├── parse_banner()          # Login/MOTD/exec banners
│   ├── parse_local_users()     # Local user accounts
│   ├── parse_line_configs()    # VTY/console line settings
│   ├── parse_tacacs()          # TACACS+ servers
│   └── parse_stp()             # Advanced STP configuration
├── converter.py                 # Convert to Mist JSON format
│   ├── MistConverter
│   ├── convert()               # Orchestrates all conversions
│   ├── Generate networks, port profiles
│   ├── Create switch matching rules
│   └── Integrate all converter_extensions
├── converter_extensions.py      # Conversion functions (~700 lines)
│   ├── convert_static_routes() # IPv4/IPv6 routes → extra_routes
│   ├── convert_ospf()          # OSPF → ospf_areas
│   ├── convert_radius()        # RADIUS → radius_config
│   ├── convert_snmp()          # SNMP → snmp_config
│   ├── convert_dhcp_snooping() # DHCP snooping config
│   ├── convert_vrfs()          # VRF → vrf_instances
│   ├── convert_acls()          # ACLs → acl_policies
│   ├── convert_port_mirroring() # SPAN → port_mirroring
│   ├── convert_syslog()        # Syslog → remote_syslog
│   ├── convert_switch_mgmt()   # Banner/users/TACACS → switch_mgmt
│   ├── convert_stp()           # STP → stp_config
│   └── enhance_port_profile_with_advanced_features()
├── merger.py                    # Merge multiple configs with conflict resolution
│   ├── ConfigMerger
│   ├── Merge VLANs, interfaces, management
│   └── Interactive conflict prompts (questionary)
├── auth.py                      # Mist API authentication
│   ├── MistAuthenticator
│   ├── Load .env credentials
│   └── Interactive login fallback
├── interactive_config.py        # Additional configuration prompts
│   ├── InteractiveConfigPrompts
│   ├── DNS, NTP, RADIUS, role selection
│   └── Custom Junos commands
└── cli.py                       # Command-line interface
    ├── Argument parsing (argparse)
    ├── Workflow orchestration
    └── Validation and export

examples/                        # Sample Cisco configs
.env.example                     # Credentials template
requirements.txt                 # Python dependencies
FEATURE_COVERAGE_ANALYSIS.md     # API coverage analysis
IMPLEMENTATION_STATUS.md         # Complete feature documentation
```

### Code Statistics

- **Total Lines**: ~3,000+ lines of production code
- **Dataclasses**: 17 (comprehensive Cisco config representation)
- **Parsing Functions**: 14 (extracting all Cisco features)
- **Conversion Functions**: 13 (transforming to Mist JSON)
- **Interface Fields**: 25+ (complete port configuration)
- **Cisco Commands**: 100+ supported patterns
- **Mist API Coverage**: ~95% of Network Templates API

---

## Advanced Usage

### Programmatic Usage

```python
from cisco_to_junos.parser import CiscoConfigParser
from cisco_to_junos.converter import MistConverter
from cisco_to_junos.merger import ConfigMerger

# Parse configs
parser = CiscoConfigParser()
config1 = parser.parse_file('switch1.txt')
config2 = parser.parse_file('switch2.txt')

# Merge
merger = ConfigMerger(interactive=False)
merged = merger.merge_configs([config1, config2])

# Convert
converter = MistConverter()
template = converter.convert(merged, match_role="access")

# Export
import json
with open('output.json', 'w') as f:
    json.dump(template, f, indent=2)
```

### Custom Port Matching Logic

```python
# Modify converter to customize port grouping
converter = MistConverter()
template = converter.convert(config, match_role="core")

# Manually adjust switch matching
template['switch_matching']['rules'][0]['match_role'] = 'distribution'
```

### Batch Processing

```bash
# Process multiple sites
for site in site1 site2 site3; do
  python -m cisco_to_junos.cli configs/$site/ \
    -o templates/${site}-template.json \
    --no-interactive --dry-run
done
```

---

## Best Practices

### 1. Always Start with Dry-Run

```bash
# First run - review without submitting
python -m cisco_to_junos.cli configs/ --dry-run

# Review output
cat mist_template.json

# Submit when satisfied
python -m cisco_to_junos.cli configs/ --org-id YOUR_ORG_ID
```

### 2. Use Template Variables for Multi-Site

```bash
# Use variables during prompts
? Primary DNS server: {{pridns}}
? Management VLAN ID: {{mgmt_vlan}}
```

Then define per-site in Mist dashboard.

### 3. Version Control Your Templates

```bash
git add mist_template.json
git commit -m "Add campus switches template - converted from Cisco"
git tag v1.0-campus-template
```

### 4. Document Custom Commands

```json
"additional_config_cmds": [
  "# Enable SSH for management",
  "set system services ssh root-login allow",
  "# Set timezone to Pacific",
  "set system time-zone America/Los_Angeles"
]
```

### 5. Test on Non-Production Org First

```bash
# Submit to test org
python -m cisco_to_junos.cli configs/ --org-id TEST_ORG_ID

# Verify in Mist dashboard
# Then submit to production org
python -m cisco_to_junos.cli configs/ --org-id PROD_ORG_ID
```

---

## References

### Mist Documentation
- [Network Templates API](https://www.juniper.net/documentation/us/en/software/mist/api/http/api/orgs/network-templates/create-org-network-template)
- [Switch Matching Rules](https://www.juniper.net/documentation/us/en/software/mist/api/http/models/structures/switch-matching-rule)

### Juniper Documentation
- [EX Series Port Configuration](https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet-switches/topics/topic-map/switches-interface-configure.html)
- [Junos CLI Reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/index.html)

### Tools & Libraries
- [mistapi Python Package](https://github.com/tmunzer/mistapi_python)
- [python-dotenv](https://pypi.org/project/python-dotenv/)
- [questionary](https://github.com/tmbo/questionary)

---

## Support & Contributing

**Issues:** Report bugs or request features via GitHub Issues  
**Questions:** Check documentation or open a discussion  
**Contributions:** Pull requests welcome!

---

**Last Updated:** November 26, 2025  
**Version:** 2.0 - Complete Feature Implementation (95% API Coverage)  
**License:** [Your License]
