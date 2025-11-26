"""Extended parsing methods for Cisco configurations."""

import re
from typing import Dict, List, Optional
from .parser import (
    StaticRoute, OSPFConfig, OSPFNetwork, OSPFInterfaceConfig,
    RADIUSConfig, RADIUSServer, SNMPConfig, DHCPSnoopingConfig,
    VRFConfig, AccessList, AccessListEntry, PortMirrorSession,
    SyslogServer, BannerConfig, LocalUser, LineConfig, TACACSServer, STPConfig
)


def parse_static_routes(content: str) -> List[StaticRoute]:
    """Parse static route configurations."""
    routes = []
    
    # Parse IPv4 routes: ip route <dest> <mask> <nexthop> [distance]
    ipv4_matches = re.finditer(
        r'^ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?',
        content,
        re.MULTILINE
    )
    
    for match in ipv4_matches:
        dest_ip = match.group(1)
        mask = match.group(2)
        next_hop = match.group(3)
        distance = int(match.group(4)) if match.group(4) else None
        
        # Convert to CIDR
        cidr = _subnet_mask_to_cidr(dest_ip, mask)
        
        # Check for null route
        is_null = next_hop.lower() in ['null0', 'null']
        
        routes.append(StaticRoute(
            destination=cidr,
            next_hop=next_hop if not is_null else "null0",
            metric=distance,
            is_null_route=is_null,
            is_ipv6=False
        ))
    
    # Parse IPv6 routes: ipv6 route <prefix>/<len> <nexthop> [distance]
    ipv6_matches = re.finditer(
        r'^ipv6 route\s+(\S+)\s+(\S+)(?:\s+(\d+))?',
        content,
        re.MULTILINE
    )
    
    for match in ipv6_matches:
        dest = match.group(1)
        next_hop = match.group(2)
        distance = int(match.group(3)) if match.group(3) else None
        
        # Check for null route
        is_null = next_hop.lower() == 'null0'
        
        routes.append(StaticRoute(
            destination=dest,
            next_hop=next_hop if not is_null else "null0",
            metric=distance,
            is_null_route=is_null,
            is_ipv6=True
        ))
    
    return routes


def parse_ospf(content: str) -> Optional[OSPFConfig]:
    """Parse OSPF configuration."""
    # Find OSPF router block
    ospf_match = re.search(
        r'^router ospf\s+(\d+)\s*\n((?:^[ ].*\n)*)',
        content,
        re.MULTILINE
    )
    
    if not ospf_match:
        return None
    
    process_id = int(ospf_match.group(1))
    ospf_content = ospf_match.group(2)
    
    config = OSPFConfig(process_id=process_id)
    
    # Parse router-id
    router_id_match = re.search(r'^\s+router-id\s+(\S+)', ospf_content, re.MULTILINE)
    if router_id_match:
        config.router_id = router_id_match.group(1)
    
    # Parse networks
    network_matches = re.finditer(
        r'^\s+network\s+(\S+)\s+(\S+)\s+area\s+(\S+)',
        ospf_content,
        re.MULTILINE
    )
    
    for match in network_matches:
        config.networks.append(OSPFNetwork(
            network=match.group(1),
            wildcard=match.group(2),
            area=match.group(3)
        ))
    
    # Parse passive interfaces
    passive_matches = re.finditer(
        r'^\s+passive-interface\s+(\S+)',
        ospf_content,
        re.MULTILINE
    )
    
    for match in passive_matches:
        config.passive_interfaces.append(match.group(1))
    
    # Parse default-information originate
    if 'default-information originate' in ospf_content:
        config.default_information_originate = True
    
    # Parse redistribution
    redist_matches = re.finditer(
        r'^\s+redistribute\s+(\S+)',
        ospf_content,
        re.MULTILINE
    )
    
    for match in redist_matches:
        config.redistribute.append(match.group(1))
    
    # Parse area configurations
    area_stub_matches = re.finditer(
        r'^\s+area\s+(\S+)\s+(stub|nssa)',
        ospf_content,
        re.MULTILINE
    )
    
    for match in area_stub_matches:
        area_id = match.group(1)
        area_type = match.group(2)
        if area_id not in config.areas:
            config.areas[area_id] = {}
        config.areas[area_id]['type'] = area_type
    
    return config


def parse_ospf_interfaces(content: str) -> Dict[str, OSPFInterfaceConfig]:
    """Parse OSPF interface-specific configurations."""
    ospf_interfaces = {}
    
    # Find all interface blocks
    interface_blocks = re.finditer(
        r'^interface\s+(\S+)\s*\n((?:^[ ].*\n)*)',
        content,
        re.MULTILINE
    )
    
    for match in interface_blocks:
        interface_name = match.group(1)
        interface_content = match.group(2)
        
        # Check for OSPF configuration
        has_ospf = False
        config = OSPFInterfaceConfig(interface_name=interface_name)
        
        # Parse OSPF authentication
        if 'ip ospf authentication message-digest' in interface_content:
            config.auth_type = "message-digest"
            has_ospf = True
        elif 'ip ospf authentication null' in interface_content:
            config.auth_type = "null"
            has_ospf = True
        elif 'ip ospf authentication' in interface_content:
            config.auth_type = "password"
            has_ospf = True
        
        # Parse MD5 key
        md5_match = re.search(
            r'^\s+ip ospf message-digest-key\s+(\d+)\s+md5\s+(\S+)',
            interface_content,
            re.MULTILINE
        )
        if md5_match:
            config.auth_key_id = int(md5_match.group(1))
            config.auth_key = md5_match.group(2)
            has_ospf = True
        
        # Parse hello interval
        hello_match = re.search(
            r'^\s+ip ospf hello-interval\s+(\d+)',
            interface_content,
            re.MULTILINE
        )
        if hello_match:
            config.hello_interval = int(hello_match.group(1))
            has_ospf = True
        
        # Parse dead interval
        dead_match = re.search(
            r'^\s+ip ospf dead-interval\s+(\d+)',
            interface_content,
            re.MULTILINE
        )
        if dead_match:
            config.dead_interval = int(dead_match.group(1))
            has_ospf = True
        
        # Parse cost
        cost_match = re.search(
            r'^\s+ip ospf cost\s+(\d+)',
            interface_content,
            re.MULTILINE
        )
        if cost_match:
            config.cost = int(cost_match.group(1))
            has_ospf = True
        
        # Parse priority
        priority_match = re.search(
            r'^\s+ip ospf priority\s+(\d+)',
            interface_content,
            re.MULTILINE
        )
        if priority_match:
            config.priority = int(priority_match.group(1))
            has_ospf = True
        
        if has_ospf:
            ospf_interfaces[interface_name] = config
    
    return ospf_interfaces


def parse_radius(content: str) -> Optional[RADIUSConfig]:
    """Parse RADIUS configuration."""
    config = RADIUSConfig()
    has_radius = False
    
    # Parse radius-server host commands
    host_matches = re.finditer(
        r'^radius-server host\s+(\S+)(?:\s+auth-port\s+(\d+))?(?:\s+acct-port\s+(\d+))?(?:\s+key\s+(.+?))?(?:\s*$)',
        content,
        re.MULTILINE
    )
    
    for match in host_matches:
        server = RADIUSServer(host=match.group(1))
        
        if match.group(2):
            server.auth_port = int(match.group(2))
        if match.group(3):
            server.acct_port = int(match.group(3))
        if match.group(4):
            server.key = match.group(4).strip()
        
        config.servers.append(server)
        has_radius = True
    
    # Parse global timeout
    timeout_match = re.search(r'^radius-server timeout\s+(\d+)', content, re.MULTILINE)
    if timeout_match:
        config.timeout = int(timeout_match.group(1))
        has_radius = True
    
    # Parse global retransmit
    retransmit_match = re.search(r'^radius-server retransmit\s+(\d+)', content, re.MULTILINE)
    if retransmit_match:
        config.retransmit = int(retransmit_match.group(1))
        has_radius = True
    
    # Parse global key
    key_match = re.search(r'^radius-server key\s+(.+?)(?:\s*$)', content, re.MULTILINE)
    if key_match:
        config.key = key_match.group(1).strip()
        has_radius = True
    
    # Parse source interface
    source_match = re.search(r'^ip radius source-interface\s+(\S+)', content, re.MULTILINE)
    if source_match:
        config.source_interface = source_match.group(1)
        has_radius = True
    
    return config if has_radius else None


def parse_snmp(content: str) -> Optional[SNMPConfig]:
    """Parse SNMP configuration."""
    config = SNMPConfig()
    has_snmp = False
    
    # Parse communities
    community_matches = re.finditer(
        r'^snmp-server community\s+(\S+)\s+(RO|RW)',
        content,
        re.MULTILINE | re.IGNORECASE
    )
    
    for match in community_matches:
        config.communities[match.group(1)] = match.group(2).upper()
        has_snmp = True
    
    # Parse location
    location_match = re.search(r'^snmp-server location\s+(.+)', content, re.MULTILINE)
    if location_match:
        config.location = location_match.group(1).strip().strip('"')
        has_snmp = True
    
    # Parse contact
    contact_match = re.search(r'^snmp-server contact\s+(.+)', content, re.MULTILINE)
    if contact_match:
        config.contact = contact_match.group(1).strip()
        has_snmp = True
    
    # Parse trap hosts
    trap_matches = re.finditer(
        r'^snmp-server host\s+(\S+)(?:\s+traps)?(?:\s+version\s+(\S+))?(?:\s+(\S+))?',
        content,
        re.MULTILINE
    )
    
    for match in trap_matches:
        trap_host = {
            'host': match.group(1),
            'version': match.group(2) if match.group(2) else '2c',
            'community': match.group(3) if match.group(3) else 'public'
        }
        config.trap_hosts.append(trap_host)
        has_snmp = True
    
    # Parse enable traps
    trap_enable_matches = re.finditer(
        r'^snmp-server enable traps\s+(\S+)',
        content,
        re.MULTILINE
    )
    
    for match in trap_enable_matches:
        config.enable_traps.append(match.group(1))
        has_snmp = True
    
    return config if has_snmp else None


def parse_dhcp_snooping(content: str) -> Optional[DHCPSnoopingConfig]:
    """Parse DHCP snooping configuration."""
    config = DHCPSnoopingConfig()
    
    # Check if DHCP snooping is enabled
    if re.search(r'^ip dhcp snooping\s*$', content, re.MULTILINE):
        config.enabled = True
    else:
        return None
    
    # Parse VLANs
    vlan_match = re.search(r'^ip dhcp snooping vlan\s+(.+)', content, re.MULTILINE)
    if vlan_match:
        vlan_str = vlan_match.group(1).strip()
        config.vlans = _parse_vlan_list_simple(vlan_str)
    
    # Parse verify mac-address
    if 'ip dhcp snooping verify mac-address' in content:
        config.verify_mac = True
    
    return config


def parse_vrfs(content: str) -> Dict[str, VRFConfig]:
    """Parse VRF configurations."""
    vrfs = {}
    
    # Find VRF definition blocks
    vrf_blocks = re.finditer(
        r'^vrf definition\s+(\S+)\s*\n((?:^[ ].*\n)*)',
        content,
        re.MULTILINE
    )
    
    for match in vrf_blocks:
        vrf_name = match.group(1)
        vrf_content = match.group(2)
        
        vrf = VRFConfig(name=vrf_name)
        
        # Parse RD
        rd_match = re.search(r'^\s+rd\s+(\S+)', vrf_content, re.MULTILINE)
        if rd_match:
            vrf.rd = rd_match.group(1)
        
        # Check address families
        if 'address-family ipv4' in vrf_content:
            vrf.ipv4 = True
        if 'address-family ipv6' in vrf_content:
            vrf.ipv6 = True
        
        vrfs[vrf_name] = vrf
    
    # Find interfaces with VRF forwarding
    interface_blocks = re.finditer(
        r'^interface\s+(\S+)\s*\n((?:^[ ].*\n)*)',
        content,
        re.MULTILINE
    )
    
    for match in interface_blocks:
        interface_name = match.group(1)
        interface_content = match.group(2)
        
        vrf_match = re.search(r'^\s+(?:vrf forwarding|ip vrf forwarding)\s+(\S+)', interface_content, re.MULTILINE)
        if vrf_match:
            vrf_name = vrf_match.group(1)
            if vrf_name in vrfs:
                vrfs[vrf_name].interfaces.append(interface_name)
    
    return vrfs


def parse_access_lists(content: str) -> Dict[str, AccessList]:
    """Parse ACL configurations."""
    acls = {}
    
    # Find extended ACL blocks
    acl_blocks = re.finditer(
        r'^ip access-list extended\s+(\S+)\s*\n((?:^[ ].*\n)*)',
        content,
        re.MULTILINE
    )
    
    for match in acl_blocks:
        acl_name = match.group(1)
        acl_content = match.group(2)
        
        acl = AccessList(name=acl_name, type="extended")
        
        # Parse ACL entries
        entry_matches = re.finditer(
            r'^\s+(?:(\d+)\s+)?(permit|deny)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?(?:\s+(\S+))?(?:\s+(log))?',
            acl_content,
            re.MULTILINE
        )
        
        for entry_match in entry_matches:
            entry = AccessListEntry(
                sequence=int(entry_match.group(1)) if entry_match.group(1) else None,
                action=entry_match.group(2),
                protocol=entry_match.group(3),
                source=entry_match.group(4),
                log=bool(entry_match.group(8))
            )
            
            # Parse destination if present
            if entry_match.group(5):
                entry.source_wildcard = entry_match.group(5) if entry_match.group(5) not in ['any', 'host'] else None
            if entry_match.group(6):
                entry.destination = entry_match.group(6)
            if entry_match.group(7):
                entry.destination_wildcard = entry_match.group(7)
            
            acl.entries.append(entry)
        
        acls[acl_name] = acl
    
    return acls


def parse_port_mirroring(content: str) -> Dict[int, PortMirrorSession]:
    """Parse port mirroring (SPAN) sessions."""
    sessions = {}
    
    # Find monitor session source commands
    source_matches = re.finditer(
        r'^monitor session\s+(\d+)\s+source\s+interface\s+(.+)',
        content,
        re.MULTILINE
    )
    
    for match in source_matches:
        session_id = int(match.group(1))
        interfaces = match.group(2).strip()
        
        if session_id not in sessions:
            sessions[session_id] = PortMirrorSession(session_id=session_id)
        
        # Parse interface list
        sessions[session_id].source_ports.extend(_parse_interface_list(interfaces))
    
    # Find monitor session destination commands
    dest_matches = re.finditer(
        r'^monitor session\s+(\d+)\s+destination\s+interface\s+(\S+)',
        content,
        re.MULTILINE
    )
    
    for match in dest_matches:
        session_id = int(match.group(1))
        interface = match.group(2)
        
        if session_id not in sessions:
            sessions[session_id] = PortMirrorSession(session_id=session_id)
        
        sessions[session_id].destination_port = interface
    
    return sessions


def parse_syslog(content: str) -> List[SyslogServer]:
    """Parse syslog server configurations."""
    servers = []
    
    # Find logging host commands
    host_matches = re.finditer(
        r'^logging host\s+(\S+)',
        content,
        re.MULTILINE
    )
    
    for match in host_matches:
        servers.append(SyslogServer(host=match.group(1)))
    
    # Parse global severity
    severity_match = re.search(r'^logging trap\s+(\S+)', content, re.MULTILINE)
    if severity_match and servers:
        severity = severity_match.group(1)
        for server in servers:
            server.severity = severity
    
    # Parse facility
    facility_match = re.search(r'^logging facility\s+(\S+)', content, re.MULTILINE)
    if facility_match and servers:
        facility = facility_match.group(1)
        for server in servers:
            server.facility = facility
    
    return servers


def parse_banner(content: str) -> Optional[BannerConfig]:
    """Parse banner configurations."""
    config = BannerConfig()
    has_banner = False
    
    # Parse login banner
    login_match = re.search(r'^banner login\s+(.)\n(.*?)\1', content, re.MULTILINE | re.DOTALL)
    if login_match:
        config.login = login_match.group(2).strip()
        has_banner = True
    
    # Parse MOTD banner
    motd_match = re.search(r'^banner motd\s+(.)\n(.*?)\1', content, re.MULTILINE | re.DOTALL)
    if motd_match:
        config.motd = motd_match.group(2).strip()
        has_banner = True
    
    # Parse exec banner
    exec_match = re.search(r'^banner exec\s+(.)\n(.*?)\1', content, re.MULTILINE | re.DOTALL)
    if exec_match:
        config.exec = exec_match.group(2).strip()
        has_banner = True
    
    return config if has_banner else None


def parse_local_users(content: str) -> Dict[str, LocalUser]:
    """Parse local user accounts."""
    users = {}
    
    # Find username commands
    user_matches = re.finditer(
        r'^username\s+(\S+)(?:\s+privilege\s+(\d+))?(?:\s+secret\s+(\d+)\s+(\S+))?(?:\s+password\s+(\d+)\s+(\S+))?',
        content,
        re.MULTILINE
    )
    
    for match in user_matches:
        username = match.group(1)
        user = LocalUser(username=username)
        
        if match.group(2):
            user.privilege = int(match.group(2))
        if match.group(4):
            user.secret = match.group(4)
        if match.group(6):
            user.password = match.group(6)
        
        users[username] = user
    
    return users


def parse_line_configs(content: str) -> List[LineConfig]:
    """Parse line configurations."""
    configs = []
    
    # Find line blocks
    line_blocks = re.finditer(
        r'^line\s+(\S+)\s+(\d+)(?:\s+(\d+))?\s*\n((?:^[ ].*\n)*)',
        content,
        re.MULTILINE
    )
    
    for match in line_blocks:
        line_type = match.group(1)
        start = int(match.group(2))
        end = int(match.group(3)) if match.group(3) else start
        line_content = match.group(4)
        
        config = LineConfig(line_type=line_type, start=start, end=end)
        
        # Parse exec-timeout
        timeout_match = re.search(r'^\s+exec-timeout\s+(\d+)', line_content, re.MULTILINE)
        if timeout_match:
            config.exec_timeout = int(timeout_match.group(1))
        
        # Parse password
        password_match = re.search(r'^\s+password\s+(?:\d+\s+)?(\S+)', line_content, re.MULTILINE)
        if password_match:
            config.password = password_match.group(1)
        
        # Parse login local
        if 'login local' in line_content:
            config.login_local = True
        
        configs.append(config)
    
    return configs


def parse_tacacs(content: str) -> List[TACACSServer]:
    """Parse TACACS+ server configurations."""
    servers = []
    
    # Find tacacs-server host commands
    host_matches = re.finditer(
        r'^tacacs-server host\s+(\S+)(?:\s+key\s+(.+?))?(?:\s*$)',
        content,
        re.MULTILINE
    )
    
    for match in host_matches:
        server = TACACSServer(host=match.group(1))
        if match.group(2):
            server.key = match.group(2).strip()
        servers.append(server)
    
    return servers


def parse_stp(content: str) -> Optional[STPConfig]:
    """Parse spanning tree configuration."""
    config = STPConfig()
    has_stp = False
    
    # Parse STP mode
    mode_match = re.search(r'^spanning-tree mode\s+(.+)', content, re.MULTILINE)
    if mode_match:
        config.mode = mode_match.group(1).strip()
        has_stp = True
    
    # Parse VLAN-specific priorities
    priority_matches = re.finditer(
        r'^spanning-tree vlan\s+(\d+)\s+priority\s+(\d+)',
        content,
        re.MULTILINE
    )
    
    for match in priority_matches:
        vlan_id = int(match.group(1))
        priority = int(match.group(2))
        config.vlan_priorities[vlan_id] = priority
        has_stp = True
    
    # Parse portfast default
    if 'spanning-tree portfast default' in content:
        config.portfast_default = True
        has_stp = True
    
    # Parse bpduguard default
    if 'spanning-tree portfast bpduguard default' in content:
        config.bpduguard_default = True
        has_stp = True
    
    return config if has_stp else None


# Helper functions

def _subnet_mask_to_cidr(ip: str, mask: str) -> str:
    """Convert subnet mask to CIDR notation."""
    # Count the number of 1 bits in the mask
    mask_parts = mask.split('.')
    if len(mask_parts) != 4:
        return f"{ip}/32"
    
    cidr_bits = 0
    for part in mask_parts:
        cidr_bits += bin(int(part)).count('1')
    
    return f"{ip}/{cidr_bits}"


def _parse_vlan_list_simple(vlan_string: str) -> List[int]:
    """Parse VLAN list (e.g., '10-24,100' -> [10,11,...,24,100])."""
    vlans = []
    parts = vlan_string.strip().split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            vlans.extend(range(int(start), int(end) + 1))
        else:
            if part:
                vlans.append(int(part))
    
    return vlans


def _parse_interface_list(interface_str: str) -> List[str]:
    """Parse interface list like 'Gi1/0/1 - 5' or 'Gi1/0/1, Gi1/0/2'."""
    interfaces = []
    
    # Handle range notation
    range_match = re.match(r'(\S+?[\d/]+/)(\d+)\s*-\s*(\d+)', interface_str)
    if range_match:
        prefix = range_match.group(1)
        start = int(range_match.group(2))
        end = int(range_match.group(3))
        for i in range(start, end + 1):
            interfaces.append(f"{prefix}{i}")
    else:
        # Handle comma-separated list
        parts = interface_str.split(',')
        for part in parts:
            interfaces.append(part.strip())
    
    return interfaces
