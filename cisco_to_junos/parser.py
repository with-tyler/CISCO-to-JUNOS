"""Parser for Cisco IOS configuration files."""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any


@dataclass
class VLANConfig:
    """VLAN configuration."""
    id: int
    name: str = ""
    state: str = "active"  # active or suspend


@dataclass
class InterfaceConfig:
    """Interface configuration."""
    name: str
    mode: str = ""  # access or trunk
    access_vlan: Optional[int] = None
    trunk_native_vlan: Optional[int] = None
    trunk_allowed_vlans: List[int] = field(default_factory=list)
    trunk_encapsulation: str = ""
    nonegotiate: bool = False
    portfast: bool = False
    bpduguard: bool = False
    shutdown: bool = False
    storm_control_broadcast: Optional[float] = None
    storm_control_multicast: Optional[float] = None
    storm_control_unknown_unicast: Optional[float] = None
    # Voice VLAN
    voice_vlan: Optional[int] = None
    # Port speed and duplex
    speed: Optional[str] = None  # "10", "100", "1000", "auto"
    duplex: Optional[str] = None  # "full", "half", "auto"
    # PoE
    poe_disabled: bool = False
    poe_priority: Optional[str] = None  # "low", "high"
    # Port security
    port_security: bool = False
    port_security_max: Optional[int] = None
    # 802.1X / MAB
    dot1x_pae: Optional[str] = None  # "authenticator"
    dot1x_port_control: Optional[str] = None  # "auto", "force-authorized", "force-unauthorized"
    mab: bool = False
    authentication_periodic: bool = False
    authentication_timer_reauthenticate: Optional[int] = None
    # DHCP snooping
    dhcp_snooping_trust: bool = False
    # Description
    description: str = ""


@dataclass
class ManagementConfig:
    """Management configuration."""
    vlan_id: Optional[int] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    default_gateway: Optional[str] = None


@dataclass
class StaticRoute:
    """Static route configuration."""
    destination: str  # CIDR format
    next_hop: str
    metric: Optional[int] = None  # Administrative distance in Cisco
    is_null_route: bool = False
    is_ipv6: bool = False


@dataclass
class OSPFNetwork:
    """OSPF network configuration."""
    network: str  # e.g., "10.0.0.0 0.0.0.255"
    area: str  # e.g., "0" or "0.0.0.0"
    wildcard: str  # e.g., "0.0.0.255"


@dataclass
class OSPFConfig:
    """OSPF configuration."""
    process_id: Optional[int] = None
    router_id: Optional[str] = None
    networks: List[OSPFNetwork] = field(default_factory=list)
    passive_interfaces: List[str] = field(default_factory=list)
    default_information_originate: bool = False
    redistribute: List[str] = field(default_factory=list)
    areas: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # area_id -> config


@dataclass
class OSPFInterfaceConfig:
    """OSPF interface-specific configuration."""
    interface_name: str
    auth_type: Optional[str] = None  # "message-digest", "null"
    auth_key_id: Optional[int] = None
    auth_key: Optional[str] = None
    hello_interval: Optional[int] = None
    dead_interval: Optional[int] = None
    cost: Optional[int] = None
    priority: Optional[int] = None


@dataclass
class RADIUSServer:
    """RADIUS server configuration."""
    host: str
    auth_port: int = 1812
    acct_port: int = 1813
    key: Optional[str] = None
    timeout: Optional[int] = None
    retransmit: Optional[int] = None


@dataclass
class RADIUSConfig:
    """RADIUS configuration."""
    servers: List[RADIUSServer] = field(default_factory=list)
    timeout: Optional[int] = None
    retransmit: Optional[int] = None
    key: Optional[str] = None  # Global key
    source_interface: Optional[str] = None


@dataclass
class SNMPConfig:
    """SNMP configuration."""
    communities: Dict[str, str] = field(default_factory=dict)  # community -> RO/RW
    location: Optional[str] = None
    contact: Optional[str] = None
    trap_hosts: List[Dict[str, Any]] = field(default_factory=list)
    enable_traps: List[str] = field(default_factory=list)


@dataclass
class DHCPSnoopingConfig:
    """DHCP Snooping configuration."""
    enabled: bool = False
    vlans: List[int] = field(default_factory=list)
    verify_mac: bool = False


@dataclass
class VRFConfig:
    """VRF configuration."""
    name: str
    rd: Optional[str] = None  # Route distinguisher
    interfaces: List[str] = field(default_factory=list)
    ipv4: bool = True
    ipv6: bool = False


@dataclass
class AccessListEntry:
    """Access list entry."""
    sequence: Optional[int] = None
    action: str = ""  # permit, deny
    protocol: str = ""  # ip, tcp, udp, icmp, etc.
    source: str = ""
    source_wildcard: Optional[str] = None
    destination: str = ""
    destination_wildcard: Optional[str] = None
    port_spec: Optional[str] = None
    log: bool = False


@dataclass
class AccessList:
    """Access list configuration."""
    name: str
    type: str = "extended"  # standard, extended
    entries: List[AccessListEntry] = field(default_factory=list)


@dataclass
class PortMirrorSession:
    """Port mirror (SPAN) session."""
    session_id: int
    source_ports: List[str] = field(default_factory=list)
    source_vlans: List[int] = field(default_factory=list)
    destination_port: Optional[str] = None
    direction: str = "both"  # rx, tx, both


@dataclass
class SyslogServer:
    """Syslog server configuration."""
    host: str
    port: int = 514
    severity: Optional[str] = None  # Level 0-7 or name
    facility: Optional[str] = None


@dataclass
class BannerConfig:
    """Banner configuration."""
    login: Optional[str] = None
    motd: Optional[str] = None
    exec: Optional[str] = None


@dataclass
class LocalUser:
    """Local user account."""
    username: str
    privilege: int = 1
    password: Optional[str] = None
    secret: Optional[str] = None


@dataclass
class LineConfig:
    """Line (VTY) configuration."""
    line_type: str  # "vty", "console"
    start: int
    end: int
    exec_timeout: Optional[int] = None
    password: Optional[str] = None
    login_local: bool = False


@dataclass
class TACACSServer:
    """TACACS+ server configuration."""
    host: str
    key: Optional[str] = None
    port: int = 49


@dataclass
class STPConfig:
    """Spanning Tree configuration."""
    mode: str = ""  # rapid-pvst, mstp, etc.
    vlan_priorities: Dict[int, int] = field(default_factory=dict)  # vlan_id -> priority
    portfast_default: bool = False
    bpduguard_default: bool = False


@dataclass
class CiscoConfig:
    """Complete parsed Cisco configuration."""
    hostname: str = ""
    vlans: Dict[int, VLANConfig] = field(default_factory=dict)
    interfaces: Dict[str, InterfaceConfig] = field(default_factory=dict)
    management: ManagementConfig = field(default_factory=ManagementConfig)
    spanning_tree_mode: str = ""  # e.g., rapid-pvst, mstp
    vtp_mode: str = ""
    source_file: str = ""
    # New configurations
    static_routes: List[StaticRoute] = field(default_factory=list)
    ospf: Optional[OSPFConfig] = None
    ospf_interfaces: Dict[str, OSPFInterfaceConfig] = field(default_factory=dict)
    radius: Optional[RADIUSConfig] = None
    snmp: Optional[SNMPConfig] = None
    dhcp_snooping: Optional[DHCPSnoopingConfig] = None
    vrfs: Dict[str, VRFConfig] = field(default_factory=dict)
    access_lists: Dict[str, AccessList] = field(default_factory=dict)
    port_mirror_sessions: Dict[int, PortMirrorSession] = field(default_factory=dict)
    syslog_servers: List[SyslogServer] = field(default_factory=list)
    banner: Optional[BannerConfig] = None
    local_users: Dict[str, LocalUser] = field(default_factory=dict)
    line_configs: List[LineConfig] = field(default_factory=list)
    tacacs_servers: List[TACACSServer] = field(default_factory=list)
    stp: Optional[STPConfig] = None


class CiscoConfigParser:
    """Parser for Cisco IOS configuration files."""

    def parse_file(self, filepath: str) -> CiscoConfig:
        """Parse a Cisco configuration file."""
        with open(filepath, 'r') as f:
            content = f.read()
        
        config = self.parse_config(content)
        config.source_file = filepath
        return config

    def parse_config(self, content: str) -> CiscoConfig:
        """Parse Cisco configuration content."""
        from .parser_extensions import (
            parse_static_routes, parse_ospf, parse_ospf_interfaces,
            parse_radius, parse_snmp, parse_dhcp_snooping, parse_vrfs,
            parse_access_lists, parse_port_mirroring, parse_syslog,
            parse_banner, parse_local_users, parse_line_configs,
            parse_tacacs, parse_stp
        )
        
        config = CiscoConfig()
        
        # Parse hostname
        hostname_match = re.search(r'^hostname\s+(\S+)', content, re.MULTILINE)
        if hostname_match:
            config.hostname = hostname_match.group(1)
        
        # Parse VTP mode
        vtp_match = re.search(r'^vtp mode\s+(\S+)', content, re.MULTILINE)
        if vtp_match:
            config.vtp_mode = vtp_match.group(1)
        
        # Parse spanning tree mode
        stp_match = re.search(r'^spanning-tree mode\s+(.+)', content, re.MULTILINE)
        if stp_match:
            config.spanning_tree_mode = stp_match.group(1).strip()
        
        # Parse VLANs
        config.vlans = self._parse_vlans(content)
        
        # Parse management config
        config.management = self._parse_management(content)
        
        # Parse interfaces
        config.interfaces = self._parse_interfaces(content)
        
        # Parse static routes
        config.static_routes = parse_static_routes(content)
        
        # Parse OSPF
        config.ospf = parse_ospf(content)
        config.ospf_interfaces = parse_ospf_interfaces(content)
        
        # Parse RADIUS
        config.radius = parse_radius(content)
        
        # Parse SNMP
        config.snmp = parse_snmp(content)
        
        # Parse DHCP snooping
        config.dhcp_snooping = parse_dhcp_snooping(content)
        
        # Parse VRFs
        config.vrfs = parse_vrfs(content)
        
        # Parse ACLs
        config.access_lists = parse_access_lists(content)
        
        # Parse port mirroring
        config.port_mirror_sessions = parse_port_mirroring(content)
        
        # Parse syslog
        config.syslog_servers = parse_syslog(content)
        
        # Parse banner
        config.banner = parse_banner(content)
        
        # Parse local users
        config.local_users = parse_local_users(content)
        
        # Parse line configs
        config.line_configs = parse_line_configs(content)
        
        # Parse TACACS
        config.tacacs_servers = parse_tacacs(content)
        
        # Parse STP
        config.stp = parse_stp(content)
        
        return config

    def _parse_vlans(self, content: str) -> Dict[int, VLANConfig]:
        """Parse VLAN configurations."""
        vlans = {}
        
        # Find all VLAN blocks
        vlan_blocks = re.finditer(
            r'^vlan\s+(\d+)\s*\n((?:^[ ].*\n)*)',
            content,
            re.MULTILINE
        )
        
        for match in vlan_blocks:
            vlan_id = int(match.group(1))
            vlan_content = match.group(2)
            
            vlan = VLANConfig(id=vlan_id)
            
            # Parse name
            name_match = re.search(r'^\s+name\s+(.+)', vlan_content, re.MULTILINE)
            if name_match:
                vlan.name = name_match.group(1).strip()
            
            # Parse state
            if 'state suspend' in vlan_content:
                vlan.state = "suspend"
            
            vlans[vlan_id] = vlan
        
        return vlans

    def _parse_management(self, content: str) -> ManagementConfig:
        """Parse management configuration."""
        mgmt = ManagementConfig()
        
        # Find management VLAN interface
        mgmt_vlan_match = re.search(
            r'^interface [Vv]lan\s*(\d+)\s*\n((?:^[ ].*\n)*)',
            content,
            re.MULTILINE
        )
        
        if mgmt_vlan_match:
            mgmt.vlan_id = int(mgmt_vlan_match.group(1))
            mgmt_content = mgmt_vlan_match.group(2)
            
            # Parse IP address
            ip_match = re.search(
                r'^\s+ip address\s+(\S+)\s+(\S+)',
                mgmt_content,
                re.MULTILINE
            )
            if ip_match:
                mgmt.ip_address = ip_match.group(1)
                mgmt.subnet_mask = ip_match.group(2)
        
        # Parse default gateway
        gw_match = re.search(r'^ip default-gateway\s+(\S+)', content, re.MULTILINE)
        if gw_match:
            mgmt.default_gateway = gw_match.group(1)
        
        return mgmt

    def _parse_interfaces(self, content: str) -> Dict[str, InterfaceConfig]:
        """Parse interface configurations."""
        interfaces = {}
        
        # First, expand interface ranges
        expanded_content = self._expand_interface_ranges(content)
        
        # Find all interface blocks
        # Match lines that are either indented (start with space) or 
        # non-indented commands (for malformed configs without indentation)
        interface_blocks = re.finditer(
            r'^interface\s+(\S+)\s*\n((?:^(?:[ ]|\S).*\n)*?)(?=^interface\s|\Z)',
            expanded_content,
            re.MULTILINE
        )
        
        for match in interface_blocks:
            interface_name = match.group(1)
            interface_content = match.group(2)
            
            # Skip VLAN interfaces (already handled in management)
            if interface_name.lower().startswith('vlan'):
                continue
            
            # Check if interface already exists (for merging configs)
            if interface_name in interfaces:
                # Merge with existing config
                interface = interfaces[interface_name]
                self._merge_interface_config(interface, interface_content)
            else:
                # Create new interface
                interface = InterfaceConfig(name=interface_name)
                self._parse_interface_config(interface, interface_content)
                interfaces[interface_name] = interface
        
        return interfaces
    
    def _parse_interface_config(self, interface: InterfaceConfig, interface_content: str):
        """Parse interface configuration content into an InterfaceConfig object."""
        # Parse description
        desc_match = re.search(r'^\s+description\s+(.+)', interface_content, re.MULTILINE)
        if desc_match:
            interface.description = desc_match.group(1).strip()
        
        # Parse switchport mode
        mode_match = re.search(r'^\s+switchport mode\s+(\S+)', interface_content, re.MULTILINE)
        if mode_match:
            interface.mode = mode_match.group(1)
        
        # Parse access VLAN (with or without leading whitespace)
        access_match = re.search(r'^\s*switchport access vlan\s+(\d+)', interface_content, re.MULTILINE)
        if access_match:
            interface.access_vlan = int(access_match.group(1))
        
        # Parse voice VLAN (with or without leading whitespace)
        voice_match = re.search(r'^\s*switchport voice vlan\s+(\d+)', interface_content, re.MULTILINE)
        if voice_match:
            interface.voice_vlan = int(voice_match.group(1))
        
        # Parse trunk configuration
        if 'trunk' in interface.mode:
            # Native VLAN
            native_match = re.search(r'^\s+switchport trunk native vlan\s+(\d+)', interface_content, re.MULTILINE)
            if native_match:
                interface.trunk_native_vlan = int(native_match.group(1))
            
            # Allowed VLANs
            allowed_match = re.search(r'^\s+switchport trunk allowed vlan\s+(.+)', interface_content, re.MULTILINE)
            if allowed_match:
                interface.trunk_allowed_vlans = self._parse_vlan_list(allowed_match.group(1))
            
            # Encapsulation
            encap_match = re.search(r'^\s+switchport trunk encapsulation\s+(\S+)', interface_content, re.MULTILINE)
            if encap_match:
                interface.trunk_encapsulation = encap_match.group(1)
        
        # Parse nonegotiate
        if 'switchport nonegotiate' in interface_content:
            interface.nonegotiate = True
        
        # Parse spanning tree
        if 'spanning-tree portfast' in interface_content:
            interface.portfast = True
        if 'spanning-tree bpduguard enable' in interface_content:
            interface.bpduguard = True
        
        # Parse shutdown
        if re.search(r'^\s+shutdown\s*$', interface_content, re.MULTILINE):
            interface.shutdown = True
        
        # Parse storm control
        storm_bc_match = re.search(r'^\s+storm-control broadcast level\s+(\S+)', interface_content, re.MULTILINE)
        if storm_bc_match:
            interface.storm_control_broadcast = float(storm_bc_match.group(1))
        
        storm_mc_match = re.search(r'^\s+storm-control multicast level\s+(\S+)', interface_content, re.MULTILINE)
        if storm_mc_match:
            interface.storm_control_multicast = float(storm_mc_match.group(1))
        
        storm_uu_match = re.search(r'^\s+storm-control unicast level\s+(\S+)', interface_content, re.MULTILINE)
        if storm_uu_match:
            interface.storm_control_unknown_unicast = float(storm_uu_match.group(1))
        
        # Parse speed
        speed_match = re.search(r'^\s+speed\s+(\S+)', interface_content, re.MULTILINE)
        if speed_match:
            speed_val = speed_match.group(1)
            # Normalize speed values
            if speed_val == "1000":
                interface.speed = "1g"
            elif speed_val == "100":
                interface.speed = "100m"
            elif speed_val == "10":
                interface.speed = "10m"
            elif speed_val == "10000":
                interface.speed = "10g"
            else:
                interface.speed = speed_val
        
        # Parse duplex
        duplex_match = re.search(r'^\s+duplex\s+(\S+)', interface_content, re.MULTILINE)
        if duplex_match:
            interface.duplex = duplex_match.group(1)
        
        # Parse PoE
        if re.search(r'^\s+power inline never', interface_content, re.MULTILINE):
            interface.poe_disabled = True
        
        poe_priority_match = re.search(r'^\s+power inline priority\s+(\S+)', interface_content, re.MULTILINE)
        if poe_priority_match:
            interface.poe_priority = poe_priority_match.group(1)
        
        # Parse port security
        if re.search(r'^\s+switchport port-security\s*$', interface_content, re.MULTILINE):
            interface.port_security = True
        
        max_match = re.search(r'^\s+switchport port-security maximum\s+(\d+)', interface_content, re.MULTILINE)
        if max_match:
            interface.port_security_max = int(max_match.group(1))
        
        # Parse 802.1X / MAB
        if 'dot1x pae authenticator' in interface_content:
            interface.dot1x_pae = "authenticator"
        
        port_control_match = re.search(r'^\s+(?:authentication port-control|dot1x port-control)\s+(\S+)', interface_content, re.MULTILINE)
        if port_control_match:
            interface.dot1x_port_control = port_control_match.group(1)
        
        if 'mab' in interface_content or 'mac authentication bypass' in interface_content:
            interface.mab = True
        
        if 'authentication periodic' in interface_content:
            interface.authentication_periodic = True
        
        timer_match = re.search(r'^\s+authentication timer reauthenticate\s+(\d+)', interface_content, re.MULTILINE)
        if timer_match:
            interface.authentication_timer_reauthenticate = int(timer_match.group(1))
        
        # Parse DHCP snooping trust
        if 'ip dhcp snooping trust' in interface_content:
            interface.dhcp_snooping_trust = True
    
    def _merge_interface_config(self, interface: InterfaceConfig, interface_content: str):
        """Merge additional configuration into existing InterfaceConfig."""
        # Parse and merge new settings (later configs override earlier ones)
        temp_interface = InterfaceConfig(name=interface.name)
        self._parse_interface_config(temp_interface, interface_content)
        
        # Merge non-default values
        if temp_interface.description:
            interface.description = temp_interface.description
        if temp_interface.mode:
            interface.mode = temp_interface.mode
        if temp_interface.access_vlan:
            interface.access_vlan = temp_interface.access_vlan
        if temp_interface.voice_vlan:
            interface.voice_vlan = temp_interface.voice_vlan
        if temp_interface.trunk_native_vlan:
            interface.trunk_native_vlan = temp_interface.trunk_native_vlan
        if temp_interface.trunk_allowed_vlans:
            interface.trunk_allowed_vlans = temp_interface.trunk_allowed_vlans
        if temp_interface.trunk_encapsulation:
            interface.trunk_encapsulation = temp_interface.trunk_encapsulation
        if temp_interface.nonegotiate:
            interface.nonegotiate = True
        if temp_interface.portfast:
            interface.portfast = True
        if temp_interface.bpduguard:
            interface.bpduguard = True
        if temp_interface.shutdown:
            interface.shutdown = True
        if temp_interface.storm_control_broadcast:
            interface.storm_control_broadcast = temp_interface.storm_control_broadcast
        if temp_interface.storm_control_multicast:
            interface.storm_control_multicast = temp_interface.storm_control_multicast
        if temp_interface.storm_control_unknown_unicast:
            interface.storm_control_unknown_unicast = temp_interface.storm_control_unknown_unicast
        if temp_interface.speed:
            interface.speed = temp_interface.speed
        if temp_interface.duplex:
            interface.duplex = temp_interface.duplex
        if temp_interface.poe_disabled:
            interface.poe_disabled = True
        if temp_interface.poe_priority:
            interface.poe_priority = temp_interface.poe_priority
        if temp_interface.port_security:
            interface.port_security = True
        if temp_interface.port_security_max:
            interface.port_security_max = temp_interface.port_security_max
        if temp_interface.dot1x_pae:
            interface.dot1x_pae = temp_interface.dot1x_pae
        if temp_interface.dot1x_port_control:
            interface.dot1x_port_control = temp_interface.dot1x_port_control
        if temp_interface.mab:
            interface.mab = True
        if temp_interface.authentication_periodic:
            interface.authentication_periodic = True
        if temp_interface.authentication_timer_reauthenticate:
            interface.authentication_timer_reauthenticate = temp_interface.authentication_timer_reauthenticate
        if temp_interface.dhcp_snooping_trust:
            interface.dhcp_snooping_trust = True

    def _expand_interface_ranges(self, content: str) -> str:
        """Expand interface range commands to individual interfaces."""
        expanded = content
        
        # Find interface range commands
        # Pattern matches: interface range GigabitEthernet1/0/1 - 15
        range_matches = re.finditer(
            r'^interface range\s+(\S+?[\d/]+/)(\d+)\s*-\s*(\d+)\s*\n((?:^[ ].*\n)*)',
            content,
            re.MULTILINE
        )
        
        for match in range_matches:
            interface_prefix = match.group(1)  # e.g., GigabitEthernet1/0/
            start = int(match.group(2))
            end = int(match.group(3))
            config_lines = match.group(4)
            
            # Generate individual interface blocks
            individual_blocks = []
            for port_num in range(start, end + 1):
                interface_name = f"{interface_prefix}{port_num}"
                individual_blocks.append(f"interface {interface_name}\n{config_lines}")
            
            # Replace the range with individual blocks
            expanded = expanded.replace(match.group(0), '\n'.join(individual_blocks))
        
        return expanded

    def _parse_vlan_list(self, vlan_string: str) -> List[int]:
        """Parse VLAN list (e.g., '10-24,100' -> [10,11,...,24,100])."""
        vlans = []
        
        # Remove comments (anything after !)
        vlan_string = vlan_string.split('!')[0].strip()
        
        parts = vlan_string.strip().split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:
                # Range
                start, end = part.split('-')
                vlans.extend(range(int(start), int(end) + 1))
            else:
                # Single VLAN
                if part:  # Skip empty parts
                    vlans.append(int(part))
        
        return vlans
