"""Parser for Cisco IOS configuration files."""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


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


@dataclass
class ManagementConfig:
    """Management configuration."""
    vlan_id: Optional[int] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    default_gateway: Optional[str] = None


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
        interface_blocks = re.finditer(
            r'^interface\s+(\S+)\s*\n((?:^[ ].*\n)*)',
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
        # Parse switchport mode
        mode_match = re.search(r'^\s+switchport mode\s+(\S+)', interface_content, re.MULTILINE)
        if mode_match:
            interface.mode = mode_match.group(1)
        
        # Parse access VLAN
        access_match = re.search(r'^\s+switchport access vlan\s+(\d+)', interface_content, re.MULTILINE)
        if access_match:
            interface.access_vlan = int(access_match.group(1))
        
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
    
    def _merge_interface_config(self, interface: InterfaceConfig, interface_content: str):
        """Merge additional configuration into existing InterfaceConfig."""
        # Parse and merge new settings (later configs override earlier ones)
        temp_interface = InterfaceConfig(name=interface.name)
        self._parse_interface_config(temp_interface, interface_content)
        
        # Merge non-default values
        if temp_interface.mode:
            interface.mode = temp_interface.mode
        if temp_interface.access_vlan:
            interface.access_vlan = temp_interface.access_vlan
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
