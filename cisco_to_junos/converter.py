"""Convert Cisco configurations to Mist JSON templates."""

from typing import Dict, List, Any
from .parser import CiscoConfig, VLANConfig, InterfaceConfig


class MistConverter:
    """Convert Cisco configuration to Mist JSON template."""

    def convert(self, cisco_config: CiscoConfig, match_role: str = "access") -> Dict[str, Any]:
        """Convert a single Cisco config to Mist template format.
        
        Args:
            cisco_config: Parsed Cisco configuration
            match_role: Switch role for matching rules (access, core, distribution)
        """
        template = {
            "name": f"Template-{cisco_config.hostname}" if cisco_config.hostname else "Cisco-Converted-Template",
            "device_type": "switch",
            "networks": self._convert_vlans(cisco_config.vlans),
            "port_usages": self._convert_port_profiles(cisco_config),
            "switch_matching": self._generate_switch_matching(cisco_config, match_role),
        }
        
        # Add spanning tree config if present
        if cisco_config.spanning_tree_mode:
            template["additional_config_cmds"] = [
                f"# Spanning Tree Mode: {cisco_config.spanning_tree_mode}"
            ]
        
        return template

    def _convert_vlans(self, vlans: Dict[int, VLANConfig]) -> Dict[str, Any]:
        """Convert Cisco VLANs to Mist networks."""
        networks = {}
        
        for vlan_id, vlan in vlans.items():
            # Skip suspended VLANs
            if vlan.state == "suspend":
                continue
            
            network_name = vlan.name if vlan.name else f"VLAN{vlan_id}"
            networks[network_name] = {
                "vlan_id": vlan_id,
                "subnet": "",  # Will need to be filled in or detected
            }
        
        return networks

    def _convert_port_profiles(self, cisco_config: CiscoConfig) -> Dict[str, Any]:
        """Convert interface configurations to Mist port profiles."""
        port_usages = {}
        
        # Group interfaces by configuration to create profiles
        profile_map = {}  # config_key -> (profile_name, interface_config, [interface_names])
        
        for interface_name, interface in cisco_config.interfaces.items():
            # Skip management interfaces
            if interface_name.lower().startswith('vlan'):
                continue
            
            # Create a key representing this interface's configuration
            config_key = self._interface_config_key(interface)
            
            if config_key not in profile_map:
                # Generate profile name based on the interface config
                profile_name = self._generate_profile_name(interface, len(profile_map))
                profile_map[config_key] = (profile_name, interface, [])
            
            profile_map[config_key][2].append(interface_name)
        
        # Create port profiles from the grouped interfaces
        for config_key, (profile_name, interface, interface_names) in profile_map.items():
            port_usages[profile_name] = self._create_port_profile(interface, cisco_config)
        
        # Store profile map for switch matching
        self._profile_mapping = {}  # interface_name -> profile_name
        for config_key, (profile_name, _, interface_names) in profile_map.items():
            for if_name in interface_names:
                self._profile_mapping[if_name] = profile_name
        
        return port_usages

    def _interface_config_key(self, interface: InterfaceConfig) -> str:
        """Generate a unique key for an interface configuration."""
        key_parts = [
            interface.mode,
            str(interface.access_vlan) if interface.access_vlan else "",
            str(interface.trunk_native_vlan) if interface.trunk_native_vlan else "",
            ",".join(map(str, sorted(interface.trunk_allowed_vlans))),
            str(interface.nonegotiate),
            str(interface.portfast),
            str(interface.bpduguard),
            str(interface.shutdown),
        ]
        return "|".join(key_parts)

    def _generate_profile_name(self, interface: InterfaceConfig, index: int) -> str:
        """Generate a descriptive profile name."""
        if interface.shutdown:
            return "Disabled-Ports"
        elif interface.mode == "access" and interface.access_vlan:
            # Include additional attributes for unique naming
            suffix = ""
            if interface.portfast:
                suffix += "-Portfast"
            if interface.bpduguard:
                suffix += "-BPDUGuard"
            return f"Access-VLAN{interface.access_vlan}{suffix}"
        elif interface.mode == "trunk":
            # Create trunk profile name based on allowed VLANs
            if interface.trunk_allowed_vlans:
                vlan_range = f"{min(interface.trunk_allowed_vlans)}-{max(interface.trunk_allowed_vlans)}"
                return f"Trunk-VLANs-{vlan_range}"
            return f"Trunk-Profile"
        else:
            return f"Unconfig-Port-{index+1}"

    def _create_port_profile(self, interface: InterfaceConfig, cisco_config: CiscoConfig) -> Dict[str, Any]:
        """Create a Mist port profile from an interface configuration."""
        profile = {
            "description": f"Converted from Cisco config: {interface.name}",
        }
        
        if interface.shutdown:
            profile["disabled"] = True
            profile["mode"] = "access"
            if interface.access_vlan:
                # Get VLAN name for disabled ports
                vlan = cisco_config.vlans.get(interface.access_vlan)
                if vlan:
                    profile["networks"] = [vlan.name if vlan.name else f"VLAN{interface.access_vlan}"]
            return profile
        
        # Configure based on mode
        if interface.mode == "access":
            profile["mode"] = "access"
            if interface.access_vlan:
                vlan = cisco_config.vlans.get(interface.access_vlan)
                if vlan:
                    profile["networks"] = [vlan.name if vlan.name else f"VLAN{interface.access_vlan}"]
        
        elif interface.mode == "trunk":
            profile["mode"] = "trunk"
            profile["all_networks"] = False
            
            # Add allowed VLANs
            if interface.trunk_allowed_vlans:
                networks = []
                for vlan_id in interface.trunk_allowed_vlans:
                    vlan = cisco_config.vlans.get(vlan_id)
                    if vlan:
                        networks.append(vlan.name if vlan.name else f"VLAN{vlan_id}")
                profile["networks"] = networks
            
            # Native VLAN
            if interface.trunk_native_vlan:
                vlan = cisco_config.vlans.get(interface.trunk_native_vlan)
                if vlan:
                    profile["native_network"] = vlan.name if vlan.name else f"VLAN{interface.trunk_native_vlan}"
        
        # STP settings
        if interface.portfast:
            profile["stp_edge"] = True
        
        if interface.bpduguard:
            profile["enable_bpdu_guard"] = True
        
        # Storm control
        if interface.storm_control_broadcast:
            profile["storm_control"] = {
                "broadcast": interface.storm_control_broadcast
            }
            if interface.storm_control_multicast:
                profile["storm_control"]["multicast"] = interface.storm_control_multicast
        
        # Disable negotiation (map to Mist equivalent)
        if interface.nonegotiate:
            profile["disable_autoneg"] = True
        
        return profile

    def _generate_switch_matching(self, cisco_config: CiscoConfig, match_role: str = "access") -> Dict[str, Any]:
        """Generate switch matching rules for port assignment.
        
        Args:
            cisco_config: Parsed Cisco configuration
            match_role: Switch role for matching rules (access, core, distribution)
        
        Mist switch matching uses device roles and port ranges to assign configurations.
        """
        # Use the profile mapping created during port profile conversion
        if not hasattr(self, '_profile_mapping'):
            return {"enable": True, "rules": []}
        
        # Group ports by profile to create range-based port configs
        profile_ports = {}  # profile_name -> [port_identifiers]
        
        for interface_name, profile_name in self._profile_mapping.items():
            if interface_name.lower().startswith('vlan'):
                continue
            
            # Extract simple port identifier
            port_id = self._extract_simple_port_id(interface_name)
            
            if port_id:
                if profile_name not in profile_ports:
                    profile_ports[profile_name] = []
                profile_ports[profile_name].append(port_id)
        
        # Build port_config dictionary with port ranges
        port_config = {}
        
        for profile_name, ports in profile_ports.items():
            # Sort ports for cleaner output
            sorted_ports = sorted(ports, key=lambda x: self._port_sort_key(x))
            
            # Convert list of ports to comma-separated ranges
            port_range_str = self._create_port_ranges(sorted_ports)
            
            port_config[port_range_str] = {
                "usage": profile_name,
                "dynamic_usage": None,
                "critical": False,
                "description": "",
                "no_local_overwrite": True
            }
        
        # Create a single rule for the converted switches
        rules = [
            {
                "name": f"Converted-{cisco_config.hostname}" if cisco_config.hostname else "Converted-Switches",
                "match_role": match_role,
                "port_config": port_config,
                "additional_config_cmds": [],
                "ip_config": {
                    "type": "dhcp",
                    "network": self._get_mgmt_network_name(cisco_config)
                },
                "oob_ip_config": {
                    "type": "dhcp",
                    "use_mgmt_vrf": False
                },
                "port_mirroring": {}
            }
        ]
        
        return {
            "enable": True,
            "rules": rules
        }
    
    def _create_port_ranges(self, ports: List[str]) -> str:
        """Convert list of ports to comma-separated ranges.
        
        Examples:
          ['ge-0/0/1', 'ge-0/0/2', 'ge-0/0/3'] -> 'ge-0/0/1-3'
          ['ge-0/0/1', 'ge-0/0/3', 'ge-0/0/5'] -> 'ge-0/0/1, ge-0/0/3, ge-0/0/5'
          ['fe-0/24', 'ge-1/0/1'] -> 'fe-0/24, ge-1/0/1'
        """
        if not ports:
            return ""
        
        # Group by prefix (e.g., 'ge-0/0', 'fe-0')
        port_groups = {}
        for port in ports:
            # Extract prefix and last number
            parts = port.rsplit('/', 1)
            if len(parts) == 2:
                prefix = parts[0]
                try:
                    num = int(parts[1])
                    if prefix not in port_groups:
                        port_groups[prefix] = []
                    port_groups[prefix].append(num)
                except ValueError:
                    # If can't parse, treat as single port
                    if None not in port_groups:
                        port_groups[None] = []
                    port_groups[None].append(port)
            else:
                # No slash, treat as single port
                if None not in port_groups:
                    port_groups[None] = []
                port_groups[None].append(port)
        
        # Build ranges for each prefix
        range_strings = []
        
        for prefix, nums in sorted(port_groups.items()):
            if prefix is None:
                # Single ports without prefix
                range_strings.extend(nums)
            else:
                # Sort numbers and find consecutive ranges
                nums.sort()
                ranges = []
                start = nums[0]
                end = nums[0]
                
                for i in range(1, len(nums)):
                    if nums[i] == end + 1:
                        end = nums[i]
                    else:
                        # End of range
                        if start == end:
                            ranges.append(f"{prefix}/{start}")
                        else:
                            ranges.append(f"{prefix}/{start}-{end}")
                        start = nums[i]
                        end = nums[i]
                
                # Add final range
                if start == end:
                    ranges.append(f"{prefix}/{start}")
                else:
                    ranges.append(f"{prefix}/{start}-{end}")
                
                range_strings.extend(ranges)
        
        return ", ".join(range_strings)
    
    def _get_mgmt_network_name(self, cisco_config: CiscoConfig) -> str:
        """Get the management network name."""
        if cisco_config.management.vlan_id:
            vlan = cisco_config.vlans.get(cisco_config.management.vlan_id)
            if vlan and vlan.name:
                return vlan.name
        return "Management"
    
    def _extract_simple_port_id(self, interface_name: str) -> str:
        """Extract simple port identifier from Cisco interface name.
        
        Examples:
          GigabitEthernet1/0/5 -> ge-1/0/5
          FastEthernet0/24 -> fe-0/24
          GigabitEthernet0/1 -> ge-0/1
        """
        import re
        
        # Match interface patterns
        match = re.match(r'(GigabitEthernet|FastEthernet|TenGigabitEthernet)(\d+/\d+(?:/\d+)?)', interface_name, re.IGNORECASE)
        
        if match:
            if_type = match.group(1).lower()
            port_num = match.group(2)
            
            # Convert to Junos-style naming
            if if_type.startswith('gigabit'):
                prefix = 'ge'
            elif if_type.startswith('fast'):
                prefix = 'fe'
            elif if_type.startswith('ten'):
                prefix = 'xe'
            else:
                prefix = 'et'
            
            return f"{prefix}-{port_num}"
        
        # Fallback to just the interface name
        return interface_name
    
    def _port_sort_key(self, port_id: str) -> tuple:
        """Generate a sort key for port identifiers."""
        import re
        
        # Extract numbers from port ID for proper sorting
        # e.g., "ge-1/0/5" -> (1, 0, 5)
        numbers = re.findall(r'\d+', port_id)
        return tuple(int(n) for n in numbers)

    def merge_templates(self, templates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple Mist templates into a single org-level template."""
        if not templates:
            return {}
        
        if len(templates) == 1:
            return templates[0]
        
        # Start with the first template
        merged = templates[0].copy()
        merged["name"] = "Merged-Org-Template"
        
        # Merge networks (VLANs)
        all_networks = {}
        for template in templates:
            if "networks" in template:
                for net_name, net_config in template["networks"].items():
                    if net_name not in all_networks:
                        all_networks[net_name] = net_config
                    # TODO: Conflict detection will be handled by merger module
        
        merged["networks"] = all_networks
        
        # Merge port profiles
        all_port_usages = {}
        for template in templates:
            if "port_usages" in template:
                for profile_name, profile_config in template["port_usages"].items():
                    # Rename if conflict exists
                    unique_name = profile_name
                    counter = 1
                    while unique_name in all_port_usages:
                        unique_name = f"{profile_name}-{counter}"
                        counter += 1
                    all_port_usages[unique_name] = profile_config
        
        merged["port_usages"] = all_port_usages
        
        # Merge switch matching rules
        all_rules = []
        for template in templates:
            if "switch_matching" in template and "rules" in template["switch_matching"]:
                all_rules.extend(template["switch_matching"]["rules"])
        
        if all_rules:
            merged["switch_matching"] = {"rules": all_rules}
        
        return merged
