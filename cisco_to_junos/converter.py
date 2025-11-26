"""Convert Cisco configurations to Mist JSON templates."""

from typing import Dict, List, Any
from .parser import CiscoConfig, VLANConfig, InterfaceConfig
from .converter_extensions import (
    convert_static_routes,
    convert_ospf,
    convert_radius,
    convert_snmp,
    convert_dhcp_snooping,
    convert_vrfs,
    convert_acls,
    convert_port_mirroring,
    convert_syslog,
    convert_switch_mgmt,
    convert_stp,
    enhance_port_profile_with_advanced_features
)


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
        
        # Ensure all VLANs referenced by interfaces are in networks
        template["networks"] = self._ensure_referenced_vlans(template["networks"], cisco_config)
        
        # Add advanced features from converter_extensions
        
        # Static routes (IPv4 and IPv6)
        if cisco_config.static_routes:
            routes = convert_static_routes(cisco_config.static_routes)
            template.update(routes)
        
        # OSPF configuration
        if cisco_config.ospf:
            ospf_config = convert_ospf(cisco_config.ospf, cisco_config.ospf_interfaces or {})
            template.update(ospf_config)
        
        # RADIUS configuration
        if cisco_config.radius:
            radius_config = convert_radius(cisco_config.radius)
            template.update(radius_config)
        
        # SNMP configuration
        if cisco_config.snmp:
            snmp_config = convert_snmp(cisco_config.snmp)
            template.update(snmp_config)
        
        # DHCP snooping
        if cisco_config.dhcp_snooping:
            dhcp_config = convert_dhcp_snooping(cisco_config.dhcp_snooping)
            template.update(dhcp_config)
        
        # VRF instances
        if cisco_config.vrfs:
            vrf_config = convert_vrfs(cisco_config.vrfs)
            template.update(vrf_config)
        
        # ACL policies
        if cisco_config.access_lists:
            acl_config = convert_acls(cisco_config.access_lists)
            template.update(acl_config)
        
        # Port mirroring (SPAN)
        if cisco_config.port_mirror_sessions:
            mirror_config = convert_port_mirroring(cisco_config.port_mirror_sessions)
            template.update(mirror_config)
        
        # Remote syslog
        if cisco_config.syslog_servers:
            syslog_config = convert_syslog(cisco_config.syslog_servers)
            template.update(syslog_config)
        
        # Switch management (banner, users, TACACS+)
        if cisco_config.banner or cisco_config.local_users or cisco_config.tacacs_servers or cisco_config.line_configs:
            switch_mgmt = convert_switch_mgmt(
                cisco_config.banner,
                cisco_config.local_users or [],
                cisco_config.line_configs or {},
                cisco_config.tacacs_servers or []
            )
            template.update(switch_mgmt)
        
        # Spanning Tree Protocol configuration
        if cisco_config.stp:
            stp_config = convert_stp(cisco_config.stp)
            template.update(stp_config)
        
        # Add spanning tree mode to additional_config_cmds for backward compatibility
        additional_cmds = []
        if cisco_config.spanning_tree_mode:
            additional_cmds.append(f"# Spanning Tree Mode: {cisco_config.spanning_tree_mode}")
        
        if additional_cmds:
            if "additional_config_cmds" in template:
                template["additional_config_cmds"].extend(additional_cmds)
            else:
                template["additional_config_cmds"] = additional_cmds
        
        return template

    def _convert_vlans(self, vlans: Dict[int, VLANConfig]) -> Dict[str, Any]:
        """Convert Cisco VLANs to Mist networks.
        
        Note: Includes suspended VLANs since they may be referenced by port profiles
        (e.g., as native VLAN for trunks or access VLAN for disabled ports).
        Mist doesn't have a "suspend" state - VLANs are either defined or not.
        
        Also ensures VLAN 1 exists if not explicitly defined (Cisco default).
        """
        networks = {}
        
        for vlan_id, vlan in vlans.items():
            # Skip VLAN 1 if no custom name - Mist has built-in "default" network
            if vlan_id == 1 and not vlan.name:
                continue
            
            network_name = vlan.name if vlan.name else f"VLAN{vlan_id}"
            networks[network_name] = {
                "vlan_id": vlan_id,
                "subnet": "",  # Will need to be filled in or detected
            }
        
        # Note: We don't add VLAN 1 - Mist has a built-in "default" network for it
        # If VLAN 1 has a custom name in Cisco config, it will be added above
        
        return networks
    
    def _ensure_referenced_vlans(self, networks: Dict[str, Any], cisco_config: CiscoConfig) -> Dict[str, Any]:
        """Ensure all VLANs referenced by interfaces exist in networks dict.
        
        This handles cases where interfaces reference VLANs that weren't explicitly
        defined in the VLAN database (common in Cisco configs).
        """
        referenced_vlans = set()
        
        # Collect all VLAN IDs referenced by interfaces
        for interface in cisco_config.interfaces.values():
            if interface.access_vlan:
                referenced_vlans.add(interface.access_vlan)
            if interface.voice_vlan:
                referenced_vlans.add(interface.voice_vlan)
            if interface.trunk_native_vlan:
                referenced_vlans.add(interface.trunk_native_vlan)
            if interface.trunk_allowed_vlans:
                referenced_vlans.update(interface.trunk_allowed_vlans)
        
        # Add any missing VLANs to networks
        for vlan_id in referenced_vlans:
            # Skip VLAN 1 - Mist has a built-in "default" network for it
            # Port profiles will reference "default" but we don't add it to networks
            if vlan_id == 1:
                continue
                
            # Check if already defined (by name or as VLANxx)
            vlan_exists = False
            for network_data in networks.values():
                if network_data.get("vlan_id") == vlan_id:
                    vlan_exists = True
                    break
            
            if not vlan_exists:
                # VLAN not defined - create it
                network_name = f"VLAN{vlan_id}"
                networks[network_name] = {
                    "vlan_id": vlan_id,
                    "subnet": "",
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
                profile_name = self._generate_profile_name(interface, cisco_config)
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
        """Generate a unique key for an interface configuration.
        
        Includes all interface fields for proper grouping.
        """
        key_parts = [
            interface.mode,
            str(interface.access_vlan) if interface.access_vlan else "",
            str(interface.voice_vlan) if interface.voice_vlan else "",
            str(interface.trunk_native_vlan) if interface.trunk_native_vlan else "",
            ",".join(map(str, sorted(interface.trunk_allowed_vlans))),
            str(interface.nonegotiate),
            str(interface.portfast),
            str(interface.bpduguard),
            str(interface.shutdown),
            str(interface.speed) if interface.speed else "",
            str(interface.duplex) if interface.duplex else "",
            str(interface.poe_disabled) if interface.poe_disabled is not None else "",
            str(interface.poe_priority) if interface.poe_priority else "",
            str(interface.port_security) if interface.port_security else "",
            str(interface.port_security_max) if interface.port_security_max else "",
            str(interface.dot1x_pae) if interface.dot1x_pae else "",
            str(interface.dot1x_port_control) if interface.dot1x_port_control else "",
            str(interface.mab) if interface.mab else "",
            str(interface.authentication_periodic) if interface.authentication_periodic else "",
            str(interface.authentication_timer_reauthenticate) if interface.authentication_timer_reauthenticate else "",
            str(interface.dhcp_snooping_trust) if interface.dhcp_snooping_trust else "",
            str(interface.storm_control_broadcast) if interface.storm_control_broadcast else "",
            str(interface.storm_control_multicast) if interface.storm_control_multicast else "",
            str(interface.storm_control_unknown_unicast) if interface.storm_control_unknown_unicast else "",
            str(interface.description) if interface.description else "",
        ]
        return "|".join(key_parts)

    def _generate_profile_name(self, interface: InterfaceConfig, cisco_config: CiscoConfig) -> str:
        """Generate a descriptive profile name based on interface configuration.
        
        Name must follow Mist rules: a-z, A-Z, 0-9, _, - only, start with letter, max 32 chars.
        """
        if interface.shutdown:
            return "Disabled-Ports"
        
        # Determine mode based on configuration (mode field might not be explicitly set)
        is_trunk = interface.mode == "trunk" or (interface.trunk_allowed_vlans and len(interface.trunk_allowed_vlans) > 0)
        is_access = interface.mode == "access" or (interface.access_vlan and not is_trunk)
        
        if is_access:
            # Find VLAN name for access port
            vlan_id = interface.access_vlan
            vlan_name = None
            if vlan_id and cisco_config.vlans:
                for vlan in cisco_config.vlans.values():
                    if vlan.id == vlan_id:
                        vlan_name = vlan.name
                        break
            
            # Build descriptive name (no parentheses - use hyphens only)
            if vlan_name:
                name = f"{vlan_name}-{vlan_id}-Access"
            elif vlan_id:
                name = f"VLAN{vlan_id}-Access"
            else:
                name = "Access-NoVLAN"
            
            # Add feature suffixes (excluding STP features)
            features = []
            if interface.voice_vlan:
                features.append(f"Voice{interface.voice_vlan}")
            if interface.dot1x_pae:
                features.append("Dot1x")
            if interface.port_security:
                features.append("PortSec")
            
            if features:
                name += "-" + "-".join(features)
            
            # Ensure name is valid (max 32 chars, starts with letter)
            name = name.replace(" ", "-")  # Replace any spaces
            if len(name) > 32:
                # Truncate but keep meaningful parts
                if vlan_name and vlan_id:
                    name = f"VLAN{vlan_id}-Access"
                    if features:
                        name += "-" + features[0]  # Add first feature only
            
            return name
        
        elif is_trunk:
            # Create trunk profile name based on allowed VLANs
            if interface.trunk_allowed_vlans:
                vlans = sorted(interface.trunk_allowed_vlans)
                if len(vlans) == 1:
                    vlan_desc = f"VLAN{vlans[0]}"
                elif len(vlans) <= 5:
                    vlan_desc = "VLANs-" + "-".join(map(str, vlans))
                else:
                    vlan_desc = f"VLANs-{min(vlans)}-to-{max(vlans)}"
                
                name = f"Trunk-{vlan_desc}"
            else:
                name = "Trunk-AllVLANs"
            
            # Add native VLAN if set and not default
            if interface.trunk_native_vlan and interface.trunk_native_vlan != 1:
                suffix = f"-Native{interface.trunk_native_vlan}"
                if len(name) + len(suffix) <= 32:
                    name += suffix
            
            return name
        
        else:
            # Fallback for unconfigured/unknown mode
            return "Unconfigured-Port"

    def _create_port_profile(self, interface: InterfaceConfig, cisco_config: CiscoConfig) -> Dict[str, Any]:
        """Create a Mist port profile from an interface configuration.
        
        Generates a complete port profile matching the Mist API schema.
        """
        # Start with base profile with proper defaults
        profile: Dict[str, Any] = {
            "mode": interface.mode if interface.mode else "access",
            "disabled": interface.shutdown if interface.shutdown else False,
            "all_networks": False,
            "enable_qos": False,
            "mac_limit": 0,
            "persist_mac": False,
            "disable_autoneg": False,
            "poe_disabled": False,
            "speed": "auto",
            "duplex": "auto",
            "storm_control": {},
            "networks": None,
            "port_network": None,
            "voip_network": None,
            "stp_edge": False,
            "enable_bpdu_guard": False,
            "stp_disable": False,
            "stp_required": False,
            "stp_p2p": False,
            "stp_no_root_port": False,
            "use_vstp": False,
            "port_auth": None,
            "allow_multiple_supplicants": None,
            "enable_mac_auth": None,
            "mac_auth_only": None,
            "mac_auth_preferred": None,
            "guest_network": None,
            "bypass_auth_when_server_down": None,
            "bypass_auth_when_server_down_for_unknown_client": None,
            "dynamic_vlan_networks": None,
            "server_reject_network": None,
            "server_fail_network": None,
            "mac_auth_protocol": None,
            "reauth_interval": None,
            "mtu": None
        }
        
        # Add description if present
        if interface.description:
            profile["description"] = interface.description
        else:
            profile["description"] = f"Converted from Cisco config: {interface.name}"
        
        # Configure based on mode
        # Default to access mode if not explicitly set and has access_vlan
        # (Cisco default behavior)
        if interface.mode == "trunk" or "trunk" in interface.mode:
            profile["mode"] = "trunk"
            profile["all_networks"] = False
            profile["port_network"] = None  # Trunks don't use port_network
            
            # For TRUNK mode: use networks (array)
            if interface.trunk_allowed_vlans:
                networks = []
                for vlan_id in interface.trunk_allowed_vlans:
                    vlan = cisco_config.vlans.get(vlan_id)
                    if vlan:
                        if vlan.name:
                            networks.append(vlan.name)
                        else:
                            networks.append("default" if vlan_id == 1 else f"VLAN{vlan_id}")
                    else:
                        networks.append("default" if vlan_id == 1 else f"VLAN{vlan_id}")
                profile["networks"] = networks
            
            # Native VLAN for trunks
            if interface.trunk_native_vlan:
                vlan = cisco_config.vlans.get(interface.trunk_native_vlan)
                if vlan:
                    if vlan.name:
                        profile["native_network"] = vlan.name
                    else:
                        profile["native_network"] = "default" if interface.trunk_native_vlan == 1 else f"VLAN{interface.trunk_native_vlan}"
                else:
                    profile["native_network"] = "default" if interface.trunk_native_vlan == 1 else f"VLAN{interface.trunk_native_vlan}"
        
        else:
            # Default to access mode (Cisco default when not specified)
            profile["mode"] = "access"
            profile["all_networks"] = False
            
            # For ACCESS mode: use port_network (string), NOT networks (array)
            if interface.access_vlan:
                vlan = cisco_config.vlans.get(interface.access_vlan)
                if vlan:
                    # Use custom name if defined, otherwise VLAN{id} (or "default" for VLAN 1)
                    if vlan.name:
                        profile["port_network"] = vlan.name
                    else:
                        profile["port_network"] = "default" if interface.access_vlan == 1 else f"VLAN{interface.access_vlan}"
                else:
                    # VLAN referenced but not defined - use Mist's "default" for VLAN 1
                    profile["port_network"] = "default" if interface.access_vlan == 1 else f"VLAN{interface.access_vlan}"
            else:
                # No access VLAN configured - default to VLAN 1 (Cisco default)
                # Use Mist's built-in "default" network
                vlan = cisco_config.vlans.get(1)
                if vlan and vlan.name:
                    profile["port_network"] = vlan.name
                else:
                    profile["port_network"] = "default"
            
            profile["networks"] = None  # Must be null for access ports
        
        # STP settings
        if interface.portfast:
            profile["stp_edge"] = True
        
        if interface.bpduguard:
            profile["enable_bpdu_guard"] = True
        
        # Disable autonegotiation
        if interface.nonegotiate:
            profile["disable_autoneg"] = True
        
        # Apply all advanced features from converter_extensions
        # This will add: voice VLAN, speed, duplex, PoE, port auth, storm control, etc.
        profile = enhance_port_profile_with_advanced_features(profile, interface)
        
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
        
        Juniper EX switches use the following interface naming:
        - ge-fpc/pic/port: Gigabit Ethernet (1G)
        - xe-fpc/pic/port: 10 Gigabit Ethernet
        - et-fpc/pic/port: 25G/40G/50G/100G+ Ethernet
        
        Note: Juniper does NOT use 'fe-' prefix. FastEthernet ports should map to 'ge-'
        since modern Juniper switches start at Gigabit speeds.
        
        Examples:
          GigabitEthernet1/0/5 -> ge-1/0/5
          FastEthernet0/24 -> ge-0/0/24 (FastEthernet maps to ge, with normalized slot format)
          GigabitEthernet0/1 -> ge-0/0/1
          TenGigabitEthernet1/1/1 -> xe-1/1/1
        """
        import re
        
        # Match interface patterns
        match = re.match(r'(GigabitEthernet|FastEthernet|TenGigabitEthernet)(\d+/\d+(?:/\d+)?)', interface_name, re.IGNORECASE)
        
        if match:
            if_type = match.group(1).lower()
            port_num = match.group(2)
            
            # Normalize port numbering to fpc/pic/port format
            # Cisco uses slot/port or slot/module/port
            # Juniper uses fpc/pic/port (all three required)
            parts = port_num.split('/')
            if len(parts) == 2:
                # Cisco: slot/port -> Juniper: fpc/pic/port (add pic=0)
                port_num = f"{parts[0]}/0/{parts[1]}"
            
            # Convert to Junos-style naming based on Cisco interface type
            if if_type.startswith('gigabit'):
                prefix = 'ge'
            elif if_type.startswith('fast'):
                # FastEthernet maps to ge- (Juniper switches don't have fe- prefix)
                # Modern Juniper EX switches start at Gigabit speeds
                prefix = 'ge'
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
