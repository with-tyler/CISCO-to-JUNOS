"""
Converter extensions for transforming parsed Cisco configs to Mist API format.
Handles advanced features: routing, OSPF, RADIUS, SNMP, ACLs, etc.
"""

from typing import Dict, List, Optional, Any
from .parser import (
    CiscoConfig, StaticRoute, OSPFConfig, OSPFInterfaceConfig, RADIUSConfig,
    SNMPConfig, DHCPSnoopingConfig, VRFConfig, AccessList, PortMirrorSession,
    SyslogServer, BannerConfig, LocalUser, LineConfig, TACACSServer, STPConfig,
    InterfaceConfig
)


def convert_static_routes(static_routes: List[StaticRoute]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convert parsed static routes to Mist extra_routes and extra_routes6.
    
    API Schema:
    - extra_routes: list of {via: str, metric: int (optional), preference: int (optional), discard: bool (optional)}
    - extra_routes6: list of {via: str, metric: int (optional), preference: int (optional), discard: bool (optional)}
    
    Returns dict with 'extra_routes' and 'extra_routes6' keys.
    """
    ipv4_routes = []
    ipv6_routes = []
    
    for route in static_routes:
        route_dict: Dict[str, Any] = {}
        
        # Determine destination (via or discard)
        if route.is_null_route:
            route_dict['discard'] = True
            route_dict['via'] = route.destination
        else:
            # For Mist, via should be in format "network/prefix via next_hop"
            if route.next_hop:
                route_dict['via'] = f"{route.destination} via {route.next_hop}"
            else:
                # Shouldn't happen but handle gracefully
                route_dict['via'] = route.destination
        
        # Add optional parameters (metric is called 'metric' in StaticRoute, which is admin distance)
        if route.metric is not None:
            route_dict['preference'] = route.metric
        
        # Note: Cisco doesn't use 'metric' for static routes (it's 'distance'),
        # but we can map it if needed
        
        # Separate by IP version
        if route.is_ipv6:
            ipv6_routes.append(route_dict)
        else:
            ipv4_routes.append(route_dict)
    
    result = {}
    if ipv4_routes:
        result['extra_routes'] = ipv4_routes
    if ipv6_routes:
        result['extra_routes6'] = ipv6_routes
    
    return result


def convert_ospf(ospf: Optional[OSPFConfig], ospf_interfaces: Dict[str, OSPFInterfaceConfig]) -> Dict[str, Any]:
    """
    Convert parsed OSPF configuration to Mist ospf_areas.
    
    API Schema:
    - ospf_areas: {area_id: {networks: list[str], include_loopback: bool, type: "default"|"nssa"|"stub"}}
    
    Note: Mist API has limited OSPF support compared to Cisco.
    We'll convert what we can and document limitations.
    """
    if not ospf or not ospf.networks:
        return {}
    
    ospf_areas: Dict[str, Dict[str, Any]] = {}
    
    # Group networks by area
    for network in ospf.networks:
        area_id = network.area
        
        if area_id not in ospf_areas:
            ospf_areas[area_id] = {
                'networks': [],
                'include_loopback': False,
                'type': 'default'
            }
        
        # Convert wildcard mask to prefix length and add network in CIDR format
        prefix_length = _wildcard_to_prefix(network.wildcard)
        ospf_areas[area_id]['networks'].append(
            f"{network.network}/{prefix_length}"
        )
    
    # Note: Mist API doesn't support per-area auth, passive interfaces, or
    # per-interface OSPF settings in the template. These would need to be
    # applied via additional_config_cmds or per-switch.
    
    return {'ospf_areas': ospf_areas} if ospf_areas else {}


def convert_radius(radius: Optional[RADIUSConfig]) -> Dict[str, Any]:
    """
    Convert parsed RADIUS configuration to Mist radius_config.
    
    API Schema:
    - radius_config: {
        auth_servers: list[{host: str, port: int, secret: str}],
        acct_servers: list[{host: str, port: int, secret: str}],
        auth_servers_timeout: int,
        auth_servers_retries: int,
        coa_enabled: bool,
        coa_port: int,
        network: str,
        source_ip: str
      }
    """
    if not radius or not radius.servers:
        return {}
    
    auth_servers = []
    acct_servers = []
    
    for server in radius.servers:
        # Authentication server
        auth_server = {
            'host': server.host,
            'port': server.auth_port,
            'secret': server.key or radius.key or ''
        }
        auth_servers.append(auth_server)
        
        # Accounting server (if different port)
        if server.acct_port and server.acct_port != server.auth_port:
            acct_server = {
                'host': server.host,
                'port': server.acct_port,
                'secret': server.key or radius.key or ''
            }
            acct_servers.append(acct_server)
    
    radius_config: Dict[str, Any] = {}
    
    if auth_servers:
        radius_config['auth_servers'] = auth_servers
    
    if acct_servers:
        radius_config['acct_servers'] = acct_servers
    
    if radius.timeout is not None:
        radius_config['auth_servers_timeout'] = radius.timeout
    
    if radius.retransmit is not None:
        radius_config['auth_servers_retries'] = radius.retransmit
    
    if radius.source_interface:
        # Note: Mist expects IP address for source_ip, not interface name
        # This would need to be resolved from interface configs
        radius_config['source_ip'] = f"{{{{ {radius.source_interface}_ip }}}}"
    
    return {'radius_config': radius_config} if radius_config else {}


def convert_snmp(snmp: Optional[SNMPConfig]) -> Dict[str, Any]:
    """
    Convert parsed SNMP configuration to Mist snmp_config.
    
    API Schema:
    - snmp_config: {
        description: str,
        location: str,
        contact: str,
        enabled: bool,
        network: str,
        trap_groups: list[{group_name: str, categories: list[str], version: "v2c"|"v3", targets: list[str]}],
        v2c_config: list[{client_list_name: str, community: str, view: str}],
        v3_config: {usm: {users: list[{name: str, authentication_password: str, encryption_password: str}]}}
      }
    """
    if not snmp:
        return {}
    
    snmp_config: Dict[str, Any] = {
        'enabled': True
    }
    
    if snmp.location:
        snmp_config['location'] = snmp.location
    
    if snmp.contact:
        snmp_config['contact'] = snmp.contact
    
    # Convert communities to v2c_config
    if snmp.communities:
        v2c_config = []
        for community_string, access_level in snmp.communities.items():
            v2c_entry = {
                'community': community_string,
                'client_list_name': f"{community_string}_acl"
            }
            if access_level == 'RO':
                v2c_entry['view'] = 'view_ro'
            else:
                v2c_entry['view'] = 'view_rw'
            v2c_config.append(v2c_entry)
        
        if v2c_config:
            snmp_config['v2c_config'] = v2c_config
    
    # Convert trap hosts to trap_groups
    if snmp.trap_hosts:
        trap_groups = []
        for trap_host in snmp.trap_hosts:
            # trap_host is a dict with keys: host, version, community
            trap_group = {
                'group_name': f"trap_{trap_host['host'].replace('.', '_')}",
                'version': trap_host.get('version', 'v2c'),
                'targets': [trap_host['host']]
            }
            if 'community' in trap_host:
                # Community is used in SNMP v2c traps
                trap_group['community'] = trap_host['community']
            
            # Default categories - Cisco 'snmp-server enable traps' is very broad
            if snmp.enable_traps:
                trap_group['categories'] = ['all']
            else:
                trap_group['categories'] = ['link-up-down']
            
            trap_groups.append(trap_group)
        
        if trap_groups:
            snmp_config['trap_groups'] = trap_groups
    
    return {'snmp_config': snmp_config} if snmp_config else {}


def convert_dhcp_snooping(dhcp_snooping: Optional[DHCPSnoopingConfig]) -> Dict[str, Any]:
    """
    Convert parsed DHCP snooping configuration to Mist dhcp_snooping.
    
    API Schema:
    - dhcp_snooping: {
        enabled: bool,
        all_networks: bool,
        networks: list[str],
        enable_arp_spoof_check: bool,
        enable_ip_source_guard: bool
      }
    
    Note: Per-port trust settings are handled in port profiles (allow_dhcpd field).
    """
    if not dhcp_snooping or not dhcp_snooping.enabled:
        return {}
    
    dhcp_snooping_config: Dict[str, Any] = {
        'enabled': True
    }
    
    if dhcp_snooping.vlans:
        dhcp_snooping_config['networks'] = dhcp_snooping.vlans
        dhcp_snooping_config['all_networks'] = False
    else:
        # If no VLANs specified, assume all
        dhcp_snooping_config['all_networks'] = True
    
    # Cisco "ip verify source" maps to ip_source_guard
    # Cisco "ip dhcp snooping verify mac-address" maps to arp_spoof_check
    if dhcp_snooping.verify_mac:
        dhcp_snooping_config['enable_arp_spoof_check'] = True
    
    return {'dhcp_snooping': dhcp_snooping_config}


def convert_vrfs(vrfs: Dict[str, VRFConfig]) -> Dict[str, Any]:
    """
    Convert parsed VRF configurations to Mist vrf_instances.
    
    API Schema:
    - vrf_instances: {
        vrf_name: {
          networks: list[str],
          extra_routes: {network: {via: str}}
        }
      }
    """
    if not vrfs:
        return {}
    
    vrf_instances: Dict[str, Dict[str, Any]] = {}
    
    for vrf_name, vrf in vrfs.items():
        vrf_instance: Dict[str, Any] = {}
        
        # Add networks (interfaces assigned to this VRF)
        if vrf.interfaces:
            vrf_instance['networks'] = vrf.interfaces
        
        # Note: VRF-specific routes would need to be parsed separately
        # from global routing table. This is a limitation of current parser.
        
        vrf_instances[vrf_name] = vrf_instance
    
    return {'vrf_instances': vrf_instances} if vrf_instances else {}


def convert_acls(acls: Dict[str, AccessList]) -> Dict[str, Any]:
    """
    Convert parsed ACLs to Mist acl_policies and acl_tags.
    
    API Schema:
    - acl_policies: list[{
        name: str,
        actions: list[{
          action: "allow"|"deny",
          src_net: str,
          dst_net: str,
          protocol: str,
          src_port: str,
          dst_port: str
        }]
      }]
    - acl_tags: {tag_name: {type: "match"|"radius_group"|"vlan", match: str, values: list[str]}}
    """
    if not acls:
        return {}
    
    acl_policies = []
    
    for acl_name, acl in acls.items():
        if not acl.entries:
            continue
        
        actions = []
        for entry in acl.entries:
            action_dict: Dict[str, Any] = {
                'action': entry.action.lower()
            }
            
            if entry.protocol and entry.protocol.lower() != 'ip':
                action_dict['protocol'] = entry.protocol.lower()
            
            # Source
            if entry.source and entry.source.lower() != 'any':
                if entry.source_wildcard and entry.source_wildcard != '0.0.0.0':
                    # Convert wildcard to prefix length
                    action_dict['src_net'] = f"{entry.source}/{_wildcard_to_prefix(entry.source_wildcard)}"
                else:
                    action_dict['src_net'] = f"{entry.source}/32"
            
            # Destination
            if entry.destination and entry.destination.lower() != 'any':
                if entry.destination_wildcard and entry.destination_wildcard != '0.0.0.0':
                    action_dict['dst_net'] = f"{entry.destination}/{_wildcard_to_prefix(entry.destination_wildcard)}"
                else:
                    action_dict['dst_net'] = f"{entry.destination}/32"
            
            # Port specification (may need parsing if present)
            if entry.port_spec:
                # Port spec might be something like "eq 80" or "range 1024 65535"
                # For now, store as-is - proper parsing would depend on format
                action_dict['port_spec'] = entry.port_spec
            
            actions.append(action_dict)
        
        acl_policies.append({
            'name': acl_name,
            'actions': actions
        })
    
    return {'acl_policies': acl_policies} if acl_policies else {}


def convert_port_mirroring(sessions: Dict[str, PortMirrorSession]) -> Dict[str, Any]:
    """
    Convert parsed port mirroring sessions to Mist port_mirroring.
    
    API Schema:
    - port_mirroring: {
        session_name: {
          input_networks_ingress: list[str],
          input_networks_egress: list[str],
          input_port_ids_ingress: list[str],
          input_port_ids_egress: list[str],
          output_network: str,
          output_port_id: str
        }
      }
    """
    if not sessions:
        return {}
    
    port_mirroring: Dict[str, Dict[str, Any]] = {}
    
    for session_name, session in sessions.items():
        mirror_config: Dict[str, Any] = {}
        
        # Source ports/interfaces
        if session.source_ports:
            # Separate ingress/egress if direction specified
            if session.source_direction == 'rx':
                mirror_config['input_port_ids_ingress'] = session.source_ports
            elif session.source_direction == 'tx':
                mirror_config['input_port_ids_egress'] = session.source_ports
            else:  # both
                mirror_config['input_port_ids_ingress'] = session.source_ports
                mirror_config['input_port_ids_egress'] = session.source_ports
        
        # Source VLANs
        if session.source_vlans:
            if session.source_direction == 'rx':
                mirror_config['input_networks_ingress'] = session.source_vlans
            elif session.source_direction == 'tx':
                mirror_config['input_networks_egress'] = session.source_vlans
            else:
                mirror_config['input_networks_ingress'] = session.source_vlans
                mirror_config['input_networks_egress'] = session.source_vlans
        
        # Destination
        if session.destination_port:
            mirror_config['output_port_id'] = session.destination_port
        
        port_mirroring[session_name] = mirror_config
    
    return {'port_mirroring': port_mirroring} if port_mirroring else {}


def convert_syslog(syslog_servers: List[SyslogServer]) -> Dict[str, Any]:
    """
    Convert parsed syslog servers to Mist remote_syslog.
    
    API Schema:
    - remote_syslog: {
        enabled: bool,
        network: str,
        send_to_all_servers: bool,
        servers: list[{host: str, port: int, protocol: "udp"|"tcp", facility: str, severity: str}]
      }
    """
    if not syslog_servers:
        return {}
    
    servers = []
    for syslog_server in syslog_servers:
        server_dict: Dict[str, Any] = {
            'host': syslog_server.host,
            'port': 514,  # Default syslog port
            'protocol': 'udp'
        }
        
        if syslog_server.severity:
            server_dict['severity'] = syslog_server.severity
        
        if syslog_server.facility:
            server_dict['facility'] = syslog_server.facility
        
        servers.append(server_dict)
    
    remote_syslog = {
        'enabled': True,
        'servers': servers,
        'send_to_all_servers': True
    }
    
    return {'remote_syslog': remote_syslog}


def convert_switch_mgmt(
    banner: Optional[BannerConfig],
    local_users: List[LocalUser],
    line_configs: Dict[str, LineConfig],
    tacacs_servers: List[TACACSServer]
) -> Dict[str, Any]:
    """
    Convert parsed switch management settings to Mist switch_mgmt.
    
    API Schema:
    - switch_mgmt: {
        cli_banner: str,
        cli_idle_timeout: int,
        protect_re: {enabled: bool, allowed_services: list[str]},
        local_accounts: {username: {password: str, role: "admin"|"helpdesk"|"read"}},
        tacacs: {
          enabled: bool,
          acct_servers: list[{host: str, port: int, secret: str, timeout: int}],
          auth_servers: list[{host: str, port: int, secret: str, timeout: int}],
          network: str
        }
      }
    """
    switch_mgmt: Dict[str, Any] = {}
    
    # Banner
    if banner and banner.login:
        switch_mgmt['cli_banner'] = banner.login
    
    # Idle timeout from line configs
    if 'vty' in line_configs:
        vty_config = line_configs['vty']
        if vty_config.exec_timeout is not None:
            switch_mgmt['cli_idle_timeout'] = vty_config.exec_timeout
    
    # Local accounts
    if local_users:
        local_accounts: Dict[str, Dict[str, Any]] = {}
        for user in local_users:
            role = 'read'  # Default
            if user.privilege is not None:
                if user.privilege >= 15:
                    role = 'admin'
                elif user.privilege >= 7:
                    role = 'helpdesk'
            
            local_accounts[user.username] = {
                'role': role
            }
            
            # Note: Mist doesn't store passwords in templates for security
            # Password would be set separately per switch
        
        if local_accounts:
            switch_mgmt['local_accounts'] = local_accounts
    
    # TACACS+
    if tacacs_servers:
        tacacs_config: Dict[str, Any] = {
            'enabled': True,
            'auth_servers': [],
            'acct_servers': []
        }
        
        for tacacs_server in tacacs_servers:
            server_dict = {
                'host': tacacs_server.host,
                'port': 49,  # Default TACACS+ port
                'secret': tacacs_server.key or ''
            }
            tacacs_config['auth_servers'].append(server_dict)
            tacacs_config['acct_servers'].append(server_dict.copy())
        
        switch_mgmt['tacacs'] = tacacs_config
    
    return {'switch_mgmt': switch_mgmt} if switch_mgmt else {}


def convert_stp(stp: Optional[STPConfig]) -> Dict[str, Any]:
    """
    Convert parsed STP configuration to Mist stp_config.
    
    API Schema:
    - stp_config: {
        enabled: bool,
        mode: "mstp"|"rstp",
        bridge_priority: int,
        vlan_config: {vlan_id: {priority: int}}
      }
    
    Note: Per-interface STP settings (portfast, bpduguard) are handled
    in port profiles, not in stp_config.
    """
    if not stp:
        return {}
    
    stp_config: Dict[str, Any] = {
        'enabled': True
    }
    
    # Map Cisco mode to Mist mode
    if stp.mode:
        if 'rapid-pvst' in stp.mode or 'rstp' in stp.mode:
            stp_config['mode'] = 'rstp'
        elif 'mst' in stp.mode:
            stp_config['mode'] = 'mstp'
        else:
            stp_config['mode'] = 'rstp'  # Default
    
    # VLAN priorities
    if stp.vlan_priorities:
        vlan_config = {}
        for vlan_id, priority in stp.vlan_priorities.items():
            vlan_config[vlan_id] = {'priority': priority}
        
        if vlan_config:
            stp_config['vlan_config'] = vlan_config
    
    return {'stp_config': stp_config}


def enhance_port_profile_with_advanced_features(
    port_profile: Dict[str, Any],
    interface_config: InterfaceConfig
) -> Dict[str, Any]:
    """
    Enhance a port profile with advanced features from interface config.
    
    This adds fields beyond basic VLAN/trunk configuration:
    - Voice VLAN (voip_network)
    - Speed/duplex
    - PoE settings
    - Port security (mac_limit)
    - 802.1X/MAB authentication
    - DHCP snooping trust
    - Storm control
    - Port description
    
    Note: Only sets values that differ from the defaults already in port_profile.
    """
    # Voice VLAN - only set if configured
    if interface_config.voice_vlan:
        vlan_name = f"VLAN{interface_config.voice_vlan}"
        port_profile['voip_network'] = vlan_name
    
    # Speed - parser already converts to Mist format (1g, 10g, etc)
    if interface_config.speed and interface_config.speed != 'auto':
        port_profile['speed'] = interface_config.speed
    
    # Duplex - use as-is from parser
    if interface_config.duplex and interface_config.duplex != 'auto':
        port_profile['duplex'] = interface_config.duplex
    
    # PoE - only set if explicitly disabled
    if interface_config.poe_disabled is not None and interface_config.poe_disabled:
        port_profile['poe_disabled'] = True
    
    # Port security → MAC limit - only set if configured
    if interface_config.port_security and interface_config.port_security_max:
        port_profile['mac_limit'] = interface_config.port_security_max
    
    # 802.1X/MAB authentication - only set if configured
    if interface_config.dot1x_pae == 'authenticator':
        port_auth: Dict[str, Any] = {}
        
        if interface_config.dot1x_port_control:
            control_map = {
                'auto': 'auto',
                'force-authorized': 'force_authorized',
                'force-unauthorized': 'force_unauthorized'
            }
            port_auth['control'] = control_map.get(
                interface_config.dot1x_port_control, 
                'auto'
            )
        
        # MAB (MAC Authentication Bypass)
        if interface_config.mab:
            port_profile['enable_mac_auth'] = True
            port_profile['mac_auth_only'] = False  # MAB with 802.1X
        
        # Reauthentication
        if interface_config.authentication_timer_reauthenticate:
            port_profile['reauth_interval'] = interface_config.authentication_timer_reauthenticate
        
        # Set port_auth if we have control settings
        if port_auth:
            port_profile['port_auth'] = port_auth
    
    # DHCP snooping trust
    if interface_config.dhcp_snooping_trust:
        port_profile['allow_dhcpd'] = True
    
    # Storm control - only set if configured
    if (interface_config.storm_control_broadcast or 
        interface_config.storm_control_multicast or 
        interface_config.storm_control_unknown_unicast):
        
        storm_control: Dict[str, Any] = {}
        
        if interface_config.storm_control_broadcast:
            storm_control['no_broadcast'] = False
            storm_control['percentage'] = interface_config.storm_control_broadcast
        
        if interface_config.storm_control_multicast:
            storm_control['no_multicast'] = False
            if 'percentage' not in storm_control:
                storm_control['percentage'] = interface_config.storm_control_multicast
        
        if interface_config.storm_control_unknown_unicast:
            storm_control['no_unknown_unicast'] = False
            if 'percentage' not in storm_control:
                storm_control['percentage'] = interface_config.storm_control_unknown_unicast
        
        port_profile['storm_control'] = storm_control
    
    return port_profile


def _wildcard_to_prefix(wildcard: str) -> int:
    """
    Convert Cisco wildcard mask to prefix length.
    Example: 0.0.0.255 → 24, 0.0.255.255 → 16
    """
    # Invert wildcard to get netmask
    parts = wildcard.split('.')
    netmask_parts = [str(255 - int(p)) for p in parts]
    netmask = '.'.join(netmask_parts)
    
    # Convert netmask to prefix length
    binary = ''.join([bin(int(x) + 256)[3:] for x in netmask_parts])
    return binary.count('1')
