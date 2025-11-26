"""Merge configurations and handle conflicts."""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import questionary

from .parser import CiscoConfig, VLANConfig, InterfaceConfig


@dataclass
class Conflict:
    """Represents a configuration conflict."""
    type: str  # "vlan", "interface", "management"
    key: str  # VLAN ID, interface name, etc.
    source1: str  # Source file 1
    value1: Any
    source2: str  # Source file 2
    value2: Any
    description: str


class ConfigMerger:
    """Merge multiple Cisco configurations with conflict resolution."""

    def __init__(self, interactive: bool = True):
        """Initialize merger.
        
        Args:
            interactive: If True, prompt user for conflict resolution. 
                        If False, use first config for conflicts.
        """
        self.interactive = interactive
        self.conflicts: List[Conflict] = []

    def merge_configs(self, configs: List[CiscoConfig]) -> CiscoConfig:
        """Merge multiple Cisco configs into one, resolving conflicts."""
        if not configs:
            raise ValueError("No configs to merge")
        
        if len(configs) == 1:
            return configs[0]
        
        # Start with first config as base
        merged = CiscoConfig(
            hostname=configs[0].hostname,
            spanning_tree_mode=configs[0].spanning_tree_mode,
            vtp_mode=configs[0].vtp_mode,
            source_file="merged"
        )
        
        # Merge VLANs
        merged.vlans = self._merge_vlans(configs)
        
        # Merge interfaces
        merged.interfaces = self._merge_interfaces(configs)
        
        # Merge management
        merged.management = self._merge_management(configs)
        
        # Report conflicts if any were detected
        if self.conflicts:
            print(f"\n✓ Resolved {len(self.conflicts)} conflicts during merge")
        
        return merged

    def _merge_vlans(self, configs: List[CiscoConfig]) -> Dict[int, VLANConfig]:
        """Merge VLANs from multiple configs."""
        merged_vlans = {}
        vlan_sources = {}  # Track which config each VLAN came from
        
        for config in configs:
            for vlan_id, vlan in config.vlans.items():
                if vlan_id not in merged_vlans:
                    # First occurrence
                    merged_vlans[vlan_id] = vlan
                    vlan_sources[vlan_id] = config.source_file
                else:
                    # VLAN already exists - check for conflicts
                    existing = merged_vlans[vlan_id]
                    
                    # Check if configurations differ
                    if (existing.name != vlan.name or 
                        existing.state != vlan.state):
                        
                        conflict = Conflict(
                            type="vlan",
                            key=str(vlan_id),
                            source1=vlan_sources[vlan_id],
                            value1=existing,
                            source2=config.source_file,
                            value2=vlan,
                            description=f"VLAN {vlan_id} has different configurations"
                        )
                        
                        # Resolve conflict
                        resolved = self._resolve_vlan_conflict(conflict)
                        if resolved:
                            merged_vlans[vlan_id] = resolved
                            vlan_sources[vlan_id] = config.source_file if resolved == vlan else vlan_sources[vlan_id]
        
        return merged_vlans

    def _merge_interfaces(self, configs: List[CiscoConfig]) -> Dict[str, InterfaceConfig]:
        """Merge interfaces from multiple configs."""
        merged_interfaces = {}
        interface_sources = {}
        
        for config in configs:
            for if_name, interface in config.interfaces.items():
                if if_name not in merged_interfaces:
                    # First occurrence
                    merged_interfaces[if_name] = interface
                    interface_sources[if_name] = config.source_file
                else:
                    # Interface already exists - check for conflicts
                    existing = merged_interfaces[if_name]
                    
                    # Check if configurations differ significantly
                    if not self._interfaces_match(existing, interface):
                        conflict = Conflict(
                            type="interface",
                            key=if_name,
                            source1=interface_sources[if_name],
                            value1=existing,
                            source2=config.source_file,
                            value2=interface,
                            description=f"Interface {if_name} has conflicting configurations"
                        )
                        
                        # Resolve conflict
                        resolved = self._resolve_interface_conflict(conflict)
                        if resolved:
                            merged_interfaces[if_name] = resolved
                            interface_sources[if_name] = config.source_file if resolved == interface else interface_sources[if_name]
        
        return merged_interfaces

    def _merge_management(self, configs: List[CiscoConfig]) -> Any:
        """Merge management configurations."""
        # Use first non-empty management config
        for config in configs:
            if config.management.vlan_id or config.management.ip_address:
                # Check for conflicts with other configs
                for other_config in configs:
                    if other_config == config:
                        continue
                    
                    if (other_config.management.vlan_id and 
                        other_config.management.vlan_id != config.management.vlan_id):
                        
                        conflict = Conflict(
                            type="management",
                            key="vlan_id",
                            source1=config.source_file,
                            value1=config.management.vlan_id,
                            source2=other_config.source_file,
                            value2=other_config.management.vlan_id,
                            description="Management VLAN ID differs between configs"
                        )
                        
                        choice = self._resolve_management_conflict(conflict)
                        if choice == 2:
                            return other_config.management
                
                return config.management
        
        # Return empty management if none found
        return configs[0].management

    def _interfaces_match(self, if1: InterfaceConfig, if2: InterfaceConfig) -> bool:
        """Check if two interface configs are equivalent."""
        return (
            if1.mode == if2.mode and
            if1.access_vlan == if2.access_vlan and
            if1.trunk_native_vlan == if2.trunk_native_vlan and
            if1.trunk_allowed_vlans == if2.trunk_allowed_vlans and
            if1.nonegotiate == if2.nonegotiate and
            if1.portfast == if2.portfast and
            if1.bpduguard == if2.bpduguard and
            if1.shutdown == if2.shutdown
        )

    def _resolve_vlan_conflict(self, conflict: Conflict) -> Optional[VLANConfig]:
        """Resolve a VLAN configuration conflict."""
        self.conflicts.append(conflict)
        
        if not self.interactive:
            # Non-interactive: keep first
            return conflict.value1
        
        vlan1: VLANConfig = conflict.value1
        vlan2: VLANConfig = conflict.value2
        
        print(f"\n⚠️  VLAN {conflict.key} Conflict Detected:")
        print(f"   Source 1: {conflict.source1}")
        print(f"     - Name: {vlan1.name}, State: {vlan1.state}")
        print(f"   Source 2: {conflict.source2}")
        print(f"     - Name: {vlan2.name}, State: {vlan2.state}")
        
        choice = questionary.select(
            "Which configuration should be used?",
            choices=[
                f"Use config from {conflict.source1}",
                f"Use config from {conflict.source2}",
            ]
        ).ask()
        
        return vlan1 if "Source 1" in choice or conflict.source1 in choice else vlan2

    def _resolve_interface_conflict(self, conflict: Conflict) -> Optional[InterfaceConfig]:
        """Resolve an interface configuration conflict."""
        self.conflicts.append(conflict)
        
        if not self.interactive:
            # Non-interactive: keep first
            return conflict.value1
        
        if1: InterfaceConfig = conflict.value1
        if2: InterfaceConfig = conflict.value2
        
        print(f"\n⚠️  Interface {conflict.key} Conflict Detected:")
        print(f"   Source 1: {conflict.source1}")
        self._print_interface_summary(if1)
        print(f"   Source 2: {conflict.source2}")
        self._print_interface_summary(if2)
        
        choice = questionary.select(
            "Which configuration should be used?",
            choices=[
                f"Use config from {conflict.source1}",
                f"Use config from {conflict.source2}",
            ]
        ).ask()
        
        return if1 if "Source 1" in choice or conflict.source1 in choice else if2

    def _resolve_management_conflict(self, conflict: Conflict) -> int:
        """Resolve a management configuration conflict."""
        self.conflicts.append(conflict)
        
        if not self.interactive:
            return 1  # Use first
        
        print(f"\n⚠️  Management Configuration Conflict:")
        print(f"   Source 1: {conflict.source1}")
        print(f"     - {conflict.key}: {conflict.value1}")
        print(f"   Source 2: {conflict.source2}")
        print(f"     - {conflict.key}: {conflict.value2}")
        
        choice = questionary.select(
            "Which configuration should be used?",
            choices=[
                f"Use config from {conflict.source1}",
                f"Use config from {conflict.source2}",
            ]
        ).ask()
        
        return 1 if "Source 1" in choice or conflict.source1 in choice else 2

    def _print_interface_summary(self, interface: InterfaceConfig):
        """Print a summary of an interface configuration."""
        print(f"     - Mode: {interface.mode}")
        if interface.access_vlan:
            print(f"     - Access VLAN: {interface.access_vlan}")
        if interface.trunk_native_vlan:
            print(f"     - Native VLAN: {interface.trunk_native_vlan}")
        if interface.trunk_allowed_vlans:
            print(f"     - Allowed VLANs: {interface.trunk_allowed_vlans}")
        if interface.portfast:
            print(f"     - Portfast: enabled")
        if interface.bpduguard:
            print(f"     - BPDU Guard: enabled")
        if interface.shutdown:
            print(f"     - Status: shutdown")
