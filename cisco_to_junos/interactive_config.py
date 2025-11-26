"""Interactive prompts for additional template configuration."""

from typing import Dict, Any, List, Optional
import questionary


class InteractiveConfigPrompts:
    """Handle interactive prompts for additional template configuration."""

    def collect_additional_config(self, template: Dict[str, Any], interactive: bool = True) -> Dict[str, Any]:
        """Collect additional configuration settings interactively.
        
        Args:
            template: Base Mist template from conversion
            interactive: Whether to prompt interactively (False uses defaults)
            
        Returns:
            Enhanced template with additional configuration
        """
        if not interactive:
            return self._apply_defaults(template)
        
        print("\n🔧 Additional Configuration")
        print("=" * 60)
        print("These settings aren't typically in Cisco configs but are")
        print("commonly needed in Mist templates. Press Enter to skip any.")
        print("=" * 60 + "\n")
        
        # Template name
        template = self._prompt_template_name(template)
        
        # DNS servers
        template = self._prompt_dns(template)
        
        # NTP servers
        template = self._prompt_ntp(template)
        
        # DNS suffix
        template = self._prompt_dns_suffix(template)
        
        # RADIUS configuration
        template = self._prompt_radius(template)
        
        # Additional CLI commands
        template = self._prompt_additional_commands(template)
        
        # Timezone
        template = self._prompt_timezone(template)
        
        return template

    def _prompt_template_name(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Prompt for template name."""
        current_name = template.get('name', 'Cisco-Converted-Template')
        
        response = questionary.text(
            "Template name:",
            default=current_name
        ).ask()
        
        if response and response.strip():
            template['name'] = response.strip()
        
        return template

    def _prompt_dns(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Prompt for DNS servers."""
        print("\n📡 DNS Servers")
        print("Examples: {{pridns}}, {{altdns}}, 8.8.8.8, 1.1.1.1")
        
        add_dns = questionary.confirm(
            "Configure DNS servers?",
            default=False
        ).ask()
        
        if not add_dns:
            return template
        
        dns_servers = []
        
        # Primary DNS
        primary = questionary.text(
            "Primary DNS server:"
        ).ask()
        
        if primary and primary.strip():
            dns_servers.append(primary.strip())
        
        # Secondary DNS
        secondary = questionary.text(
            "Secondary DNS server (optional):"
        ).ask()
        
        if secondary and secondary.strip():
            dns_servers.append(secondary.strip())
        
        # Additional DNS servers
        while questionary.confirm("Add another DNS server?", default=False).ask():
            additional = questionary.text("DNS server:").ask()
            if additional and additional.strip():
                dns_servers.append(additional.strip())
        
        if dns_servers:
            template['dns_servers'] = dns_servers
        
        return template

    def _prompt_ntp(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Prompt for NTP servers."""
        print("\n🕐 NTP Servers")
        print("Examples: {{ntp1}}, {{ntp2}}, time.google.com, pool.ntp.org")
        
        add_ntp = questionary.confirm(
            "Configure NTP servers?",
            default=False
        ).ask()
        
        if not add_ntp:
            return template
        
        ntp_servers = []
        
        # Primary NTP
        primary = questionary.text(
            "Primary NTP server:"
        ).ask()
        
        if primary and primary.strip():
            ntp_servers.append(primary.strip())
        
        # Secondary NTP
        secondary = questionary.text(
            "Secondary NTP server (optional):"
        ).ask()
        
        if secondary and secondary.strip():
            ntp_servers.append(secondary.strip())
        
        # Additional NTP servers
        while questionary.confirm("Add another NTP server?", default=False).ask():
            additional = questionary.text("NTP server:").ask()
            if additional and additional.strip():
                ntp_servers.append(additional.strip())
        
        if ntp_servers:
            template['ntp_servers'] = ntp_servers
        
        return template

    def _prompt_dns_suffix(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Prompt for DNS suffix/search domains."""
        add_suffix = questionary.confirm(
            "Configure DNS search suffixes?",
            default=False
        ).ask()
        
        if not add_suffix:
            return template
        
        suffixes = []
        
        while True:
            suffix = questionary.text(
                "DNS suffix (e.g., example.com):",
                default="" if suffixes else "{{dns_suffix}}"
            ).ask()
            
            if suffix and suffix.strip():
                suffixes.append(suffix.strip())
                
                if not questionary.confirm("Add another suffix?", default=False).ask():
                    break
            else:
                break
        
        if suffixes:
            template['dns_suffix'] = suffixes
        
        return template

    def _prompt_radius(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Prompt for RADIUS configuration."""
        print("\n🔐 RADIUS Configuration")
        
        add_radius = questionary.confirm(
            "Configure RADIUS authentication?",
            default=False
        ).ask()
        
        if not add_radius:
            # Add disabled RADIUS config
            template['radius_config'] = {
                'enabled': False,
                'auth_servers': [],
                'acct_servers': [],
                'auth_servers_timeout': 5,
                'auth_servers_retries': 3,
                'fast_dot1x_timers': False,
                'acct_interim_interval': 0,
                'auth_server_selection': 'ordered',
                'coa_enabled': False,
                'coa_port': ''
            }
            return template
        
        radius_config = {
            'enabled': True,
            'auth_servers': [],
            'acct_servers': [],
            'auth_servers_timeout': 5,
            'auth_servers_retries': 3,
            'fast_dot1x_timers': False,
            'acct_interim_interval': 0,
            'auth_server_selection': 'ordered',
            'coa_enabled': False,
            'coa_port': ''
        }
        
        # Authentication servers
        print("\nAuthentication Servers:")
        print("Examples: {{radius_server}}, 10.1.1.100, radius.example.com")
        while True:
            host = questionary.text(
                "RADIUS auth server (IP or hostname):"
            ).ask()
            
            if not host or not host.strip():
                break
            
            secret = questionary.password(
                "RADIUS secret (example: {{radius_secret}}):"
            ).ask()
            
            port = questionary.text(
                "Port:",
                default="1812"
            ).ask()
            
            radius_config['auth_servers'].append({
                'host': host.strip(),
                'secret': secret.strip() if secret else '{{radius_secret}}',
                'port': int(port) if port and port.isdigit() else 1812
            })
            
            if not questionary.confirm("Add another auth server?", default=False).ask():
                break
        
        # Accounting servers (optional)
        if questionary.confirm("Configure RADIUS accounting servers?", default=False).ask():
            print("Examples: {{radius_acct_server}}, 10.1.1.101")
            while True:
                host = questionary.text(
                    "RADIUS accounting server:"
                ).ask()
                
                if not host or not host.strip():
                    break
                
                secret = questionary.password(
                    "RADIUS secret:"
                ).ask()
                
                port = questionary.text(
                    "Port:",
                    default="1813"
                ).ask()
                
                radius_config['acct_servers'].append({
                    'host': host.strip(),
                    'secret': secret.strip() if secret else '{{radius_secret}}',
                    'port': int(port) if port and port.isdigit() else 1813
                })
                
                if not questionary.confirm("Add another accounting server?", default=False).ask():
                    break
        
        # Advanced RADIUS settings
        if questionary.confirm("Configure advanced RADIUS settings?", default=False).ask():
            timeout = questionary.text(
                "Auth server timeout (seconds):",
                default="5"
            ).ask()
            
            retries = questionary.text(
                "Auth server retries:",
                default="3"
            ).ask()
            
            fast_timers = questionary.confirm(
                "Enable fast 802.1X timers?",
                default=False
            ).ask()
            
            coa_enabled = questionary.confirm(
                "Enable Change of Authorization (CoA)?",
                default=False
            ).ask()
            
            radius_config['auth_servers_timeout'] = int(timeout) if timeout and timeout.isdigit() else 5
            radius_config['auth_servers_retries'] = int(retries) if retries and retries.isdigit() else 3
            radius_config['fast_dot1x_timers'] = fast_timers
            radius_config['coa_enabled'] = coa_enabled
            
            if coa_enabled:
                coa_port = questionary.text(
                    "CoA port:",
                    default="3799"
                ).ask()
                radius_config['coa_port'] = int(coa_port) if coa_port and coa_port.isdigit() else 3799
        
        template['radius_config'] = radius_config
        return template

    def _prompt_additional_commands(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Prompt for additional Junos CLI commands."""
        print("\n⚙️  Additional Junos Commands")
        print("These will be applied directly to switches via CLI.")
        
        add_commands = questionary.confirm(
            "Add custom Junos CLI commands?",
            default=False
        ).ask()
        
        if not add_commands:
            return template
        
        commands = template.get('additional_config_cmds', [])
        
        print("\nExamples:")
        print("  - set system root-authentication ssh-rsa \"key...\"")
        print("  - set system services ssh root-login allow")
        print("  - set interfaces vlan unit 0 description \"Management VLAN\"")
        print("\nEnter commands one at a time. Press Enter on empty line to finish.\n")
        
        while True:
            cmd = questionary.text(
                "Junos command:",
                multiline=False
            ).ask()
            
            if not cmd or not cmd.strip():
                break
            
            commands.append(cmd.strip())
            print(f"  ✓ Added: {cmd.strip()}")
        
        if commands:
            template['additional_config_cmds'] = commands
        
        return template

    def _prompt_timezone(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Prompt for timezone configuration."""
        add_tz = questionary.confirm(
            "Configure timezone?",
            default=False
        ).ask()
        
        if not add_tz:
            return template
        
        timezone = questionary.text(
            "Timezone (e.g., America/Los_Angeles, Europe/London):",
            default="America/New_York"
        ).ask()
        
        if timezone and timezone.strip():
            commands = template.get('additional_config_cmds', [])
            tz_cmd = f'set system time-zone {timezone.strip()}'
            
            # Remove existing timezone command if present
            commands = [c for c in commands if not c.startswith('set system time-zone')]
            commands.append(tz_cmd)
            
            template['additional_config_cmds'] = commands
        
        return template

    def _apply_defaults(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Apply default configuration when not interactive.
        
        Args:
            template: Base template
            
        Returns:
            Template with default additional config
        """
        # Add disabled RADIUS by default
        if 'radius_config' not in template:
            template['radius_config'] = {
                'enabled': False,
                'auth_servers': [],
                'acct_servers': [],
                'auth_servers_timeout': 5,
                'auth_servers_retries': 3,
                'fast_dot1x_timers': False,
                'acct_interim_interval': 0,
                'auth_server_selection': 'ordered',
                'coa_enabled': False,
                'coa_port': ''
            }
        
        # Use template variables for DNS/NTP if not already set
        if 'dns_servers' not in template:
            template['dns_servers'] = []
        
        if 'ntp_servers' not in template:
            template['ntp_servers'] = []
        
        if 'dns_suffix' not in template:
            template['dns_suffix'] = []
        
        return template
