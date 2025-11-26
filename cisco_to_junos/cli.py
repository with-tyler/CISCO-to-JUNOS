"""Command-line interface for Cisco to Junos converter."""

import argparse
import sys
import json
from pathlib import Path
from typing import List
import questionary

from .parser import CiscoConfigParser
from .converter import MistConverter
from .merger import ConfigMerger
from .auth import MistAuthenticator, MistAPIClient
from .interactive_config import InteractiveConfigPrompts


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Convert Cisco switch configurations to Mist JSON templates"
    )
    
    parser.add_argument(
        "config_dir",
        help="Directory containing Cisco configuration files"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file path (default: mist_template.json)",
        default="mist_template.json"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify authentication and generate template without submitting to Mist"
    )
    
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Disable interactive prompts (use defaults for conflicts)"
    )
    
    parser.add_argument(
        "--skip-additional-config",
        action="store_true",
        help="Skip prompts for DNS, NTP, RADIUS, and other additional configuration"
    )
    
    parser.add_argument(
        "--org-id",
        help="Mist organization ID (required for submission)"
    )
    
    parser.add_argument(
        "--env-file",
        help="Path to .env file (default: .env)",
        default=".env"
    )
    
    args = parser.parse_args()
    
    # Validate input directory
    config_path = Path(args.config_dir)
    if not config_path.exists():
        print(f"❌ Error: Directory '{args.config_dir}' not found")
        sys.exit(1)
    
    if not config_path.is_dir():
        print(f"❌ Error: '{args.config_dir}' is not a directory")
        sys.exit(1)
    
    # Find all config files
    config_files = list(config_path.glob("*.txt")) + list(config_path.glob("*.cfg"))
    if not config_files:
        print(f"❌ Error: No configuration files (.txt or .cfg) found in '{args.config_dir}'")
        sys.exit(1)
    
    print(f"\n📁 Found {len(config_files)} configuration file(s)")
    for cf in config_files:
        print(f"   - {cf.name}")
    
    # Parse configurations
    print("\n🔍 Parsing Cisco configurations...")
    cisco_parser = CiscoConfigParser()
    parsed_configs = []
    
    for config_file in config_files:
        try:
            config = cisco_parser.parse_file(str(config_file))
            parsed_configs.append(config)
            print(f"   ✓ Parsed {config_file.name}: {len(config.vlans)} VLANs, {len(config.interfaces)} interfaces")
        except Exception as e:
            print(f"   ❌ Failed to parse {config_file.name}: {e}")
            continue
    
    if not parsed_configs:
        print("\n❌ Error: No configurations could be parsed successfully")
        sys.exit(1)
    
    # Merge configurations
    print("\n🔄 Merging configurations...")
    merger = ConfigMerger(interactive=not args.no_interactive)
    
    try:
        merged_config = merger.merge_configs(parsed_configs)
        print(f"   ✓ Merged successfully")
        print(f"   - Total VLANs: {len(merged_config.vlans)}")
        print(f"   - Total interfaces: {len(merged_config.interfaces)}")
    except Exception as e:
        print(f"   ❌ Merge failed: {e}")
        sys.exit(1)
    
    # Convert to Mist template
    print("\n🔧 Converting to Mist template...")
    converter = MistConverter()
    
    # Prompt for switch role if interactive
    match_role = "access"  # default
    if not args.no_interactive:
        print("\n🔀 Switch Matching Role")
        print("Select the role for switch matching rules:")
        role_choice = questionary.select(
            "Switch role:",
            choices=[
                "access",
                "core",
                "distribution",
                "edge",
                "Custom (enter your own)"
            ],
            default="access"
        ).ask()
        
        if role_choice == "Custom (enter your own)":
            custom_role = questionary.text(
                "Enter custom switch role:",
                validate=lambda x: len(x.strip()) > 0 or "Role cannot be empty"
            ).ask()
            if custom_role:
                match_role = custom_role.strip()
        elif role_choice:
            match_role = role_choice
    
    try:
        mist_template = converter.convert(merged_config, match_role=match_role)
        print(f"   ✓ Conversion complete")
        print(f"   - Template name: {mist_template.get('name')}")
        print(f"   - Networks: {len(mist_template.get('networks', {}))}")
        print(f"   - Port profiles: {len(mist_template.get('port_usages', {}))}")
        print(f"   - Switch role: {match_role}")
    except Exception as e:
        print(f"   ❌ Conversion failed: {e}")
        sys.exit(1)
    
    # Interactive configuration prompts
    if not args.skip_additional_config:
        print("\n⚙️  Additional Configuration...")
        config_prompts = InteractiveConfigPrompts()
        mist_template = config_prompts.collect_additional_config(
            mist_template, 
            interactive=not args.no_interactive
        )
    else:
        # Apply defaults without prompting
        config_prompts = InteractiveConfigPrompts()
        mist_template = config_prompts._apply_defaults(mist_template)
    
    # Validate template
    print("\n✅ Validating template...")
    validation_errors = validate_template(mist_template)
    
    if validation_errors:
        print("   ⚠️  Validation warnings:")
        for error in validation_errors:
            print(f"      - {error}")
    else:
        print("   ✓ Template is valid")
    
    # Export template
    print(f"\n💾 Exporting template to {args.output}...")
    try:
        with open(args.output, 'w') as f:
            json.dump(mist_template, f, indent=2)
        print(f"   ✓ Template saved")
    except Exception as e:
        print(f"   ❌ Export failed: {e}")
        sys.exit(1)
    
    # Display template preview
    if not args.no_interactive:
        if questionary.confirm("View generated template?", default=False).ask():
            print("\n" + "="*60)
            print(json.dumps(mist_template, indent=2))
            print("="*60)
    
    # Authentication and submission
    if args.dry_run:
        print("\n🔍 Dry-run mode: Verifying authentication...")
        authenticator = MistAuthenticator(args.env_file)
        
        if authenticator.authenticate(interactive=not args.no_interactive):
            print("   ✓ Authentication verified")
            print("\n✅ Dry-run complete!")
            print(f"   - Template saved to: {args.output}")
            print(f"   - Ready to submit when dry-run is disabled")
        else:
            print("   ❌ Authentication failed")
            sys.exit(1)
    else:
        # Real submission mode
        print("\n🌐 Preparing to submit to Mist API...")
        
        # Authenticate
        authenticator = MistAuthenticator(args.env_file)
        if not authenticator.authenticate(interactive=not args.no_interactive):
            print("❌ Authentication failed")
            sys.exit(1)
        
        # Get org ID
        org_id = args.org_id
        if not org_id and not args.no_interactive:
            org_id = questionary.text(
                "Enter Mist Organization ID:",
                validate=lambda x: len(x) > 0 or "Organization ID is required"
            ).ask()
        
        if not org_id:
            print("❌ Organization ID is required for submission")
            sys.exit(1)
        
        # Confirm submission
        if not args.no_interactive:
            confirm = questionary.confirm(
                f"Submit template '{mist_template.get('name')}' to Org {org_id}?",
                default=False
            ).ask()
            
            if not confirm:
                print("\n❌ Submission cancelled by user")
                sys.exit(0)
        
        # Submit
        api_client = MistAPIClient(authenticator)
        
        print(f"\n📤 Submitting template to Mist...")
        status_code = api_client.submit_template(org_id, mist_template)
        
        # Handle authentication failure
        if status_code == 401:
            print("\n⚠️  Your API token is invalid or expired.")
            
            if not args.no_interactive:
                retry = questionary.confirm(
                    "Would you like to re-enter your credentials?",
                    default=True
                ).ask()
                
                if retry and authenticator.reauthenticate():
                    # Recreate API client with new session
                    api_client = MistAPIClient(authenticator)
                    print(f"\n📤 Retrying template submission...")
                    status_code = api_client.submit_template(org_id, mist_template)
                    
                    if status_code is None:
                        print("\n✅ Success! Template submitted to Mist")
                        print(f"   - Organization ID: {org_id}")
                        print(f"   - Template name: {mist_template.get('name')}")
                        sys.exit(0)
            
            print("\n❌ Submission failed - Invalid credentials")
            sys.exit(1)
        elif status_code is None:
            print("\n✅ Success! Template submitted to Mist")
            print(f"   - Organization ID: {org_id}")
            print(f"   - Template name: {mist_template.get('name')}")
        else:
            print("\n❌ Submission failed")
            sys.exit(1)


def validate_template(template: dict) -> List[str]:
    """Validate Mist template against basic requirements.
    
    Args:
        template: Mist template dictionary
        
    Returns:
        List of validation error messages (empty if valid)
    """
    errors = []
    
    # Check required fields
    if not template.get('name'):
        errors.append("Template is missing 'name' field")
    
    if not template.get('device_type'):
        errors.append("Template is missing 'device_type' field")
    
    # Check networks
    networks = template.get('networks', {})
    if not networks:
        errors.append("Template has no networks defined")
    else:
        for net_name, net_config in networks.items():
            if 'vlan_id' not in net_config:
                errors.append(f"Network '{net_name}' is missing vlan_id")
    
    # Check port usages
    port_usages = template.get('port_usages', {})
    if not port_usages:
        errors.append("Template has no port profiles defined")
    
    return errors


if __name__ == "__main__":
    main()
