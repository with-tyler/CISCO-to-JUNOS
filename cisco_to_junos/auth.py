"""Authentication and API client for Mist."""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import questionary
from dotenv import load_dotenv


class MistAuthenticator:
    """Handle Mist API authentication."""

    def __init__(self, env_file: str = ".env"):
        """Initialize authenticator.
        
        Args:
            env_file: Path to .env file
        """
        self.env_file = env_file
        self.credentials = {}
        self.authenticated = False
        self.api_session = None

    def authenticate(self, interactive: bool = True) -> bool:
        """Authenticate with Mist API.
        
        Args:
            interactive: If True, prompt for credentials if .env fails
            
        Returns:
            True if authentication successful
        """
        # Try loading from .env
        if Path(self.env_file).exists():
            load_dotenv(self.env_file)
            self.credentials = {
                'email': os.getenv('MIST_USERNAME') or os.getenv('MIST_EMAIL'),
                'api_key': os.getenv('MIST_API_KEY'),
                'password': os.getenv('MIST_PASSWORD'),
                'host': os.getenv('MIST_HOST', 'api.mist.com')
            }
            
            # Try API token first if available
            if self.credentials.get('api_key'):
                print(f"✓ Loaded API token from {self.env_file}")
                if self._create_session_with_token():
                    return True
                print(f"⚠️  API token authentication failed")
            # Try email/password if available
            elif self.credentials.get('email') and self.credentials.get('password'):
                print(f"✓ Loaded email/password from {self.env_file}")
                if self._create_session_with_password():
                    return True
                print(f"⚠️  Email/password authentication failed")
            else:
                print(f"⚠️  No valid credentials in {self.env_file}")
        else:
            print(f"⚠️  No {self.env_file} file found")
        
        # Interactive fallback using mistapi's built-in login
        if interactive:
            print("\n🔐 Interactive Login")
            return self._mistapi_interactive_login()
        
        return False

    def _create_session_with_token(self) -> bool:
        """Create mistapi APISession with API token."""
        try:
            import mistapi
            
            # Create API session with token authentication
            self.api_session = mistapi.APISession(
                host=self.credentials.get('host', 'api.mist.com'),
                apitoken=self.credentials.get('api_key'),
                console_log_level=30  # WARNING level to reduce noise
            )
            
            # Token auth doesn't need explicit login
            self.authenticated = True
            return True
            
        except ImportError:
            print("⚠️  mistapi package not installed. Run: pip install mistapi")
            return False
        except Exception as e:
            print(f"⚠️  Failed to create API session: {e}")
            return False
    
    def _create_session_with_password(self) -> bool:
        """Create mistapi APISession with email/password."""
        try:
            import mistapi
            
            # Create API session with email/password
            self.api_session = mistapi.APISession(
                email=self.credentials.get('email'),
                password=self.credentials.get('password'),
                host=self.credentials.get('host', 'api.mist.com'),
                console_log_level=30  # WARNING level to reduce noise
            )
            
            # Login with email/password (may prompt for 2FA)
            print("🔑 Logging in with email/password...")
            self.api_session.login()
            self.authenticated = True
            return True
            
        except ImportError:
            print("⚠️  mistapi package not installed. Run: pip install mistapi")
            return False
        except Exception as e:
            print(f"⚠️  Login failed: {e}")
            return False

    def _mistapi_interactive_login(self) -> bool:
        """Use mistapi's built-in interactive login.
        
        This will prompt for email and password, handle 2FA if needed,
        and can use API token as an alternative.
        """
        try:
            import mistapi
            
            print("\nMist supports two authentication methods:")
            print("  1. Email/Password (supports 2FA)")
            print("  2. API Token (from Mist dashboard)")
            print("\nPlease follow the prompts...\n")
            
            # Let user choose host first
            host = questionary.text(
                "Mist Host:",
                default=self.credentials.get('host', 'api.mist.com')
            ).ask()
            
            if not host:
                host = 'api.mist.com'
            
            # Create session without credentials - mistapi will prompt
            self.api_session = mistapi.APISession(
                host=host,
                console_log_level=30  # WARNING level
            )
            
            # mistapi's login() will interactively prompt for credentials
            # It handles email/password, 2FA, and API token options
            self.api_session.login()
            
            self.authenticated = True
            self.credentials['host'] = host
            
            # Offer to save (but we can't save password for security)
            print("\n✓ Authentication successful")
            save = questionary.confirm(
                f"Save host configuration to {self.env_file}?",
                default=True
            ).ask()
            
            if save:
                self._save_host_config()
            
            return True
            
        except ImportError:
            print("⚠️  mistapi package not installed. Run: pip install mistapi")
            return False
        except (KeyboardInterrupt, EOFError):
            print("\n❌ Authentication cancelled")
            return False
        except Exception as e:
            print(f"❌ Login failed: {e}")
            return False

    def _save_credentials(self):
        """Save credentials to .env file."""
        try:
            with open(self.env_file, 'w') as f:
                if self.credentials.get('email'):
                    f.write(f"MIST_EMAIL={self.credentials['email']}\n")
                if self.credentials.get('api_key'):
                    f.write(f"MIST_API_KEY={self.credentials['api_key']}\n")
                f.write(f"MIST_HOST={self.credentials.get('host', 'api.mist.com')}\n")
            
            print(f"✓ Credentials saved to {self.env_file}")
        except Exception as e:
            print(f"⚠️  Failed to save credentials: {e}")
    
    def _save_host_config(self):
        """Save only host configuration to .env file."""
        try:
            # Read existing .env if it exists
            existing = {}
            if Path(self.env_file).exists():
                with open(self.env_file, 'r') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            existing[key] = value
            
            # Update host
            existing['MIST_HOST'] = self.credentials.get('host', 'api.mist.com')
            
            # Write back
            with open(self.env_file, 'w') as f:
                for key, value in existing.items():
                    f.write(f"{key}={value}\n")
            
            print(f"✓ Host configuration saved to {self.env_file}")
        except Exception as e:
            print(f"⚠️  Failed to save configuration: {e}")
    
    def reauthenticate(self) -> bool:
        """Force re-authentication with interactive login.
        
        Returns:
            True if re-authentication successful
        """
        print("\n🔄 Re-authentication required")
        self.authenticated = False
        self.api_session = None
        return self._mistapi_interactive_login()


class MistAPIClient:
    """Client for Mist API operations using mistapi library."""

    def __init__(self, authenticator: MistAuthenticator, dry_run: bool = False):
        """Initialize API client.
        
        Args:
            authenticator: Authenticated MistAuthenticator instance
            dry_run: If True, don't actually submit to API
        """
        self.authenticator = authenticator
        self.dry_run = dry_run
        self.session = authenticator.api_session if authenticator.authenticated else None

    def verify_connection(self) -> bool:
        """Verify API connection.
        
        Returns:
            True if connection is valid
        """
        if self.dry_run:
            print("✓ Dry-run mode: Authentication verified (not actually connecting)")
            return self.authenticator.authenticated
        
        if not self.session:
            print("❌ No active API session")
            return False
        
        try:
            # Test connection by listing orgs
            import mistapi
            response = mistapi.api.v1.orgs.orgs.listOrgs(self.session)
            
            if response.status_code == 200:
                print("✓ Connected to Mist API")
                return True
            elif response.status_code == 401:
                print(f"❌ Authentication failed: Invalid or expired API token")
                return False
            else:
                print(f"❌ API connection failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Failed to verify connection: {e}")
            return False

    def submit_template(self, org_id: str, template: Dict[str, Any]) -> Optional[int]:
        """Submit network template to Mist.
        
        Args:
            org_id: Mist organization ID
            template: Network template JSON
            
        Returns:
            None if successful, HTTP status code if failed (401 = auth failure)
        """
        if self.dry_run:
            print("\n🔍 Dry-run mode: Template NOT submitted to Mist API")
            print(f"   Would submit to Org ID: {org_id}")
            print(f"   Template name: {template.get('name', 'Unknown')}")
            return None
        
        if not self.session:
            print("❌ No active API session")
            return 500
        
        try:
            import mistapi
            
            # Submit template using mistapi
            response = mistapi.api.v1.orgs.networktemplates.createOrgNetworkTemplate(
                self.session,
                org_id,
                template
            )
            
            if response.status_code == 200:
                print(f"✓ Template '{template.get('name')}' submitted to Org {org_id}")
                return None
            else:
                print(f"❌ Failed to submit template: {response.status_code}")
                if hasattr(response, 'data'):
                    print(f"   Error: {response.data}")
                return response.status_code
                
        except Exception as e:
            print(f"❌ Failed to submit template: {e}")
            return 500

    def list_organizations(self) -> List[Dict[str, Any]]:
        """List available organizations.
        
        Returns:
            List of organization dictionaries
        """
        if self.dry_run:
            print("🔍 Dry-run mode: Cannot list organizations")
            return []
        
        if not self.session:
            print("❌ No active API session")
            return []
        
        try:
            import mistapi
            
            response = mistapi.api.v1.orgs.orgs.listOrgs(self.session)
            
            if response.status_code == 200:
                orgs = response.data if hasattr(response, 'data') else []
                return orgs
            else:
                print(f"❌ Failed to list organizations: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"❌ Failed to list organizations: {e}")
            return []

    def list_templates(self, org_id: str) -> List[Dict[str, Any]]:
        """List network templates for an organization.
        
        Args:
            org_id: Mist organization ID
            
        Returns:
            List of network template dictionaries
        """
        if self.dry_run:
            print("🔍 Dry-run mode: Cannot list templates")
            return []
        
        if not self.session:
            print("❌ No active API session")
            return []
        
        try:
            import mistapi
            
            response = mistapi.api.v1.orgs.networktemplates.listOrgNetworkTemplates(
                self.session,
                org_id
            )
            
            if response.status_code == 200:
                templates = response.data if hasattr(response, 'data') else []
                return templates
            else:
                print(f"❌ Failed to list templates: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"❌ Failed to list templates: {e}")
            return []

    def export_template(self, template: Dict[str, Any], output_file: str) -> bool:
        """Export template to JSON file.
        
        Args:
            template: Network template dictionary
            output_file: Path to output JSON file
            
        Returns:
            True if export successful
        """
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(template, f, indent=2)
            
            print(f"✓ Template exported to {output_file}")
            return True
        except Exception as e:
            print(f"❌ Failed to export template: {e}")
            return False
