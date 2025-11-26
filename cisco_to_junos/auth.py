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
        self.org_id = None  # Store org ID if loaded from .env

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
                'email': os.getenv('MIST_EMAIL'),
                'api_key': os.getenv('MIST_API_KEY'),
                'password': os.getenv('MIST_PASSWORD'),
                'host': os.getenv('MIST_HOST', 'api.mist.com')
            }
            # Load org ID if present
            self.org_id = os.getenv('MIST_ORG_ID')
            
            # Try API token first if available
            if self.credentials.get('api_key'):
                print(f"✓ Loaded API token from {self.env_file}")
                if self._create_session_with_token():
                    return True
                print(f"⚠️  API token authentication failed")
                # Token is invalid - offer to create new one if interactive
                if interactive:
                    print("\n💡 Your API token is invalid or expired.")
                    use_alt = questionary.confirm(
                        "Would you like to authenticate with email/password to create a new token?",
                        default=True
                    ).ask()
                    if use_alt:
                        return self._mistapi_interactive_login()
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
            
            # Store email if available from session
            if hasattr(self.api_session, 'email') and self.api_session.email:
                self.credentials['email'] = self.api_session.email
                print(f"📧 Logged in as: {self.api_session.email}")
            
            print("\n✓ Authentication successful")
            
            # Check if we should offer to create API token
            # Offer if: 1) we have an email, and 2) we don't already have a token
            has_email = bool(self.credentials.get('email'))
            has_token = bool(self.credentials.get('api_key'))
            
            # Also check if session has a token (might have logged in with existing token)
            # mistapi stores the token in _apitoken after login
            if hasattr(self.api_session, '_apitoken') and self.api_session._apitoken:
                session_token = self.api_session._apitoken
                if session_token and isinstance(session_token, str):
                    has_token = True
                    self.credentials['api_key'] = session_token
                    print(f"✓ Using existing API token from session")
            
            # Offer to create API token if logged in with password (no token yet)
            if has_email and not has_token:
                create_token = questionary.confirm(
                    "Create an API token for future use? (Recommended - no password needed)",
                    default=True
                ).ask()
                
                if create_token:
                    if self._create_and_save_api_token():
                        print("✓ API token created and will be saved")
            elif not has_email:
                # If no email in session, might have logged in with API token directly
                print("ℹ️  Logged in with API token (email not available)")
            
            # Offer to save credentials
            save = questionary.confirm(
                f"Save credentials to {self.env_file} for future use?",
                default=True
            ).ask()
            
            if save:
                self._save_credentials_to_env()
            
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

    def _create_and_save_api_token(self) -> bool:
        """Create a new API token using mistapi and store it.
        
        Returns:
            True if token created successfully
        """
        try:
            if not self.api_session:
                print("⚠️  No active session")
                return False
            
            # Use mistapi to create token
            print("🔑 Creating API token...")
            token_name = questionary.text(
                "Token name:",
                default="cisco-to-junos-converter"
            ).ask()
            
            if not token_name:
                token_name = "cisco-to-junos-converter"
            
            # Create the token (parameter is 'token_name', not 'name')
            result = self.api_session.create_api_token(token_name=token_name)
            
            # Extract token from APIResponse
            token = None
            if result and hasattr(result, 'data'):
                # result.data should be a dict with 'key' field
                if isinstance(result.data, dict) and 'key' in result.data:
                    token = result.data['key']
                elif isinstance(result.data, str):
                    token = result.data
            
            if token and isinstance(token, str):
                self.credentials['api_key'] = token
                print(f"✓ API token '{token_name}' created successfully")
                return True
            else:
                print(f"⚠️  Failed to extract API token from response")
                if result:
                    print(f"   Response type: {type(result)}, has data: {hasattr(result, 'data')}")
                    if hasattr(result, 'data'):
                        print(f"   Data type: {type(result.data)}, data: {result.data}")
                return False
                
        except Exception as e:
            print(f"⚠️  Error creating API token: {e}")
            return False
    
    def _save_credentials_to_env(self):
        """Save credentials to .env file, preserving existing values."""
        try:
            # Read existing .env if it exists
            existing = {}
            if Path(self.env_file).exists():
                with open(self.env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            existing[key] = value
            
            # Update with new credentials
            if self.credentials.get('email'):
                existing['MIST_EMAIL'] = self.credentials['email']
            if self.credentials.get('api_key'):
                # Ensure we're saving a string, not an object
                token = self.credentials['api_key']
                if isinstance(token, str):
                    existing['MIST_API_KEY'] = token
                else:
                    print(f"⚠️  Warning: API token is not a string, skipping save")
            if self.credentials.get('host'):
                existing['MIST_HOST'] = self.credentials['host']
            
            # Remove old MIST_USERNAME if it exists (standardize on MIST_EMAIL)
            existing.pop('MIST_USERNAME', None)
            # Never save password for security
            existing.pop('MIST_PASSWORD', None)
            
            # Write back all values
            with open(self.env_file, 'w') as f:
                for key, value in existing.items():
                    f.write(f"{key}={value}\n")
            
            print(f"✓ Credentials saved to {self.env_file}")
        except Exception as e:
            print(f"⚠️  Failed to save credentials: {e}")
    
    def _update_env_file(self, key: str, value: str) -> bool:
        """Update a single key in .env file while preserving others.
        
        Args:
            key: Environment variable key
            value: Environment variable value
            
        Returns:
            True if updated successfully
        """
        try:
            # Read existing .env if it exists
            existing = {}
            if Path(self.env_file).exists():
                with open(self.env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            k, v = line.split('=', 1)
                            existing[k] = v
            
            # Update the key
            existing[key] = value
            
            # Write back
            with open(self.env_file, 'w') as f:
                for k, v in existing.items():
                    f.write(f"{k}={v}\n")
            
            return True
        except Exception as e:
            print(f"⚠️  Failed to update {self.env_file}: {e}")
            return False
    
    def save_org_id(self, org_id: str) -> bool:
        """Save organization ID to .env file.
        
        Args:
            org_id: Mist organization ID
            
        Returns:
            True if saved successfully
        """
        if self._update_env_file('MIST_ORG_ID', org_id):
            self.org_id = org_id
            print(f"✓ Organization ID saved to {self.env_file}")
            return True
        return False
    
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
