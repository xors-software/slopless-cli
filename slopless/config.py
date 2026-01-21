"""Configuration and credential management for Slopless CLI.

Handles:
- License key storage (~/.slopless/credentials.json)
- API URL configuration
- Authentication headers
"""

import hashlib
import json
import os
import platform
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

# Default hosted API endpoint
DEFAULT_API_URL = "https://api.slopless.work"

# Local config directory
DEFAULT_CONFIG_DIR = Path.home() / ".slopless"


@dataclass
class LicenseInfo:
    """Information about a validated license."""

    license_key: str
    email: str | None = None
    plan: str = "free"
    valid: bool = True
    expires_at: str | None = None
    usage_limit: int | None = None
    usage_count: int = 0
    # Organization support - org keys can be shared across teams
    organization: str | None = None
    seats: int | None = None


@dataclass
class Credentials:
    """Stored credentials for the CLI."""

    license_key: str
    api_url: str = DEFAULT_API_URL

    def to_dict(self) -> dict[str, Any]:
        return {
            "license_key": self.license_key,
            "api_url": self.api_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Credentials":
        return cls(
            license_key=data["license_key"],
            api_url=data.get("api_url", DEFAULT_API_URL),
        )


def get_config_dir() -> Path:
    """Get the config directory, creating it if needed."""
    config_dir = Path(os.environ.get("SLOPLESS_CONFIG_DIR", DEFAULT_CONFIG_DIR))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_credentials_path() -> Path:
    """Get the path to the credentials file."""
    return get_config_dir() / "credentials.json"


def save_credentials(credentials: Credentials) -> None:
    """Save credentials to disk."""
    path = get_credentials_path()
    path.write_text(json.dumps(credentials.to_dict(), indent=2))
    # Secure the file (owner read/write only)
    path.chmod(0o600)


def load_credentials() -> Credentials | None:
    """Load credentials from disk, if they exist."""
    path = get_credentials_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return Credentials.from_dict(data)
    except (json.JSONDecodeError, KeyError):
        return None


def clear_credentials() -> None:
    """Remove stored credentials."""
    path = get_credentials_path()
    if path.exists():
        path.unlink()


def get_license_key() -> str | None:
    """Get the license key from environment or stored credentials."""
    # Environment variable takes precedence
    env_key = os.environ.get("SLOPLESS_LICENSE_KEY")
    if env_key:
        return env_key

    # Fall back to stored credentials
    creds = load_credentials()
    return creds.license_key if creds else None


def get_api_url() -> str:
    """Get the API URL from environment or stored credentials."""
    # Environment variable takes precedence
    env_url = os.environ.get("SLOPLESS_API_URL")
    if env_url:
        return env_url

    # Fall back to stored credentials or default
    creds = load_credentials()
    return creds.api_url if creds else DEFAULT_API_URL


def mask_license_key(key: str) -> str:
    """Mask a license key for display (show first 8 and last 4 chars)."""
    if len(key) <= 12:
        return key[:4] + "..." + key[-2:]
    return key[:8] + "..." + key[-4:]


def generate_device_id() -> str:
    """Generate a unique device ID for this machine."""
    hostname = platform.node()
    mac = uuid.getnode()
    raw = f"{hostname}-{mac}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_auth_headers() -> dict[str, str]:
    """Get authentication headers for API calls."""
    license_key = get_license_key()
    if not license_key:
        return {}

    return {
        "Authorization": f"Bearer {license_key}",
        "X-Device-ID": generate_device_id(),
    }


async def validate_license(license_key: str, api_url: str | None = None) -> LicenseInfo:
    """Validate a license key against the licensing server.

    Args:
        license_key: The license key to validate
        api_url: Override the default API URL

    Returns:
        LicenseInfo with validation results
    """
    url = api_url or get_api_url()

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{url}/v1/license/validate",
            json={"license_key": license_key},
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 401:
            return LicenseInfo(
                license_key=license_key,
                valid=False,
            )

        response.raise_for_status()
        data = response.json()

        return LicenseInfo(
            license_key=license_key,
            email=data.get("email"),
            plan=data.get("plan", "free"),
            valid=data.get("valid", True),
            expires_at=data.get("expires_at"),
            usage_limit=data.get("usage_limit"),
            usage_count=data.get("usage_count", 0),
            organization=data.get("organization"),
            seats=data.get("seats"),
        )
