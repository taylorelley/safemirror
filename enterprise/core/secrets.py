"""Secrets management for SafeMirror Enterprise.

Provides secure handling of secrets from multiple sources:
- Environment variables
- .env files
- Docker secrets
- Kubernetes secrets (via env vars)
- HashiCorp Vault (optional)

Features:
- Validates required secrets on startup
- Never logs secrets
- Supports secret rotation
- Provides masked display for debugging
"""

import os
import json
from pathlib import Path
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


# Required secrets that must be set in production
REQUIRED_SECRETS = [
    "SECRET_KEY",
    "POSTGRES_PASSWORD",  # or DATABASE_URL
]

# Optional secrets
OPTIONAL_SECRETS = [
    "REDIS_PASSWORD",
    "SMTP_PASSWORD",
    "SENTRY_DSN",
]

# Docker secrets mount path
DOCKER_SECRETS_PATH = "/run/secrets"

# Default (unsafe) secret values that should be changed
UNSAFE_DEFAULTS = [
    "dev-secret-key-change-in-production",
    "changeme",
    "password",
    "secret",
]


@dataclass
class SecretSource:
    """Represents the source of a secret."""
    name: str
    source: str  # env, file, docker_secret, vault
    masked_value: str  # e.g., "sm_****abcd"
    

@dataclass
class SecretsManager:
    """
    Manages secrets from multiple sources.
    
    Priority order:
    1. Environment variables
    2. Docker secrets (/run/secrets/)
    3. .env file
    4. HashiCorp Vault (if configured)
    """
    
    env_file: Optional[str] = ".env.prod"
    docker_secrets_path: str = DOCKER_SECRETS_PATH
    vault_url: Optional[str] = None
    vault_token: Optional[str] = None
    _secrets: Dict[str, SecretSource] = field(default_factory=dict)
    _loaded: bool = False
    
    def load(self) -> None:
        """Load secrets from all sources."""
        if self._loaded:
            return
        
        # 1. Load from .env file first (lowest priority)
        if self.env_file:
            self._load_env_file()
        
        # 2. Load from Docker secrets
        self._load_docker_secrets()
        
        # 3. Environment variables override everything
        self._load_env_vars()
        
        # 4. Load from Vault if configured
        if self.vault_url and self.vault_token:
            self._load_from_vault()
        
        self._loaded = True
    
    def _load_env_file(self) -> None:
        """Load secrets from .env file."""
        env_path = Path(self.env_file)
        if not env_path.exists():
            return
        
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip(').strip(")
                        if key and value:
                            self._secrets[key] = SecretSource(
                                name=key,
                                source="env_file",
                                masked_value=self._mask_value(value),
                            )
                            os.environ.setdefault(key, value)
        except Exception as e:
            logger.warning(f"Failed to load env file: {e}")
    
    def _load_docker_secrets(self) -> None:
        """Load secrets from Docker secrets mount."""
        secrets_path = Path(self.docker_secrets_path)
        if not secrets_path.exists():
            return
        
        for secret_file in secrets_path.iterdir():
            if secret_file.is_file():
                try:
                    value = secret_file.read_text().strip()
                    # Convert filename to env var format
                    key = secret_file.name.upper().replace("-", "_")
                    self._secrets[key] = SecretSource(
                        name=key,
                        source="docker_secret",
                        masked_value=self._mask_value(value),
                    )
                    os.environ[key] = value
                except Exception as e:
                    logger.warning(f"Failed to load Docker secret {secret_file.name}: {e}")
    
    def _load_env_vars(self) -> None:
        """Load secrets from environment variables."""
        for key in REQUIRED_SECRETS + OPTIONAL_SECRETS:
            value = os.environ.get(key)
            if value:
                self._secrets[key] = SecretSource(
                    name=key,
                    source="env",
                    masked_value=self._mask_value(value),
                )
    
    def _load_from_vault(self) -> None:
        """Load secrets from HashiCorp Vault."""
        try:
            import hvac
            client = hvac.Client(url=self.vault_url, token=self.vault_token)
            
            if not client.is_authenticated():
                logger.warning("Vault authentication failed")
                return
            
            # Read secrets from safemirror path
            secret = client.secrets.kv.v2.read_secret_version(
                path="safemirror",
                mount_point="secret",
            )
            
            for key, value in secret["data"]["data"].items():
                key = key.upper()
                self._secrets[key] = SecretSource(
                    name=key,
                    source="vault",
                    masked_value=self._mask_value(value),
                )
                os.environ[key] = value
                
        except ImportError:
            logger.info("hvac not installed, skipping Vault integration")
        except Exception as e:
            logger.warning(f"Failed to load from Vault: {e}")
    
    def _mask_value(self, value: str, show_chars: int = 4) -> str:
        """Mask a secret value for display."""
        if not value:
            return "****"
        if len(value) <= show_chars * 2:
            return "****"
        return f"{value[:show_chars]}****{value[-show_chars:]}"
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a secret value."""
        self.load()
        return os.environ.get(key, default)
    
    def validate(self, production_mode: bool = True) -> List[str]:
        """
        Validate that required secrets are set.
        
        Returns list of validation errors.
        """
        self.load()
        errors = []
        
        for key in REQUIRED_SECRETS:
            value = os.environ.get(key)
            
            if not value:
                # Check if DATABASE_URL is set instead of POSTGRES_PASSWORD
                if key == "POSTGRES_PASSWORD" and os.environ.get("DATABASE_URL"):
                    continue
                errors.append(f"Missing required secret: {key}")
            elif production_mode and value in UNSAFE_DEFAULTS:
                errors.append(f"Secret {key} has an unsafe default value")
        
        return errors
    
    def get_sources(self) -> Dict[str, SecretSource]:
        """Get information about loaded secrets (without values)."""
        self.load()
        return self._secrets.copy()
    
    def rotate(self, key: str, new_value: str) -> None:
        """
        Rotate a secret value.
        
        Note: This only updates the runtime environment.
        The source (Vault, Docker secret, etc.) must be updated separately.
        """
        os.environ[key] = new_value
        self._secrets[key] = SecretSource(
            name=key,
            source="rotated",
            masked_value=self._mask_value(new_value),
        )
        logger.info(f"Secret {key} rotated")


@lru_cache
def get_secrets_manager() -> SecretsManager:
    """Get the singleton secrets manager."""
    manager = SecretsManager()
    manager.load()
    return manager


def validate_secrets(production_mode: bool = True) -> None:
    """
    Validate secrets on startup.
    
    Raises RuntimeError if required secrets are missing or unsafe.
    """
    manager = get_secrets_manager()
    errors = manager.validate(production_mode)
    
    if errors:
        error_msg = "Secret validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        if production_mode:
            raise RuntimeError(error_msg)
        else:
            logger.warning(error_msg)


def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get a secret value."""
    return get_secrets_manager().get(key, default)
