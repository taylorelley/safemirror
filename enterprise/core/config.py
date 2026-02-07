from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    # App
    app_name: str = "SafeMirror Enterprise"
    debug: bool = False
    
    # CORS
    cors_origins: str = "http://localhost:3000"
    
    # Allowed hosts
    allowed_hosts: str = "localhost"
    
    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
    
    @property
    def allowed_hosts_list(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]
    
    # Database
    database_url: str = "postgresql://safemirror:devpass@localhost:5432/safemirror"
    
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    
    # Celery
    celery_broker_url: Optional[str] = None
    celery_result_backend: Optional[str] = None
    
    @property
    def celery_broker(self) -> str:
        return self.celery_broker_url or self.redis_url
    
    @property
    def celery_backend(self) -> str:
        return self.celery_result_backend or self.redis_url
    
    # Security
    secret_key: str = "dev-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_default: int = 100  # requests per window
    rate_limit_window: int = 60  # seconds
    rate_limit_auth: int = 200  # authenticated users
    rate_limit_login: int = 5  # login attempts
    
    # Notifications
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: str = "noreply@safemirror.local"
    smtp_from_name: str = "SafeMirror"
    smtp_use_tls: bool = True
    
    # Webhooks
    webhook_timeout: int = 30
    webhook_max_retries: int = 3
    
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"  # Allow extra env vars without raising validation errors
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
