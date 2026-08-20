"""Server Configuration settings for KarsaSec REST API."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerSettings(BaseSettings):
    """Enterprise REST API server settings."""

    model_config = SettingsConfigDict(env_prefix="KARSASEC_SERVER_", case_sensitive=False)

    host: str = Field(default="127.0.0.1", description="Host address for API server.")
    port: int = Field(default=8000, description="Port for API server.")
    api_prefix: str = Field(default="/api/v1", description="URL prefix for v1 API routes.")
    title: str = Field(default="KarsaSec SecOS Enterprise REST API", description="API Title")
    version: str = Field(default="1.0.0", description="API Version")
    debug: bool = Field(default=False, description="Debug mode flag.")
    cors_origins: list[str] = Field(default=["*"], description="CORS allowed origins.")
    auth_secret_key: str = Field(
        default="karsasec-dev-secret-key-change-in-production-32bytes",
        description="Development secret key for tokens.",
    )


server_settings = ServerSettings()
