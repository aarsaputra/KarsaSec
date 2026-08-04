"""Configuration settings management using Pydantic Settings."""

from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Global configuration settings for KarsaSec."""
    
    app_name: str = "KarsaSec"
    version: str = "0.1.0"
    debug: bool = Field(default=False, description="Enable debug mode and verbose logging")
    
    # Storage & Cache paths
    cache_dir: Path = Field(
        default=Path.home() / ".karsasec" / "cache",
        description="Directory for local database and RAG indices"
    )
    
    # LLM Settings
    default_llm_provider: str = Field(default="litellm", description="Default AI provider adapter")
    default_llm_model: str = Field(default="gemini-2.5-flash", description="Default LLM model name")
    max_token_budget_per_scan: int = Field(default=50000, description="Max token limit per audit session")
    
    model_config = SettingsConfigDict(
        env_prefix="KARSASEC_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
