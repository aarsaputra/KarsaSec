"""Configuration settings management using Pydantic Settings."""

from pathlib import Path
from typing import Any

import yaml
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


def load_project_config(config_path: Path | None = None, search_root: Path | None = None) -> dict[str, Any]:
    """Load a simple project-local YAML configuration if present."""
    candidates: list[Path] = []

    if config_path is not None:
        candidates.append(Path(config_path).expanduser())

    if search_root is not None:
        search_root = Path(search_root).expanduser()
        if search_root.is_file():
            search_root = search_root.parent
        candidates.extend([search_root / "karsasec.yaml", search_root / "karsasec.yml"])

    cwd = Path.cwd().expanduser()
    candidates.extend([cwd / "karsasec.yaml", cwd / "karsasec.yml"])

    seen: set[Path] = set()
    for candidate in candidates:
        normalized = Path(candidate).expanduser()
        if normalized in seen:
            continue
        seen.add(normalized)
        if normalized.exists() and normalized.is_file():
            try:
                data = yaml.safe_load(normalized.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            if isinstance(data, dict):
                return data

    return {}


def get_scan_exclusions(config: dict[str, Any]) -> list[str]:
    """Return configured scan exclusion patterns from the YAML config."""
    scan_section = config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}
    exclusions = scan_section.get("exclude", [])

    if isinstance(exclusions, str):
        return [exclusions]
    if not isinstance(exclusions, list):
        return []

    return [str(item).strip() for item in exclusions if str(item).strip()]
