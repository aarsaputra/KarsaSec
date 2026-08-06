"""Unit tests for Settings configuration."""

from karsasec.config import Settings


def test_default_settings() -> None:
    """Test default settings initialization."""
    settings = Settings()
    assert settings.app_name == "KarsaSec"
    assert settings.version == "0.1.0"
    assert settings.debug is False
    assert settings.default_llm_provider == "litellm"
