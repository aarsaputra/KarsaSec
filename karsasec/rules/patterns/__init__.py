"""Rules patterns subpackage containing default rule YAML definitions."""

from pathlib import Path

def get_default_rules_directory() -> Path:
    """Returns the Path to the default rule YAML patterns directory."""
    return Path(__file__).parent
