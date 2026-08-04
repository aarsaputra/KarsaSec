"""SeverityFormatter for ANSI terminal coloring and --no-color mode support."""

from typing import Dict
from karsasec.rules.enums import Severity

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_BOLD_RED = "\033[1;31m"
COLOR_RED = "\033[0;31m"
COLOR_YELLOW = "\033[0;33m"
COLOR_BLUE = "\033[0;34m"
COLOR_GRAY = "\033[0;37m"

SEVERITY_COLORS: Dict[Severity, str] = {
    Severity.CRITICAL: COLOR_BOLD_RED,
    Severity.HIGH: COLOR_RED,
    Severity.MEDIUM: COLOR_YELLOW,
    Severity.LOW: COLOR_BLUE,
    Severity.INFO: COLOR_GRAY,
}

class SeverityFormatter:
    """Formats text and severity labels for terminal output with optional ANSI coloring."""

    def __init__(self, no_color: bool = False) -> None:
        self.no_color = no_color

    def format_severity(self, severity: Severity) -> str:
        """Formats a severity label string, applying ANSI colors if color mode is enabled."""
        label = severity.name.upper()
        if self.no_color:
            return f"[{label}]"

        color = SEVERITY_COLORS.get(severity, COLOR_RESET)
        return f"{color}[{label}]{COLOR_RESET}"

    def color_text(self, text: str, color_code: str) -> str:
        """Wraps text in ANSI color codes if color mode is enabled."""
        if self.no_color:
            return text
        return f"{color_code}{text}{COLOR_RESET}"
