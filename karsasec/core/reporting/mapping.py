"""Severity and SARIF level mapping layer for report interoperability."""

from typing import Dict
from karsasec.rules.enums import Severity

# Maps KarsaSec Severity to SARIF 2.1.0 level strings
SARIF_SEVERITY_MAP: Dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Maps KarsaSec Severity to CVSS / SARIF security score ranks (0.0 to 10.0)
SARIF_SCORE_MAP: Dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}
