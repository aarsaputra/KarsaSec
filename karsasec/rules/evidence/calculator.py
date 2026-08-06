"""ConfidenceCalculator mapping evidence reports and rule overrides to Confidence levels."""

from karsasec.rules.enums import Confidence
from karsasec.rules.evidence.collector import EvidenceReport
from karsasec.rules.schema import Rule


class ConfidenceCalculator:
    """Calculates hybrid confidence combining fixed rule overrides and dynamic evidence scoring."""

    def calculate(self, report: EvidenceReport, rule: Rule) -> Confidence:
        """Calculates final Confidence enum level.

        Hybrid approach:
        - If rule output defines confidence explicitly, use rule.output.confidence as baseline.
        - Otherwise or if total_score is evaluated:
          - score >= 80 -> CONFIDENT
          - 50 <= score < 80 -> LIKELY
          - score < 50 -> POSSIBLE
        """
        score = report.total_score

        if score >= 80:
            return Confidence.CONFIDENT
        elif score >= 50:
            return Confidence.LIKELY
        elif score > 0:
            return Confidence.POSSIBLE

        return rule.output.confidence
