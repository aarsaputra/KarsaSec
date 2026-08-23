"""K1 Integrated Security Analysis Engine (Task K1.4).

Aggregates findings from JWT, OAuth, and Business Logic Knowledge Packs while
ensuring complete cross-pack isolation, detector blindness, determinism, and
zero label contamination.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.analysis.taint.business_logic import BusinessLogicAnalyzer
from karsasec.analysis.taint.jwt import JWTAnalyzer
from karsasec.analysis.taint.oauth import OAuthAnalyzer


@dataclass(frozen=True)
class K1IntegratedFinding:
    rule_id: str
    property_name: str
    knowledge_pack: str
    cwe: str
    severity: str
    line_number: int
    rationale: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "property_name": self.property_name,
            "knowledge_pack": self.knowledge_pack,
            "cwe": self.cwe,
            "severity": self.severity,
            "line_number": self.line_number,
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


class K1IntegratedAnalyzer:
    """Integrated K1 Analysis Engine executing JWT, OAuth, and Business Logic analyzers."""

    def __init__(self) -> None:
        self.jwt_analyzer = JWTAnalyzer()
        self.oauth_analyzer = OAuthAnalyzer()
        self.biz_analyzer = BusinessLogicAnalyzer()

    def analyze_code(
        self,
        source_code: str,
        language: str = "Python",
        framework: str | None = None,
        enabled_packs: tuple[str, ...] = ("JWT", "OAuth", "Business Logic"),
    ) -> list[K1IntegratedFinding]:
        """Performs isolated, deterministic analysis across enabled Knowledge Packs."""
        integrated_findings: list[K1IntegratedFinding] = []
        if not source_code:
            return integrated_findings

        # 1. Isolated JWT Pass
        if "JWT" in enabled_packs:
            jwt_res = self.jwt_analyzer.analyze_code(source_code, language)
            for f in jwt_res:
                integrated_findings.append(
                    K1IntegratedFinding(
                        rule_id=f.rule_id,
                        property_name=f.property_name,
                        knowledge_pack="JWT",
                        cwe=f.cwe,
                        severity=f.severity,
                        line_number=f.line_number,
                        rationale=f.rationale,
                        evidence=f.evidence,
                    )
                )

        # 2. Isolated OAuth Pass
        if "OAuth" in enabled_packs:
            oauth_res = self.oauth_analyzer.analyze_code(source_code, language)
            for f in oauth_res:
                integrated_findings.append(
                    K1IntegratedFinding(
                        rule_id=f.rule_id,
                        property_name=f.property_name,
                        knowledge_pack="OAuth",
                        cwe=f.cwe,
                        severity=f.severity,
                        line_number=f.line_number,
                        rationale=f.rationale,
                        evidence=f.evidence,
                    )
                )

        # 3. Isolated Business Logic Pass
        if "Business Logic" in enabled_packs:
            biz_res = self.biz_analyzer.analyze_code(source_code, language)
            for f in biz_res:
                integrated_findings.append(
                    K1IntegratedFinding(
                        rule_id=f.rule_id,
                        property_name=f.property_name,
                        knowledge_pack="Business Logic",
                        cwe=f.cwe,
                        severity=f.severity,
                        line_number=f.line_number,
                        rationale=f.rationale,
                        evidence=f.evidence,
                    )
                )

        # Deterministic sorting by knowledge_pack, rule_id, line_number
        return sorted(
            integrated_findings,
            key=lambda x: (x.knowledge_pack, x.rule_id, x.line_number, x.property_name),
        )


def analyze_k1(
    source_code: str,
    language: str = "Python",
    framework: str | None = None,
) -> list[K1IntegratedFinding]:
    """Helper entry point for blind K1 analysis."""
    analyzer = K1IntegratedAnalyzer()
    return analyzer.analyze_code(source_code, language, framework)
