"""Adversarial Semantic Corpus Management (Gate 5C & Phase 7 Expansion).

Manages 6 explicit semantic test categories:
- TRUE_POSITIVE
- TRUE_NEGATIVE
- AMBIGUOUS
- CONTRADICTORY
- BOUNDARY
- DECEPTIVE
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.analysis.decision.models import DecisionResolution


class CorpusCategory(StrEnum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    TRUE_NEGATIVE = "TRUE_NEGATIVE"
    AMBIGUOUS = "AMBIGUOUS"
    CONTRADICTORY = "CONTRADICTORY"
    BOUNDARY = "BOUNDARY"
    DECEPTIVE = "DECEPTIVE"


@dataclass(frozen=True)
class AdversarialTestCase:
    """Immutable representation of an adversarial semantic test case."""

    test_id: str
    category: CorpusCategory
    vulnerability_class: str
    cwe: str
    expected_resolution: DecisionResolution
    code_snippet: str
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "category": self.category.value,
            "vulnerability_class": self.vulnerability_class,
            "cwe": self.cwe,
            "expected_resolution": self.expected_resolution.value,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "metadata": self.metadata,
        }


class AdversarialSemanticCorpus:
    """Repository of 6-category adversarial semantic test cases for engine validation."""

    def __init__(self) -> None:
        self.cases: list[AdversarialTestCase] = self._build_default_adversarial_suite()

    def get_all_cases(self) -> list[AdversarialTestCase]:
        return list(self.cases)

    def list_items(self, category: CorpusCategory | None = None) -> list[Any]:
        cases = [c for c in self.cases if c.category == category] if category else self.cases
        return cases

    def get_cases_by_category(self, category: CorpusCategory) -> list[AdversarialTestCase]:
        return [c for c in self.cases if c.category == category]

    def _build_default_adversarial_suite(self) -> list[AdversarialTestCase]:
        return [
            # 1. Direct HTTP Source (TP)
            AdversarialTestCase(
                test_id="ADV-TP-001",
                category=CorpusCategory.TRUE_POSITIVE,
                vulnerability_class="SQL_INJECTION",
                cwe="CWE-89",
                expected_resolution=DecisionResolution.VULNERABLE,
                code_snippet="String val = request.getParameter('id'); stmt.execute('SELECT * FROM users WHERE id=' + val);",
                description="Unsanitized direct HTTP parameter concatenated into SQL query.",
            ),
            # 2. Wrapped HTTP Source (TP)
            AdversarialTestCase(
                test_id="ADV-TP-002",
                category=CorpusCategory.TRUE_POSITIVE,
                vulnerability_class="SQL_INJECTION",
                cwe="CWE-89",
                expected_resolution=DecisionResolution.VULNERABLE,
                code_snippet="String val = customRequest.getInput('id'); stmt.execute('SELECT * FROM users WHERE id=' + val);",
                description="Wrapped HTTP request parameter concatenated into SQL query.",
            ),
            # 3. Direct HTTP Source + Verified Sanitizer (TN)
            AdversarialTestCase(
                test_id="ADV-TN-001",
                category=CorpusCategory.TRUE_NEGATIVE,
                vulnerability_class="SQL_INJECTION",
                cwe="CWE-89",
                expected_resolution=DecisionResolution.SAFE,
                code_snippet="String val = request.getParameter('id'); PreparedStatement stmt = conn.prepareStatement('SELECT * FROM users WHERE id=?'); stmt.setString(1, val);",
                description="Direct HTTP parameter safely parameterized via PreparedStatement.",
            ),
            # 4. Direct HTTP Source + Authz Decorator (TN)
            AdversarialTestCase(
                test_id="ADV-TN-002",
                category=CorpusCategory.TRUE_NEGATIVE,
                vulnerability_class="COMMAND_INJECTION",
                cwe="CWE-78",
                expected_resolution=DecisionResolution.SAFE,
                code_snippet="@require_permission('ADMIN')\ndef run_cmd(request):\n    cmd = request.args.get('cmd')\n    os.system(cmd)",
                description="Administrative command execution protected by verified authorization check.",
            ),
            # 5. Unknown Wrapper Source (AMBIGUOUS -> UNKNOWN)
            AdversarialTestCase(
                test_id="ADV-AMB-001",
                category=CorpusCategory.AMBIGUOUS,
                vulnerability_class="SQL_INJECTION",
                cwe="CWE-89",
                expected_resolution=DecisionResolution.UNKNOWN,
                code_snippet="String val = unknownProvider.fetchData(); stmt.execute('SELECT * FROM users WHERE id=' + val);",
                description="Data source comes from unverified provider wrapper.",
            ),
            # 6. Misleading Sanitizer Name (DECEPTIVE -> VULNERABLE)
            AdversarialTestCase(
                test_id="ADV-DEC-001",
                category=CorpusCategory.DECEPTIVE,
                vulnerability_class="SQL_INJECTION",
                cwe="CWE-89",
                expected_resolution=DecisionResolution.VULNERABLE,
                code_snippet="String val = request.getParameter('id'); String clean = fake_sanitize(val); stmt.execute('SELECT * FROM users WHERE id=' + clean);",
                description="Function named fake_sanitize performs no actual escaping.",
            ),
            # 7. Contradictory Control (CONTRADICTORY -> CONFLICT)
            AdversarialTestCase(
                test_id="ADV-CON-001",
                category=CorpusCategory.CONTRADICTORY,
                vulnerability_class="SQL_INJECTION",
                cwe="CWE-89",
                expected_resolution=DecisionResolution.CONFLICT,
                code_snippet="String val = request.getParameter('id'); stmt.execute('SELECT * FROM users WHERE id=' + val); PreparedStatement p = conn.prepareStatement('SELECT * FROM users WHERE id=?');",
                description="Same endpoint executes both raw unauthenticated query and parameterized query.",
            ),
            # 8. Boundary Property Mismatch (BOUNDARY -> UNKNOWN/VULNERABLE)
            AdversarialTestCase(
                test_id="ADV-BND-001",
                category=CorpusCategory.BOUNDARY,
                vulnerability_class="SQL_INJECTION",
                cwe="CWE-89",
                expected_resolution=DecisionResolution.VULNERABLE,
                code_snippet="String val = request.getParameter('id'); String clean = htmlspecialchars(val); stmt.execute('SELECT * FROM users WHERE id=' + clean);",
                description="HTML sanitizer applied to SQL injection sink yields zero SQL mitigation.",
            ),
        ]
