"""Ground-truth model for the KarsaSec Qualification System (E12-1).

Design decisions:
  - GroundTruth describes EXPECTED behavior, not KarsaSec output.
  - Ground truth is NEVER derived automatically from KarsaSec findings.
  - FP/FN are derived by the QualificationClassifier; they are NOT encoded here.
  - TRUE_NEGATIVE means: at this location no finding should be emitted.
  - TRUE_POSITIVE means: at this location a finding MUST be emitted.
  - UNKNOWN findings are tracked separately and never collapsed into TP/FP.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml

from karsasec.rules.enums import Severity


class GroundTruthExpectation(StrEnum):
    """Expected security behavior at a specific code location.

    TRUE_POSITIVE  — a real vulnerability; KarsaSec MUST detect it.
    TRUE_NEGATIVE  — not a vulnerability; KarsaSec MUST NOT produce a finding.
    """
    TRUE_POSITIVE = "TRUE_POSITIVE"
    TRUE_NEGATIVE = "TRUE_NEGATIVE"


@dataclass(slots=True, frozen=True)
class GroundTruthCase:
    """One manually verified benchmark case.

    Attributes:
        case_id:     Unique, stable identifier within the benchmark (e.g. 'dvwa-sqli-low-001').
        benchmark:   Benchmark this case belongs to (e.g. 'dvwa').
        file:        Relative file path from scan root (e.g. 'vulnerabilities/sqli/source/low.php').
        line:        Expected line of the vulnerability (1-indexed). None means file-level.
        rule_id:     Expected rule that should fire (e.g. 'KS-PHP-0002').
        expected:    Expected outcome (TRUE_POSITIVE or TRUE_NEGATIVE).
        description: Short human justification for this classification.
        cwe:         CWE identifier if known (e.g. 'CWE-89').
        language:    Source language (e.g. 'PHP').
        severity:    Expected severity, if applicable.
    """
    case_id: str
    benchmark: str
    file: str
    line: int | None
    rule_id: str | None
    expected: GroundTruthExpectation
    description: str
    cwe: str | None = None
    language: str | None = None
    severity: Severity | None = None
    category: str | None = None
    rationale: str | None = None
    source_reference: str | None = None

    def __post_init__(self) -> None:
        if not self.case_id or not self.case_id.strip():
            raise ValueError("case_id must not be empty")
        if not self.description or not self.description.strip():
            raise ValueError(f"case '{self.case_id}': description must not be empty")
        if self.line is not None and self.line < 1:
            raise ValueError(f"case '{self.case_id}': line must be ≥ 1, got {self.line}")


@dataclass(frozen=True)
class GroundTruthBenchmark:
    """A collection of ground-truth cases for a named benchmark.

    Invariants enforced at construction:
      - No duplicate case_id values.
      - All cases belong to this benchmark.
    """
    benchmark_id: str
    version: str
    description: str
    cases: tuple[GroundTruthCase, ...]

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for case in self.cases:
            if case.case_id in seen:
                raise ValueError(f"Duplicate case_id '{case.case_id}' in benchmark '{self.benchmark_id}'")
            seen.add(case.case_id)

    @property
    def tp_cases(self) -> tuple[GroundTruthCase, ...]:
        return tuple(c for c in self.cases if c.expected == GroundTruthExpectation.TRUE_POSITIVE)

    @property
    def tn_cases(self) -> tuple[GroundTruthCase, ...]:
        return tuple(c for c in self.cases if c.expected == GroundTruthExpectation.TRUE_NEGATIVE)

    @property
    def rules_covered(self) -> frozenset[str]:
        return frozenset(c.rule_id for c in self.cases if c.rule_id)


class ManifestLoader:
    """Loads and validates a YAML ground-truth manifest."""

    def load(self, manifest_path: Path) -> GroundTruthBenchmark:
        """Load a manifest YAML file and return a validated GroundTruthBenchmark."""
        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found: {manifest_path}")
        try:
            raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise ValueError(f"YAML parse error in {manifest_path}: {e}") from e

        if not isinstance(raw, dict):
            raise ValueError(f"Manifest root must be a mapping, got {type(raw).__name__}")

        bm = raw.get("benchmark", {})
        benchmark_id = str(bm.get("id", "")).strip()
        if not benchmark_id:
            raise ValueError("manifest.benchmark.id is required")
        version = str(bm.get("version", "unknown"))
        description = str(bm.get("description", ""))

        raw_cases = raw.get("cases", [])
        if not isinstance(raw_cases, list):
            raise ValueError("manifest.cases must be a list")

        cases: list[GroundTruthCase] = []
        for i, item in enumerate(raw_cases):
            cases.append(self._parse_case(item, benchmark_id, i))

        return GroundTruthBenchmark(
            benchmark_id=benchmark_id,
            version=version,
            description=description,
            cases=tuple(cases),
        )

    @staticmethod
    def _parse_case(item: dict, benchmark_id: str, index: int) -> GroundTruthCase:
        if not isinstance(item, dict):
            raise ValueError(f"Case at index {index} must be a mapping")

        case_id = str(item.get("id", "")).strip()
        if not case_id:
            raise ValueError(f"Case at index {index}: 'id' is required")

        raw_file = item.get("file")
        if not raw_file:
            raise ValueError(f"Case '{case_id}': 'file' is required")

        raw_expected = str(item.get("expected", "")).upper().strip()
        if not raw_expected:
            raise ValueError(f"Case '{case_id}': 'expected' is required")
        try:
            expected = GroundTruthExpectation(raw_expected)
        except ValueError:
            valid = [e.value for e in GroundTruthExpectation]
            raise ValueError(f"Case '{case_id}': invalid 'expected' value '{raw_expected}'. Must be one of {valid}")

        description = str(item.get("description", "")).strip()
        if not description:
            raise ValueError(f"Case '{case_id}': 'description' is required")

        raw_line = item.get("line")
        line: int | None = None
        if raw_line is not None:
            try:
                line = int(raw_line)
            except (ValueError, TypeError):
                raise ValueError(f"Case '{case_id}': 'line' must be an integer, got '{raw_line}'")

        rule_id = item.get("rule_id") or None
        cwe = item.get("cwe") or None
        language = item.get("language") or None
        category = item.get("category") or None
        rationale = item.get("rationale") or None
        source_reference = item.get("source_reference") or None

        raw_sev = item.get("severity")
        severity: Severity | None = None
        if raw_sev:
            try:
                severity = Severity(str(raw_sev).upper())
            except ValueError:
                pass  # Unknown severity — ignore, don't fail manifest load

        return GroundTruthCase(
            case_id=case_id,
            benchmark=benchmark_id,
            file=str(raw_file),
            line=line,
            rule_id=rule_id,
            expected=expected,
            description=description,
            cwe=cwe,
            language=language,
            severity=severity,
            category=category,
            rationale=rationale,
            source_reference=source_reference,
        )
