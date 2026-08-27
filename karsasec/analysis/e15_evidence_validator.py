"""Sprint E15 — Evidence Validator Engine.

Validates finding evidence completeness, source/sink consistency,
and absence of contradictions or invalid numeric metrics.
"""

import math
from typing import Any

from karsasec.analysis.e15_models import EvidenceValidation


class EvidenceValidator:
    """Deterministic evidence validation engine."""

    def validate(
        self,
        cluster: Any,
        evidence_graph: Any = None,
        confidence_calibrator: Any = None,
    ) -> EvidenceValidation:
        """Validates evidence graph & cluster integrity."""
        missing: list[str] = []
        contradictions = 0

        if cluster is None:
            return EvidenceValidation(
                evidence_valid=False,
                completeness=0.0,
                contradictions=1,
                missing_dimensions=("cluster",),
                validation_reason="Null cluster object provided",
            )

        # Inspect cluster status
        c_status = str(getattr(cluster, "status", "UNKNOWN")).upper()
        if c_status == "UNKNOWN":
            missing.append("cluster_status_known")

        # Inspect findings inside cluster
        findings = getattr(cluster, "findings", ())
        if not findings:
            missing.append("findings")

        # Validate source and sink facts across findings
        has_source = False
        has_sink = False
        vuln_classes = set()
        sink_categories = set()

        for f in findings:
            v_class = getattr(f, "vulnerability_class", None)
            if v_class:
                vuln_classes.add(v_class)
            s_cat = getattr(f, "sink_category", None)
            if s_cat:
                sink_categories.add(s_cat)

            source_fact = getattr(f, "source_fact", None)
            if source_fact is not None:
                has_source = True
            sink_fact = getattr(f, "sink_fact", None)
            if sink_fact is not None:
                has_sink = True

            # Validate confidence score bounds
            conf = getattr(f, "confidence", 1.0)
            if not isinstance(conf, (int, float)) or math.isnan(conf) or math.isinf(conf) or conf < 0.0 or conf > 1.0:
                contradictions += 1

        if not has_source:
            missing.append("source_fact")
        if not has_sink:
            missing.append("sink_fact")

        # Contradiction check: multiple incompatible vulnerability classes in single cluster
        if len(vuln_classes) > 1:
            contradictions += 1
        if len(sink_categories) > 1:
            contradictions += 1

        # Calculate completeness score [0.0, 1.0]
        total_checks = 4
        passed_checks = 0
        if "cluster_status_known" not in missing:
            passed_checks += 1
        if "findings" not in missing:
            passed_checks += 1
        if "source_fact" not in missing:
            passed_checks += 1
        if "sink_fact" not in missing:
            passed_checks += 1

        completeness = round(passed_checks / total_checks, 4)

        # Fail-closed guard: if missing critical dimensions or contradictions exist
        is_valid = (len(missing) == 0) and (contradictions == 0) and (completeness >= 0.75)

        reason = "Evidence validation passed"
        if not is_valid:
            reasons = []
            if missing:
                reasons.append(f"Missing dimensions: {', '.join(missing)}")
            if contradictions > 0:
                reasons.append(f"Contradictions detected: {contradictions}")
            reason = "; ".join(reasons)

        return EvidenceValidation(
            evidence_valid=is_valid,
            completeness=completeness,
            contradictions=contradictions,
            missing_dimensions=tuple(missing),
            validation_reason=reason,
        )
