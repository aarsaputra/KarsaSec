"""FindingFactory module for computing fingerprints and instantiating immutable Finding models."""

import hashlib
import uuid
from pathlib import Path
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.enums import Confidence, OWASPCategory, Severity
from karsasec.rules.matcher.result import RuleMatch
from karsasec.rules.schema import Rule

class FindingFactory:
    """Computes deterministic SHA-256 fingerprints and builds immutable Finding instances."""

    def compute_fingerprint(self, rule_id: str, file_path: Path, line: int, snippet: str) -> str:
        """Computes a deterministic SHA-256 fingerprint for finding deduplication."""
        norm_path = str(file_path).replace("\\", "/")
        snippet_hash = hashlib.sha256(snippet.encode("utf-8", errors="ignore")).hexdigest()[:16]
        raw_key = f"{norm_path}:{rule_id}:{line}:{snippet_hash}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:32]

    def create_finding(
        self,
        rule: Rule,
        file_path: Path,
        evidence: Evidence,
        match_result: RuleMatch,
    ) -> Finding:
        """Assembles an immutable Finding instance from Rule evaluation metadata."""
        finding_id = f"finding-{uuid.uuid4().hex[:8]}"
        fingerprint = self.compute_fingerprint(rule.id, file_path, evidence.line, evidence.snippet)

        # Resolve severity & confidence
        raw_severity = rule.output.severity if hasattr(rule.output, "severity") else Severity.HIGH
        raw_conf = getattr(rule.output, "confidence", "CONFIDENT")
        base_confidence = Confidence[raw_conf.upper()] if isinstance(raw_conf, str) and raw_conf.upper() in Confidence.__members__ else Confidence.CONFIDENT

        # Apply TaintVerifier to adjust severity & confidence based on source taint & static guards
        from karsasec.graph.taint_verifier import taint_verifier
        context_text = "\n".join(evidence.context_lines) if evidence.context_lines else evidence.snippet
        rule_lang = getattr(rule.match, "language", "Generic")
        if hasattr(rule_lang, "value"):
            rule_lang = rule_lang.value
        elif hasattr(rule_lang, "name"):
            rule_lang = rule_lang.name

        taint_res = taint_verifier.verify_sink(
            node=ASTNode(node_id=match_result.node_id, node_type="sink", start=None, end=None),
            snippet=evidence.snippet,
            context_text=context_text,
            language=str(rule_lang),
            base_severity=raw_severity,
            base_confidence=base_confidence,
        )

        severity = taint_res.adjusted_severity
        confidence = taint_res.adjusted_confidence

        cwe_id = getattr(rule.metadata, "cwe", "CWE-20")
        owasp_raw = getattr(rule.metadata, "owasp", "A03:2021-Injection")
        owasp = owasp_raw.value if isinstance(owasp_raw, OWASPCategory) else str(owasp_raw)

        title = getattr(rule.metadata, "name", rule.id)
        description = getattr(rule.output, "message", title)
        remediation = getattr(rule.output, "remediation", "Review and sanitize input.")

        return Finding(
            finding_id=finding_id,
            rule_id=rule.id,
            fingerprint=fingerprint,
            title=title,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_id,
            owasp=owasp,
            file_path=file_path,
            evidence=evidence,
            description=description,
            remediation=remediation,
            rule_version=str(getattr(rule.metadata, "version", "1.0")),
        )

# Global default factory instance
finding_factory = FindingFactory()
