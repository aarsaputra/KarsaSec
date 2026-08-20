import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.rules.enums import Confidence, LanguageEnum, Severity, TargetFormatEnum, UnknownResolution

RULE_ID_PATTERN = re.compile(r"^KS-[A-Z0-9_-]{2,10}-\d{4}$")


class AnalysisEngine(StrEnum):
    """Engine modes for rule analysis."""

    AST = "AST"
    PATTERN = "PATTERN"
    CPG = "CPG"


class AnalysisBehavior(StrEnum):
    """Vulnerability role behavior classification."""

    SOURCE = "SOURCE"
    SINK = "SINK"
    SANITIZER = "SANITIZER"


@dataclass(slots=True)
class TargetSpec:
    """Target language and framework scope specification (Schema v2)."""

    languages: list[LanguageEnum] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisSpec:
    """Analysis engine, behavior, and required capabilities specification (Schema v2)."""

    engine: AnalysisEngine = AnalysisEngine.AST
    behavior: AnalysisBehavior = AnalysisBehavior.SINK
    requires: list[str] = field(default_factory=lambda: ["ast"])


@dataclass(slots=True)
class EvidenceSpec:
    """Evidence requirements and score weight definitions (Schema v2)."""

    require: list[str] = field(default_factory=list)
    score_weights: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class RuleMetadataV2:
    """Metadata describing rule authorship, versioning, references, and tags (Schema v2)."""

    name: str
    author: str
    version: str
    enabled: bool = True
    experimental: bool = False
    cwe: str = "CWE-20"
    owasp: str = "A03:2021-Injection"
    created: str = ""
    updated: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


# Backward Compatible Dataclasses (Schema v1)
@dataclass(slots=True)
class RuleMetadata:
    """Metadata describing rule authorship, versioning, and security classification (Schema v1)."""

    name: str
    author: str
    version: str
    enabled: bool = True
    experimental: bool = False
    cwe: str = "CWE-20"
    owasp: str = "A03:2021-Injection"


@dataclass(slots=True)
class RuleMatch:
    """Target language and AST node selection scope."""

    language: LanguageEnum
    ast_node_types: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RuleCondition:
    """Predicate condition triggering rule matching."""

    symbol_triggers: list[str] = field(default_factory=list)
    pattern: str | None = None
    value_evidence_equals: str | None = None
    value_evidence_not_in: list[str] = field(default_factory=list)
    node_text_not_matches: str | None = None


@dataclass(slots=True)
class RuleOutput:
    """Finding metadata produced when a rule matches."""

    severity: Severity
    confidence: Confidence
    message: str
    remediation: str


# ---------------------------------------------------------------------------
# Rule Contract (E10-3J) — four-section formal quality gate
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class DetectionContract:
    """Describes what makes a rule match semantically dangerous."""

    source_kind: str = ""  # e.g. 'credential_assignment', 'hash_for_password'
    semantic_context: str = ""  # Human description of the vulnerability intent
    unsafe_evidence: tuple[str, ...] = field(default_factory=tuple)  # ValueEvidenceKind values


@dataclass(slots=True, frozen=True)
class SafetyContract:
    """Describes what evidence proves a match is safe (no finding)."""

    safe_evidence: tuple[str, ...] = field(default_factory=tuple)  # ValueEvidenceKind -> suppress
    unknown_evidence: tuple[str, ...] = field(default_factory=tuple)  # ValueEvidenceKind -> suppress
    unknown_resolution: UnknownResolution = UnknownResolution.SUPPRESS


@dataclass(slots=True, frozen=True)
class FixtureContract:
    """Executable code fixtures that validate the rule deterministically.

    positive: snippets that MUST produce a Finding.
    negative: snippets that MUST NOT produce any Finding.
    Both are verified by RuleContractValidator in CI.
    """

    positive: tuple[str, ...] = field(default_factory=tuple)
    negative: tuple[str, ...] = field(default_factory=tuple)


@dataclass(slots=True, frozen=True)
class RegressionContract:
    """Tracks known FP patterns this rule has been explicitly hardened against."""

    fp_regression_ids: tuple[str, ...] = field(default_factory=tuple)
    regression_context: str = ""  # Human description of FP source


@dataclass(slots=True)
class RuleContract:
    """Full formal contract for a security rule — composed of four sub-contracts.

    Rules without a contract section are valid (backward compatible).
    Rules modified after E10-3J MUST carry a contract before merging.
    """

    detection: DetectionContract = field(default_factory=DetectionContract)
    safety: SafetyContract = field(default_factory=SafetyContract)
    fixtures: FixtureContract = field(default_factory=FixtureContract)
    regression: RegressionContract = field(default_factory=RegressionContract)


@dataclass(slots=True)
class Rule:
    """Structured security rule definition supporting both Schema v1 and v2 contracts."""

    id: str
    metadata: RuleMetadataV2
    match: RuleMatch
    condition: RuleCondition
    output: RuleOutput
    target: TargetSpec | None = None
    analysis: AnalysisSpec | None = None
    evidence: EvidenceSpec | None = None
    contract: RuleContract | None = None
    schema_version: str = "2.0"


def validate_rule_dict(raw_data: dict[str, Any]) -> Rule:
    """Validates raw dict structure and converts it into a validated Rule object.

    Supports both Schema v1 and Schema v2 contracts for full backward compatibility.
    """
    if not isinstance(raw_data, dict):
        raise ValueError("Rule data must be a dictionary.")

    rule_sec = raw_data.get("rule")
    if not isinstance(rule_sec, dict):
        raise ValueError("Missing top-level 'rule' dictionary block.")

    rule_id = rule_sec.get("id")
    if not rule_id or not isinstance(rule_id, str):
        raise ValueError("Rule must have a string 'id' field under 'rule'.")

    if not RULE_ID_PATTERN.match(rule_id):
        raise ValueError(f"Invalid Rule ID format '{rule_id}'. Expected format like 'KS-PY-0001' or 'KS-COMMON-0001'.")

    # Validate Metadata
    meta_sec = raw_data.get("metadata", {})
    if not isinstance(meta_sec, dict):
        raise ValueError("Section 'metadata' must be a dictionary.")

    name = meta_sec.get("name", "Unnamed Rule")
    author = meta_sec.get("author", "KarsaSec")
    version = str(meta_sec.get("version", "1.0"))
    enabled = bool(meta_sec.get("enabled", True))
    experimental = bool(meta_sec.get("experimental", False))
    cwe = str(meta_sec.get("cwe", "CWE-20"))
    owasp = str(meta_sec.get("owasp", "A03:2021-Injection"))
    created = str(meta_sec.get("created", ""))
    updated = str(meta_sec.get("updated", ""))
    references = [str(r) for r in meta_sec.get("references", [])]
    tags = [str(t) for t in meta_sec.get("tags", [])]

    metadata_v2 = RuleMetadataV2(
        name=name,
        author=author,
        version=version,
        enabled=enabled,
        experimental=experimental,
        cwe=cwe,
        owasp=owasp,
        created=created,
        updated=updated,
        references=references,
        tags=tags,
    )

    # Validate Target Spec (Schema v2) or Match (Schema v1)
    target_sec = raw_data.get("target")
    match_sec = raw_data.get("match", {})

    target_languages: list[LanguageEnum] = []
    target_frameworks: list[str] = []

    if target_sec and isinstance(target_sec, dict):
        raw_langs = target_sec.get("languages", [])
        for l in raw_langs:
            try:
                target_languages.append(LanguageEnum(str(l)))
            except ValueError:
                pass
        target_frameworks = [str(f) for f in target_sec.get("frameworks", [])]

    # Validate Match section
    if not isinstance(match_sec, dict):
        raise ValueError("Section 'match' must be a dictionary.")

    raw_lang = match_sec.get("language")
    if not raw_lang and target_languages:
        raw_lang = target_languages[0].value
    elif not raw_lang:
        raise ValueError("Section 'match' must specify 'language'.")

    try:
        language = LanguageEnum(raw_lang)
    except ValueError:
        try:
            language = TargetFormatEnum(raw_lang)
        except ValueError:
            valid_langs = [l.value for l in LanguageEnum] + [f.value for f in TargetFormatEnum]
            raise ValueError(f"Invalid language or target format '{raw_lang}'. Supported: {valid_langs}")

    if language not in target_languages:
        target_languages.append(language)

    ast_node_types = match_sec.get("ast_node_types", [])
    if not isinstance(ast_node_types, list):
        raise ValueError("Field 'ast_node_types' in 'match' section must be a list.")

    match_obj = RuleMatch(
        language=language,
        ast_node_types=[str(t).lower() for t in ast_node_types],
    )

    target_obj = TargetSpec(
        languages=target_languages,
        frameworks=target_frameworks,
    )

    # Validate Analysis Spec (Schema v2)
    analysis_sec = raw_data.get("analysis", {})
    engine_val = AnalysisEngine.AST
    behavior_val = AnalysisBehavior.SINK

    if isinstance(analysis_sec, dict):
        raw_engine = str(analysis_sec.get("engine", "AST")).upper()
        if raw_engine in AnalysisEngine.__members__:
            engine_val = AnalysisEngine[raw_engine]

        raw_behavior = str(analysis_sec.get("behavior", "SINK")).upper()
        if raw_behavior in AnalysisBehavior.__members__:
            behavior_val = AnalysisBehavior[raw_behavior]

        reqs = analysis_sec.get("requires", ["ast"])
        if isinstance(reqs, list):
            requires_val = [str(r).lower() for r in reqs]
        else:
            requires_val = ["ast"]

    analysis_obj = AnalysisSpec(
        engine=engine_val,
        behavior=behavior_val,
        requires=requires_val,
    )

    # Validate Condition
    cond_sec = raw_data.get("condition", {})
    if not isinstance(cond_sec, dict):
        raise ValueError("Section 'condition' must be a dictionary.")

    symbol_triggers = cond_sec.get("symbol_triggers", [])
    if not isinstance(symbol_triggers, list):
        raise ValueError("Field 'symbol_triggers' in 'condition' section must be a list.")

    pattern = cond_sec.get("pattern")
    ve_eq = cond_sec.get("value_evidence_equals")
    ve_not_in = cond_sec.get("value_evidence_not_in", [])
    if not isinstance(ve_not_in, list):
        ve_not_in = []
    node_text_not_matches = cond_sec.get("node_text_not_matches")

    condition_obj = RuleCondition(
        symbol_triggers=[str(s) for s in symbol_triggers],
        pattern=str(pattern) if pattern else None,
        value_evidence_equals=str(ve_eq) if ve_eq else None,
        value_evidence_not_in=[str(v) for v in ve_not_in],
        node_text_not_matches=str(node_text_not_matches) if node_text_not_matches else None,
    )

    # Validate Evidence Spec (Schema v2)
    ev_sec = raw_data.get("evidence", {})
    ev_require: list[str] = []
    ev_score_weights: dict[str, int] = {}
    if isinstance(ev_sec, dict):
        ev_require = [str(r) for r in ev_sec.get("require", [])]
        raw_weights = ev_sec.get("score_weights", {})
        if isinstance(raw_weights, dict):
            ev_score_weights = {str(k): int(v) for k, v in raw_weights.items()}

    evidence_obj = EvidenceSpec(
        require=ev_require,
        score_weights=ev_score_weights,
    )

    # Validate Output
    out_sec = raw_data.get("output", {})
    if not isinstance(out_sec, dict):
        raise ValueError("Section 'output' must be a dictionary.")

    raw_sev = out_sec.get("severity")
    if not raw_sev:
        raise ValueError("Section 'output' must specify 'severity'.")
    try:
        severity = Severity(raw_sev.upper())
    except ValueError:
        valid_sevs = [s.value for s in Severity]
        raise ValueError(f"Invalid severity '{raw_sev}'. Supported values: {valid_sevs}")

    raw_conf = out_sec.get("confidence", "CONFIDENT")
    try:
        confidence = Confidence(raw_conf.upper())
    except ValueError:
        valid_confs = [c.value for c in Confidence]
        raise ValueError(f"Invalid confidence '{raw_conf}'. Supported values: {valid_confs}")

    message = out_sec.get("message", "Potential security issue detected.")
    remediation = out_sec.get("remediation", "Review and sanitize input.")

    output_obj = RuleOutput(
        severity=severity,
        confidence=confidence,
        message=message,
        remediation=remediation,
    )

    schema_ver = "2.0" if (target_sec or analysis_sec or ev_sec or created) else "1.0"

    # Parse optional contract section (E10-3J) — fully backward-compatible
    contract_obj: RuleContract | None = None
    contract_sec = raw_data.get("contract")
    if isinstance(contract_sec, dict):
        det = contract_sec.get("detection", {}) or {}
        saf = contract_sec.get("safety", {}) or {}
        fix = contract_sec.get("fixtures", {}) or {}
        reg = contract_sec.get("regression", {}) or {}

        raw_unknown_res = saf.get("unknown_resolution", "SUPPRESS")
        try:
            unknown_res = UnknownResolution(str(raw_unknown_res).upper())
        except ValueError:
            unknown_res = UnknownResolution.SUPPRESS

        contract_obj = RuleContract(
            detection=DetectionContract(
                source_kind=str(det.get("source_kind", "")),
                semantic_context=str(det.get("semantic_context", "")),
                unsafe_evidence=tuple(str(v) for v in det.get("unsafe_evidence", [])),
            ),
            safety=SafetyContract(
                safe_evidence=tuple(str(v) for v in saf.get("safe_evidence", [])),
                unknown_evidence=tuple(str(v) for v in saf.get("unknown_evidence", [])),
                unknown_resolution=unknown_res,
            ),
            fixtures=FixtureContract(
                positive=tuple(str(v) for v in fix.get("positive", [])),
                negative=tuple(str(v) for v in fix.get("negative", [])),
            ),
            regression=RegressionContract(
                fp_regression_ids=tuple(str(v) for v in reg.get("fp_regression_ids", [])),
                regression_context=str(reg.get("regression_context", "")),
            ),
        )

    return Rule(
        id=rule_id,
        metadata=metadata_v2,
        match=match_obj,
        condition=condition_obj,
        output=output_obj,
        target=target_obj,
        analysis=analysis_obj,
        evidence=evidence_obj,
        contract=contract_obj,
        schema_version=schema_ver,
    )
