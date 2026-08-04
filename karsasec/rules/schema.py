"""Rule Schema data models and validation logic for KarsaSec security rules."""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from karsasec.rules.enums import Confidence, LanguageEnum, OWASPCategory, Severity

RULE_ID_PATTERN = re.compile(r"^KS-[A-Z]{2,4}-\d{4}$")

@dataclass(slots=True)
class RuleMetadata:
    """Metadata describing rule authorship, versioning, and security classification."""
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
    ast_node_types: List[str] = field(default_factory=list)

@dataclass(slots=True)
class RuleCondition:
    """Predicate condition triggering rule matching."""
    symbol_triggers: List[str] = field(default_factory=list)
    pattern: Optional[str] = None

@dataclass(slots=True)
class RuleOutput:
    """Finding metadata produced when a rule matches."""
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str

@dataclass(slots=True)
class Rule:
    """Structured security rule definition."""
    id: str
    metadata: RuleMetadata
    match: RuleMatch
    condition: RuleCondition
    output: RuleOutput

def validate_rule_dict(raw_data: Dict[str, Any]) -> Rule:
    """Validates raw dict structure and converts it into a validated Rule dataclass object."""
    if not isinstance(raw_data, dict):
        raise ValueError("Rule data must be a dictionary.")

    rule_sec = raw_data.get("rule")
    if not isinstance(rule_sec, dict):
        raise ValueError("Missing top-level 'rule' dictionary block.")

    rule_id = rule_sec.get("id")
    if not rule_id or not isinstance(rule_id, str):
        raise ValueError("Rule must have a string 'id' field under 'rule'.")

    if not RULE_ID_PATTERN.match(rule_id):
        raise ValueError(f"Invalid Rule ID format '{rule_id}'. Expected format 'KS-XX-0000' (e.g. KS-PY-0001).")

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

    metadata = RuleMetadata(
        name=name,
        author=author,
        version=version,
        enabled=enabled,
        experimental=experimental,
        cwe=cwe,
        owasp=owasp,
    )

    # Validate Match
    match_sec = raw_data.get("match", {})
    if not isinstance(match_sec, dict):
        raise ValueError("Section 'match' must be a dictionary.")

    raw_lang = match_sec.get("language")
    if not raw_lang:
        raise ValueError("Section 'match' must specify 'language'.")

    try:
        language = LanguageEnum(raw_lang)
    except ValueError:
        valid_langs = [l.value for l in LanguageEnum]
        raise ValueError(f"Invalid language '{raw_lang}'. Supported languages: {valid_langs}")

    ast_node_types = match_sec.get("ast_node_types", [])
    if not isinstance(ast_node_types, list):
        raise ValueError("Field 'ast_node_types' in 'match' section must be a list.")

    match_obj = RuleMatch(
        language=language,
        ast_node_types=[str(t).lower() for t in ast_node_types],
    )

    # Validate Condition
    cond_sec = raw_data.get("condition", {})
    if not isinstance(cond_sec, dict):
        raise ValueError("Section 'condition' must be a dictionary.")

    symbol_triggers = cond_sec.get("symbol_triggers", [])
    if not isinstance(symbol_triggers, list):
        raise ValueError("Field 'symbol_triggers' in 'condition' section must be a list.")

    pattern = cond_sec.get("pattern")
    condition_obj = RuleCondition(
        symbol_triggers=[str(s) for s in symbol_triggers],
        pattern=str(pattern) if pattern else None,
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

    return Rule(
        id=rule_id,
        metadata=metadata,
        match=match_obj,
        condition=condition_obj,
        output=output_obj,
    )
