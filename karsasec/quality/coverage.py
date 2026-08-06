"""Rule Coverage Analyzer module for evaluating security coverage across languages, CWEs, and OWASP categories."""

from __future__ import annotations

from typing import Any

from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory


class CoverageAnalyzer:
    """Analyzes and compiles comprehensive rule coverage statistics for the platform."""

    def __init__(self) -> None:
        self.loader = YAMLRuleLoader()
        self.rules_dir = get_default_rules_directory()

    def analyze(self) -> dict[str, Any]:
        """Scans all rules and returns detailed metric breakdowns."""
        rules = self.loader.load_directory(self.rules_dir)

        language_map: dict[str, int] = {}
        cwe_map: dict[str, int] = {}
        owasp_map: dict[str, int] = {}
        severity_map: dict[str, int] = {}
        framework_map: dict[str, int] = {}

        for r in rules:
            # Languages
            for lang in r.target.languages:
                lang_str = getattr(lang, "value", str(lang))
                language_map[lang_str] = language_map.get(lang_str, 0) + 1

            # CWE
            if r.metadata.cwe:
                cwe_map[r.metadata.cwe] = cwe_map.get(r.metadata.cwe, 0) + 1

            # OWASP
            if r.metadata.owasp:
                owasp_map[r.metadata.owasp] = owasp_map.get(r.metadata.owasp, 0) + 1

            # Severity
            sev_str = getattr(r.output.severity, "value", str(r.output.severity))
            severity_map[sev_str] = severity_map.get(sev_str, 0) + 1

            # Framework
            tags = r.metadata.tags or []
            for tag in tags:
                if tag.lower() in [
                    "flask",
                    "django",
                    "express",
                    "nextjs",
                    "nestjs",
                    "fastify",
                    "laravel",
                    "wordpress",
                    "symfony",
                    "gin",
                    "echo",
                    "fiber",
                    "axum",
                    "actix",
                    "aspnet",
                ]:
                    framework_map[tag.lower()] = framework_map.get(tag.lower(), 0) + 1

        return {
            "total_rules": len(rules),
            "languages": language_map,
            "cwes": cwe_map,
            "owasp": owasp_map,
            "severities": severity_map,
            "frameworks": framework_map,
        }
