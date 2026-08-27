"""Evidence-Based Framework Detector with Deterministic Scoring Model."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from karsasec.framework.semantic_fact import ConfidenceLevel

logger = logging.getLogger("karsasec.framework.detector")


@dataclass(frozen=True)
class FrameworkEvidence:
    """Individual evidence item supporting a framework detection hypothesis."""

    framework: str
    kind: str  # "import", "decorator", "api", "dependency"
    value: str
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "kind": self.kind,
            "value": self.value,
            "score": self.score,
        }


@dataclass(frozen=True)
class FrameworkDetectionResult:
    """Result of evidence-based framework detection."""

    framework: str
    version: str = "1.0.0"
    language: str = "Generic"
    confidence: float = 1.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    capabilities: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    reason: str = "Framework detected"

    def is_known(self) -> bool:
        return self.framework.upper() != "UNKNOWN" and self.confidence >= 0.30

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "version": self.version,
            "language": self.language,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value if hasattr(self.confidence_level, "value") else str(self.confidence_level),
            "capabilities": list(self.capabilities),
            "evidence": list(self.evidence),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrameworkDetectionResult:
        c_level_raw = data.get("confidence_level", ConfidenceLevel.UNKNOWN)
        c_level = ConfidenceLevel(c_level_raw) if isinstance(c_level_raw, str) else c_level_raw
        return cls(
            framework=data["framework"],
            version=data.get("version", "1.0.0"),
            language=data.get("language", "Generic"),
            confidence=data.get("confidence", 1.0),
            confidence_level=c_level,
            capabilities=tuple(data.get("capabilities", ())),
            evidence=tuple(data.get("evidence", ())),
            reason=data.get("reason", "Framework detected"),
        )


DetectionResult = FrameworkDetectionResult


class FrameworkDetector:
    """Stateless evidence-based Framework Detector."""

    EVIDENCE_WEIGHTS = {
        "import": 0.30,
        "decorator": 0.30,
        "api": 0.25,
        "dependency": 0.15,
    }

    def detect_framework(self, project_path: Path | str) -> FrameworkDetectionResult:
        """Detects framework in a project directory."""
        from pathlib import Path

        path = Path(project_path)
        if not path.exists():
            return FrameworkDetectionResult(
                framework="GENERIC",
                version="1.0.0",
                language="Generic",
                confidence=0.5,
                reason="Path does not exist",
            )

        files_text: list[str] = []
        file_names: list[str] = []
        manifest_names = {"requirements.txt", "package.json", "composer.json", "go.mod", "pipfile", "pyproject.toml"}
        if path.is_file():
            files = [path]
        else:
            files = [f for f in path.rglob("*") if f.is_file() and (f.suffix in (".py", ".js", ".ts", ".php", ".go", ".json", ".txt", ".toml") or f.name.lower() in manifest_names)]

        # VULN-003 Fix: Prioritize dependency manifests and key framework files first
        manifest_files = [f for f in files if f.name.lower() in manifest_names]
        other_files = [f for f in files if f.name.lower() not in manifest_names]

        # Process manifests first, followed by source files
        sorted_files = manifest_files + other_files

        for f in sorted_files:
            file_names.append(f.name.lower())
            try:
                files_text.append(f.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass

        combined_text = "\n".join(files_text)
        import re

        if re.search(r'\bfrom\s+flask\s+import\b|\bimport\s+flask\b|\bflask\b', combined_text, re.I):
            return FrameworkDetectionResult(framework="FLASK", language="Python", confidence=0.95, evidence=("flask import found",), reason="Flask import detected")
        elif re.search(r'\bfrom\s+fastapi\s+import\b|\bimport\s+fastapi\b|\bfastapi\b', combined_text, re.I):
            return FrameworkDetectionResult(framework="FASTAPI", language="Python", confidence=0.95, evidence=("fastapi import found",), reason="FastAPI import detected")
        elif re.search(r'\bfrom\s+django\s+import\b|\bimport\s+django\b|\bdjango\b', combined_text, re.I) or "urls.py" in file_names:
            return FrameworkDetectionResult(framework="DJANGO", language="Python", confidence=0.95, evidence=("django imports/urls.py found",), reason="Django framework detected")
        elif re.search(r'\brequire\(["\']express["\']\)|["\']express["\']|\bexpress\b', combined_text, re.I) or "app.js" in file_names:
            return FrameworkDetectionResult(framework="EXPRESS", language="JavaScript", confidence=0.95, evidence=("express require/app.js found",), reason="Express framework detected")
        elif re.search(r'\bnext/router\b|["\']next["\']|\bnext\b', combined_text, re.I) or "route.ts" in file_names:
            return FrameworkDetectionResult(framework="NEXTJS", language="JavaScript", confidence=0.95, evidence=("nextjs route found",), reason="NextJS framework detected")
        elif re.search(r'\billuminate\\support\b|["\']laravel/framework["\']|\blaravel\b', combined_text, re.I) or "web.php" in file_names:
            return FrameworkDetectionResult(framework="LARAVEL", language="PHP", confidence=0.95, evidence=("laravel route web.php found",), reason="Laravel framework detected")
        elif re.search(r'\bgithub\.com/gin-gonic/gin\b|\bgin\b', combined_text, re.I) or "main.go" in file_names:
            return FrameworkDetectionResult(framework="GIN", language="Go", confidence=0.95, evidence=("gin framework found",), reason="Gin framework detected")

        return FrameworkDetectionResult(framework="GENERIC", language="Generic", confidence=0.5, reason="No specific framework detected")

    def detect(self, project_path: Path | str, file_nodes: list[Any] | None = None) -> list[Any]:
        """Detects frameworks returning list of DetectorResult models for FrameworkPass."""
        from karsasec.framework.models import DetectorResult as ModelDetectorResult, FrameworkType

        fw_res = self.detect_framework(project_path)
        try:
            fw_type = FrameworkType(fw_res.framework)
        except ValueError:
            fw_type = FrameworkType.GENERIC

        det = ModelDetectorResult(
            framework=fw_type,
            confidence=fw_res.confidence,
            reason=fw_res.reason,
            evidence=fw_res.evidence,
        )
        return [det]

    FRAMEWORK_PATTERNS = {
        "FLASK": {
            "imports": ("flask", "flask.views", "flask_restful"),
            "decorators": ("app.route", "blueprint.route", "bp.route"),
            "apis": ("Flask", "Blueprint", "request.args", "request.form"),
        },
        "FASTAPI": {
            "imports": ("fastapi", "starlette"),
            "decorators": ("app.get", "app.post", "router.get", "router.post"),
            "apis": ("FastAPI", "APIRouter", "Header", "Query", "Body"),
        },
        "EXPRESS": {
            "imports": ("express",),
            "decorators": (),
            "apis": ("express()", "app.get", "app.post", "router.get", "app.use", "req.query", "req.body"),
        },

        "DJANGO": {
            "imports": ("django", "django.urls", "django.http"),
            "decorators": ("require_http_methods", "login_required"),
            "apis": ("HttpResponse", "JsonResponse", "request.GET", "request.POST"),
        },
    }

    def detect_from_ast(
        self,
        ast_nodes: list[Any],
        file_path: str = "",
        dependencies: list[str] | None = None,
    ) -> DetectionResult:
        """Detects framework identity deterministically based on AST nodes and explicit evidence scoring."""
        evidence_by_fw: dict[str, list[FrameworkEvidence]] = {}

        # 1. Dependency Evidence
        if dependencies:
            for dep in sorted(dependencies):
                dep_l = dep.lower()
                for fw, rules in self.FRAMEWORK_PATTERNS.items():
                    if any(imp in dep_l for imp in rules["imports"]):
                        ev = FrameworkEvidence(
                            framework=fw,
                            kind="dependency",
                            value=dep,
                            score=self.EVIDENCE_WEIGHTS["dependency"],
                        )
                        evidence_by_fw.setdefault(fw, []).append(ev)

        # 2. AST Inspection (Imports, Decorators, APIs)
        for node in ast_nodes:
            code_snippet = ""
            if getattr(node, "attributes", None):
                code_snippet = str(node.attributes.get("code", "") or node.attributes.get("name", "") or "")
            if not code_snippet:
                code_snippet = str(getattr(node, "name", "") or getattr(node, "label", "") or "")

            node_type = str(getattr(node, "node_type", "") or getattr(node, "label", "")).lower()


            for fw, rules in self.FRAMEWORK_PATTERNS.items():
                # Import check
                if "import" in node_type or "use" in node_type:
                    for imp in rules["imports"]:
                        if imp in code_snippet.lower():
                            ev = FrameworkEvidence(
                                framework=fw,
                                kind="import",
                                value=code_snippet[:100],
                                score=self.EVIDENCE_WEIGHTS["import"],
                            )
                            evidence_by_fw.setdefault(fw, []).append(ev)

                # Decorator check
                for dec in rules["decorators"]:
                    if dec in code_snippet:
                        ev = FrameworkEvidence(
                            framework=fw,
                            kind="decorator",
                            value=code_snippet[:100],
                            score=self.EVIDENCE_WEIGHTS["decorator"],
                        )
                        evidence_by_fw.setdefault(fw, []).append(ev)

                # API check
                for api in rules["apis"]:
                    if api in code_snippet:
                        ev = FrameworkEvidence(
                            framework=fw,
                            kind="api",
                            value=code_snippet[:100],
                            score=self.EVIDENCE_WEIGHTS["api"],
                        )
                        evidence_by_fw.setdefault(fw, []).append(ev)

        # Aggregate scores deterministically
        scored_frameworks: list[tuple[str, float, list[FrameworkEvidence]]] = []
        for fw, ev_list in sorted(evidence_by_fw.items()):
            # Deduplicate evidence by (kind, value)
            seen = set()
            unique_ev: list[FrameworkEvidence] = []
            total_score = 0.0
            for ev in ev_list:
                key = (ev.kind, ev.value)
                if key not in seen:
                    seen.add(key)
                    unique_ev.append(ev)
                    total_score += ev.score

            final_score = min(1.0, round(total_score, 4))
            scored_frameworks.append((fw, final_score, unique_ev))

        if not scored_frameworks:
            return DetectionResult(
                framework="UNKNOWN",
                confidence=0.0,
                confidence_level=ConfidenceLevel.UNKNOWN,
                evidence=(),
            )

        # Sort frameworks by score descending, then framework name ascending
        scored_frameworks.sort(key=lambda x: (-x[1], x[0]))
        top_fw, top_score, top_ev = scored_frameworks[0]

        # Ambiguous check: If top score is too low or tie between top two
        if top_score < 0.30:
            return DetectionResult(
                framework="UNKNOWN",
                confidence=top_score,
                confidence_level=ConfidenceLevel.UNKNOWN,
                evidence=tuple(top_ev),
            )

        if len(scored_frameworks) > 1 and scored_frameworks[1][1] == top_score:
            logger.warning("Tie in framework detection between %s and %s", top_fw, scored_frameworks[1][0])
            return DetectionResult(
                framework="UNKNOWN",
                confidence=top_score,
                confidence_level=ConfidenceLevel.UNKNOWN,
                evidence=(),
            )

        c_level = ConfidenceLevel.HIGH if top_score >= 0.70 else ConfidenceLevel.MEDIUM
        return DetectionResult(
            framework=top_fw,
            confidence=top_score,
            confidence_level=c_level,
            evidence=tuple(top_ev),
        )
