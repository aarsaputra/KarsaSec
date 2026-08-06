"""Intelligent Target Detector determining TargetKind, TargetFormat, Appropriate Parser, and Detection Confidence."""

from pathlib import Path
from typing import NamedTuple

from karsasec.rules.enums import TargetFormatEnum, TargetKindEnum


class TargetDetectionResult(NamedTuple):
    target_kind: TargetKindEnum
    target_format: TargetFormatEnum
    parser_name: str
    confidence: float = 1.0


class TargetDetector:
    """Detects target kind, format, and confidence score based on filename, path heuristics, and content inspection."""

    def detect(self, file_path: Path, content: str | None = None) -> TargetDetectionResult:
        path = file_path.resolve()
        filename = path.name.lower()
        ext = path.suffix.lower()

        # 1. Dockerfile / Containerfile (High Certainty 1.0)
        if filename == "dockerfile" or filename.startswith("dockerfile.") or ext == ".dockerfile" or filename == "containerfile":
            return TargetDetectionResult(TargetKindEnum.IAC, TargetFormatEnum.DOCKERFILE, "DockerParser", confidence=1.0)

        # 2. GitHub Actions Workflow (Path certainty 0.95, Content 0.85)
        if ".github/workflows" in str(path):
            return TargetDetectionResult(TargetKindEnum.PIPELINE, TargetFormatEnum.GITHUB_ACTIONS, "GitHubActionsParser", confidence=0.95)
        elif ext in (".yaml", ".yml") and content and ("on:" in content and "jobs:" in content):
            return TargetDetectionResult(TargetKindEnum.PIPELINE, TargetFormatEnum.GITHUB_ACTIONS, "GitHubActionsParser", confidence=0.85)

        # 3. Kubernetes Manifest vs Helm
        if ext in (".yaml", ".yml"):
            if content and ("apiVersion:" in content and "kind:" in content):
                return TargetDetectionResult(TargetKindEnum.MANIFEST, TargetFormatEnum.KUBERNETES, "KubernetesParser", confidence=0.90)
            elif "templates/" in str(path) or filename == "values.yaml":
                return TargetDetectionResult(TargetKindEnum.MANIFEST, TargetFormatEnum.HELM, "HelmParser", confidence=0.80)
            else:
                return TargetDetectionResult(TargetKindEnum.MANIFEST, TargetFormatEnum.KUBERNETES, "KubernetesParser", confidence=0.60)

        # 4. Terraform HCL (Certainty 0.95)
        if ext in (".tf", ".tfvars"):
            return TargetDetectionResult(TargetKindEnum.IAC, TargetFormatEnum.TERRAFORM, "TerraformParser", confidence=0.95)

        # 5. Source Code Fallbacks (Extension certainty 0.90)
        if ext == ".py":
            return TargetDetectionResult(TargetKindEnum.SOURCE_CODE, TargetFormatEnum.PYTHON, "PythonParser", confidence=0.90)
        elif ext in (".js", ".jsx"):
            return TargetDetectionResult(TargetKindEnum.SOURCE_CODE, TargetFormatEnum.JAVASCRIPT, "JSParser", confidence=0.90)
        elif ext in (".ts", ".tsx"):
            return TargetDetectionResult(TargetKindEnum.SOURCE_CODE, TargetFormatEnum.TYPESCRIPT, "TSParser", confidence=0.90)
        elif ext == ".go":
            return TargetDetectionResult(TargetKindEnum.SOURCE_CODE, TargetFormatEnum.GO, "GoParser", confidence=0.90)
        elif ext == ".php":
            return TargetDetectionResult(TargetKindEnum.SOURCE_CODE, TargetFormatEnum.PHP, "PHPParser", confidence=0.90)
        elif ext == ".rs":
            return TargetDetectionResult(TargetKindEnum.SOURCE_CODE, TargetFormatEnum.RUST, "RustParser", confidence=0.90)
        elif ext == ".java":
            return TargetDetectionResult(TargetKindEnum.SOURCE_CODE, TargetFormatEnum.JAVA, "JavaParser", confidence=0.90)

        return TargetDetectionResult(TargetKindEnum.CONFIG, TargetFormatEnum.PYTHON, "GenericParser", confidence=0.40)


target_detector = TargetDetector()
