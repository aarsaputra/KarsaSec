"""BaselineManager for loading, saving, and comparing vulnerability baselines with regression detection."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple
from karsasec.core.baseline.models import Baseline, BaselineFinding, ComparisonResult
from karsasec.core.finding.collection import SEVERITY_WEIGHTS
from karsasec.core.finding.model import Finding

class BaselineManager:
    """Manages creation, persistence, and lifecycle comparison of vulnerability baselines."""

    def save_baseline(self, findings: Tuple[Finding, ...], target_file: Path) -> Baseline:
        """Serializes current scan findings into a baseline JSON file."""
        now_iso = datetime.now(timezone.utc).isoformat()
        baseline_findings: Dict[str, BaselineFinding] = {}

        for f in findings:
            bf = BaselineFinding(
                fingerprint=f.fingerprint,
                rule_id=f.rule_id,
                severity=f.severity.name,
                file_path=str(f.file_path).replace("\\", "/"),
                created_at=now_iso,
            )
            baseline_findings[f.fingerprint] = bf

        baseline = Baseline(findings=baseline_findings, created_at=now_iso)

        payload = {
            "scanner_version": baseline.scanner_version,
            "created_at": baseline.created_at,
            "total_findings": len(baseline_findings),
            "findings": [
                {
                    "fingerprint": bf.fingerprint,
                    "rule_id": bf.rule_id,
                    "severity": bf.severity,
                    "file_path": bf.file_path,
                    "created_at": bf.created_at,
                }
                for bf in baseline_findings.values()
            ],
        }

        path = Path(target_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return baseline

    def load_baseline(self, source_file: Path) -> Baseline:
        """Loads a baseline JSON file from disk."""
        path = Path(source_file)
        if not path.exists():
            raise FileNotFoundError(f"Baseline file not found at {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings_dict: Dict[str, BaselineFinding] = {}
        for item in data.get("findings", []):
            bf = BaselineFinding(
                fingerprint=item["fingerprint"],
                rule_id=item["rule_id"],
                severity=item["severity"],
                file_path=item["file_path"],
                created_at=item.get("created_at", ""),
            )
            findings_dict[bf.fingerprint] = bf

        return Baseline(
            findings=findings_dict,
            created_at=data.get("created_at", ""),
            scanner_version=data.get("scanner_version", "0.1.0"),
        )

    def compare(self, current_findings: Tuple[Finding, ...], baseline: Baseline) -> ComparisonResult:
        """Compares current scan findings against an existing baseline.

        Returns:
            ComparisonResult: Categorized into NEW, EXISTING, FIXED, and REGRESSED.
        """
        current_map = {f.fingerprint: f for f in current_findings}
        baseline_map = baseline.findings

        new_findings: List[Finding] = []
        existing_findings: List[Finding] = []
        regressed_findings: List[Finding] = []

        for fp, curr in current_map.items():
            if fp not in baseline_map:
                new_findings.append(curr)
            else:
                base_entry = baseline_map[fp]
                base_sev_weight = SEVERITY_WEIGHTS.get(base_entry.severity, 0) if isinstance(base_entry.severity, str) else 0
                curr_sev_weight = SEVERITY_WEIGHTS.get(curr.severity, 0)

                if curr_sev_weight > base_sev_weight:
                    regressed_findings.append(curr)
                else:
                    existing_findings.append(curr)

        fixed_findings: List[BaselineFinding] = [
            base_entry for fp, base_entry in baseline_map.items() if fp not in current_map
        ]

        return ComparisonResult(
            new_findings=tuple(new_findings),
            existing_findings=tuple(existing_findings),
            fixed_findings=tuple(fixed_findings),
            regressed_findings=tuple(regressed_findings),
        )

# Global default baseline manager instance
baseline_manager = BaselineManager()
