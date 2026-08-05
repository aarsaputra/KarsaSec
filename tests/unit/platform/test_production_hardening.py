"""Unit test suite for KarsaSec Production Hardening & Architecture Freeze (Failure isolation, telemetry, and ADR integrity)."""

from pathlib import Path

from karsasec.runtime.artifact_store import ArtifactStore
from karsasec.runtime.pass_manager import AnalysisPass, PassDescriptor, PassManager


class FailingPass(AnalysisPass):
    def run(self, store: ArtifactStore) -> bool:
        raise RuntimeError("Simulated pass parsing failure in language extension")


class SuccessPass(AnalysisPass):
    def run(self, store: ArtifactStore) -> bool:
        store.put("success_key", "valid_result")
        return True


def test_pass_manager_failure_isolation() -> None:
    """Verify PassManager isolates pass failures so subsequent passes continue uninterrupted."""
    store = ArtifactStore()
    pm = PassManager()

    failing_desc = PassDescriptor(name="FailingPass", inputs=[], outputs=[])
    success_desc = PassDescriptor(name="SuccessPass", inputs=[], outputs=["success_key"])

    pm.register_pass(FailingPass(failing_desc))
    pm.register_pass(SuccessPass(success_desc))

    results = pm.run_passes(store)

    # Failing pass returns False, but does not crash execution
    assert results["FailingPass"] is False
    assert results["SuccessPass"] is True
    assert store.has("success_key") is True
    assert store.get("success_key") == "valid_result"

    telemetry = pm.get_telemetry()
    assert len(telemetry) == 2
    assert telemetry[0].success is False
    assert "Simulated pass parsing failure" in telemetry[0].error_message
    assert telemetry[1].success is True


def test_architecture_decision_records_existence() -> None:
    """Verify Architecture Decision Records (ADRs) 0001 through 0005 exist and have required structure."""
    repo_root = Path(__file__).resolve().parents[3]
    adr_dir = repo_root / "docs" / "adr"

    for i in range(1, 6):
        adr_file = adr_dir / f"ADR-000{i}-*.md"
        matches = list(adr_dir.glob(f"ADR-000{i}-*.md"))
        assert len(matches) == 1, f"Missing or duplicate ADR-000{i} in {adr_dir}"
        content = matches[0].read_text(encoding="utf-8")
        assert "# ADR-000" in content
        assert "Status:" in content
        assert "Context" in content
        assert "Decision" in content
        assert "Consequences" in content


def test_capability_integration_matrix_existence() -> None:
    """Verify Capability Integration Matrix documentation exists."""
    repo_root = Path(__file__).resolve().parents[3]
    matrix_file = repo_root / "docs" / "architecture" / "CAPABILITY_INTEGRATION_MATRIX.md"
    assert matrix_file.exists() is True
    content = matrix_file.read_text(encoding="utf-8")
    assert "Capability Integration Matrix" in content
    assert "Artifact Ownership" in content
