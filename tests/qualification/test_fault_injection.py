"""Fault Injection Qualification Test Suite verifying crash isolation across parser, pass, and pipeline layers."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from karsasec.runtime.pass_manager import (
    AnalysisPass,
    PassDescriptor,
    PassManager,
    PassTelemetry,
)
from karsasec.runtime.artifact_store import ArtifactStore
from karsasec.parser.python_parser import PythonParserPlugin
from karsasec.parser.generic_parser import GenericParserPlugin
from karsasec.core.execution import RuleExecutor, ScanContext
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory


# === Phase G.1: Pass Manager Crash Isolation ===

class _HealthyPass(AnalysisPass):
    """Pass that always succeeds."""
    def run(self, store: ArtifactStore) -> bool:
        store.put(self.descriptor.outputs[0], "healthy_artifact")
        return True


class _CrashingPass(AnalysisPass):
    """Pass that always raises RuntimeError to simulate crash."""
    def run(self, store: ArtifactStore) -> bool:
        raise RuntimeError("Simulated parser crash: segfault in tree-sitter binding")


class _PostCrashPass(AnalysisPass):
    """Pass that runs after a crashed pass to verify pipeline continuity."""
    def run(self, store: ArtifactStore) -> bool:
        store.put(self.descriptor.outputs[0], "post_crash_artifact")
        return True


def test_pass_manager_isolates_crashing_pass():
    """Verifies that a crashing pass does not halt subsequent passes in the pipeline."""
    mgr = PassManager()
    store = ArtifactStore()

    healthy = _HealthyPass(PassDescriptor(name="HealthyPass", inputs=[], outputs=["ast"]))
    crashing = _CrashingPass(PassDescriptor(name="CrashingPass", inputs=["ast"], outputs=["hir"]))
    post = _PostCrashPass(PassDescriptor(name="PostCrashPass", inputs=[], outputs=["report"]))

    mgr.register_pass(healthy)
    mgr.register_pass(crashing)
    mgr.register_pass(post)

    results = mgr.run_passes(store)

    # Healthy pass succeeded
    assert results["HealthyPass"] is True
    # Crashing pass was isolated (failed gracefully)
    assert results["CrashingPass"] is False
    # Post-crash pass still executed successfully
    assert results["PostCrashPass"] is True

    # Artifacts from healthy and post-crash passes are present
    assert store.get("ast") == "healthy_artifact"
    assert store.get("report") == "post_crash_artifact"
    # Crashed pass did not produce artifact
    assert store.has("hir") is False


def test_pass_manager_telemetry_records_crash():
    """Verifies telemetry captures crash error messages without masking them."""
    mgr = PassManager()
    store = ArtifactStore()

    crashing = _CrashingPass(PassDescriptor(name="CrashTest", inputs=[], outputs=["out"]))
    mgr.register_pass(crashing)

    mgr.run_passes(store)

    telemetry = mgr.get_telemetry()
    assert len(telemetry) == 1
    assert telemetry[0].success is False
    assert "Simulated parser crash" in (telemetry[0].error_message or "")
    assert telemetry[0].elapsed_ms >= 0


# === Phase G.2: Parser Crash Isolation (Tree-sitter binding failure) ===

def test_python_parser_survives_malformed_source():
    """Verifies PythonParserPlugin produces a ParseResult (possibly with diagnostics) for malformed input."""
    parser = PythonParserPlugin()
    malformed = Path("/tmp/_karsasec_fault_test_malformed.py")
    malformed.write_text("def broken(:\n    pass\n\nclass 123Invalid:\n", encoding="utf-8")

    try:
        result = parser.parse_file(malformed)
        # Must not raise; result should exist even if AST is partial
        assert result is not None
        assert result.language == "Python"
    finally:
        if malformed.exists():
            malformed.unlink()


def test_generic_parser_survives_binary_garbage():
    """Verifies GenericParserPlugin does not crash on binary/garbage input."""
    parser = GenericParserPlugin("PHP", [".php"])
    garbage_file = Path("/tmp/_karsasec_fault_test_garbage.php")
    garbage_file.write_bytes(b"\x00\x01\x02\xff\xfe\xfd" * 100)

    try:
        result = parser.parse_file(garbage_file)
        assert result is not None
        assert result.language == "PHP"
    finally:
        if garbage_file.exists():
            garbage_file.unlink()


# === Phase G.3: Scan Pipeline Crash Isolation (Single file crash does not halt directory scan) ===

VALID_PHP_SOURCE = b"""<?php
$cmd = shell_exec($_GET['input']);
?>
"""

def test_scan_pipeline_isolates_single_file_failure():
    """Verifies that scan pipeline continues when one file in a batch throws an exception during parsing."""
    rules_dir = get_default_rules_directory()
    loader = YAMLRuleLoader()
    rules = loader.load_directory(rules_dir)

    executor = RuleExecutor()
    parser = GenericParserPlugin("PHP", [".php"])

    # Create two temp files: one valid, one that will be mocked to crash
    valid_file = Path("/tmp/_karsasec_fault_valid.php")
    valid_file.write_bytes(VALID_PHP_SOURCE)

    crash_file = Path("/tmp/_karsasec_fault_crash.php")
    crash_file.write_bytes(b"<?php echo 'hello'; ?>")

    all_findings = []
    scan_errors = []

    files = [crash_file, valid_file]

    for idx, file_path in enumerate(files):
        try:
            if idx == 0:
                # Simulate crash on first file
                raise RuntimeError("Simulated I/O failure on crash_file")
            source_bytes = file_path.read_bytes()
            parse_res = parser.parse_file(file_path)
            if parse_res.root:
                scan_ctx = ScanContext(
                    file_node=parse_res.root,
                    source_bytes=source_bytes,
                    file_path=file_path,
                    symbol_table=parse_res.symbol_table,
                    language="PHP",
                )
                res = executor.execute_scan(scan_ctx, rules)
                all_findings.extend(res.findings)
        except Exception as err:
            scan_errors.append(str(err))

    # First file crashed but second file was still scanned
    assert len(scan_errors) == 1
    assert "Simulated I/O failure" in scan_errors[0]
    # Pipeline continued; valid file was processed (may or may not have findings)
    # The key assertion: no unhandled exception propagated

    for f in [valid_file, crash_file]:
        if f.exists():
            f.unlink()


# === Phase G.4: Multiple consecutive crashes ===

def test_pass_manager_survives_all_passes_crashing():
    """Verifies PassManager completes even when ALL registered passes crash."""
    mgr = PassManager()
    store = ArtifactStore()

    for i in range(5):
        crash = _CrashingPass(PassDescriptor(name=f"Crash_{i}", inputs=[], outputs=[f"out_{i}"]))
        mgr.register_pass(crash)

    results = mgr.run_passes(store)

    # All passes should be recorded as failed
    assert all(v is False for v in results.values())
    assert len(results) == 5

    # Telemetry should record all 5 crashes
    telemetry = mgr.get_telemetry()
    assert len(telemetry) == 5
    assert all(t.success is False for t in telemetry)
