"""Unit tests for execute_business_test_suite and integration with RemediationApplicationAgent."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import shutil
from unittest.mock import MagicMock, patch

from karsasec.ai.remediation.verification import execute_business_test_suite, VerificationStatus
from karsasec.ai.remediation.application_agent import RemediationApplicationAgent
from karsasec.ai.remediation.models import PatchProposal, PatchHunk, PatchValidationStatus
from karsasec.ai.remediation.approval import PatchApprovalToken, ApprovalStatus
from karsasec.core.finding.model import Finding
from karsasec.core.finding.evidence import Evidence
from karsasec.graph.dataflow.security_verdict import SecurityVerdict, VerdictStatus, VerdictConfidence


def test_go_project_test_runner():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "go.mod").write_text("module test", encoding="utf-8")

        with patch("subprocess.run") as mock_run:
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = "ok"
            mock_res.stderr = ""
            mock_run.return_value = mock_res

            success, output = execute_business_test_suite(tmp_path)
            assert success is True
            assert "ok" in output
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "go" in args
            assert "test" in args


def test_node_project_test_runner():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        pkg_data = {"name": "test", "scripts": {"test": "jest"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg_data), encoding="utf-8")

        with patch("subprocess.run") as mock_run:
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = "tests passed"
            mock_res.stderr = ""
            mock_run.return_value = mock_res

            success, output = execute_business_test_suite(tmp_path)
            assert success is True
            assert "tests passed" in output
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "npm" in args
            assert "test" in args


def test_python_pytest_test_runner():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "pytest.ini").write_text("[pytest]", encoding="utf-8")

        with patch("subprocess.run") as mock_run:
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = "pytest passed"
            mock_res.stderr = ""
            mock_run.return_value = mock_res

            success, output = execute_business_test_suite(tmp_path)
            assert success is True
            assert "pytest passed" in output
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "pytest" in args


def test_python_unittest_fallback():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")

        # Mock first run (pytest) to raise FileNotFoundError (not installed)
        # Mock second run (unittest) to succeed
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                FileNotFoundError("pytest not found"),
                MagicMock(returncode=0, stdout="unittest passed", stderr=""),
            ]

            success, output = execute_business_test_suite(tmp_path)
            assert success is True
            assert "unittest passed" in output
            assert mock_run.call_count == 2
            first_args = mock_run.call_args_list[0][0][0]
            second_args = mock_run.call_args_list[1][0][0]
            assert "pytest" in first_args
            assert "unittest" in second_args


def test_no_test_suite_detected():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        success, output = execute_business_test_suite(tmp_path)
        assert success is True
        assert "No native test suite detected" in output


def test_business_test_regression_triggers_rollback():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        repo_path = tmp_path.resolve()

        # Write test target file
        target_rel = "app.py"
        target_abs = repo_path / target_rel
        target_abs.write_text("x = 1\n", encoding="utf-8")

        # Create dummy python pytest config to trigger pytest execution
        (repo_path / "pytest.ini").write_text("[pytest]", encoding="utf-8")

        # Mock proposal & token
        hunk = PatchHunk(
            file_path=target_rel,
            original_text="x = 1\n",
            proposed_text="x = 2\n",
            start_line=1,
            end_line=1,
            context="main",
            evidence_reference="app.py:1",
        )
        diff = "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-x = 1\n+x = 2\n"
        fp = PatchProposal.compute_fingerprint("F-101", (target_rel,), diff, PatchValidationStatus.VALID)
        
        proposal = PatchProposal(
            proposal_id="prop_01",
            finding_id="F-101",
            target_files=(target_rel,),
            hunks=(hunk,),
            unified_diff=diff,
            rationale="Fix XSS",
            root_cause_reference="RCA-101",
            evidence_references=("app.py:1",),
            expected_effect="Safe",
            risk_level="LOW",
            assumptions=(),
            validation_status=PatchValidationStatus.VALID,
            proposal_fingerprint=fp,
        )

        from karsasec.ai.remediation.snapshot import SourceSnapshot
        snap = SourceSnapshot.capture(repo_path, (target_rel,))

        token = PatchApprovalToken.create(
            finding_id="F-101",
            proposal_fingerprint=fp,
            source_snapshot_hash=snap.aggregate_hash,
            target_files=(target_rel,),
            repository_identity=str(repo_path),
            approved_by="reviewer",
        )

        finding = Finding(
            finding_id="F-101",
            rule_id="CWE-79-XSS",
            fingerprint="mock_fp",
            title="XSS",
            severity="HIGH",
            confidence="HIGH",
            cwe_id="CWE-79",
            owasp="A03:2021",
            file_path=Path(target_rel),
            evidence=Evidence(snippet="x = 1", line=1, column=1),
            description="desc",
            remediation="rem",
            verdict=SecurityVerdict.create(
                status=VerdictStatus.VULNERABLE,
                confidence=VerdictConfidence.HIGH,
                rule_id="CWE-79-XSS",
                sink_id="sink_01",
                sink_category="HTML_OUTPUT",
                file_path=target_rel,
                function_name="main",
                line_number=1,
                variable_version="x",
                call_context="GLOBAL",
                branch_polarity="UNKNOWN",
                reason_codes=(),
                provenance_path=(),
            ),
        )

        # Mock scanning callback (returns no findings, i.e. vulnerability fixed)
        rescan_callback = MagicMock(return_value=())

        agent = RemediationApplicationAgent(repository_root=repo_path)

        # Mock execute_business_test_suite to fail (regression detected)
        with patch("subprocess.run") as mock_run:
            mock_res = MagicMock()
            mock_res.returncode = 1
            mock_res.stdout = ""
            mock_res.stderr = "FAILED: test_regression"
            mock_run.return_value = mock_res

            app_res, ver_res, used_token = agent.execute_transaction(
                proposal=proposal,
                token=token,
                finding=finding,
                rescan_callback=rescan_callback,
            )

            # Verification should fail and prompt atomic rollback
            assert ver_res is not None
            assert ver_res.status == VerificationStatus.ROLLBACK_REQUIRED
            assert "Business test suite regression detected" in ver_res.details
            assert app_res.status == "ROLLED_BACK"

            # Check that file content was restored
            assert target_abs.read_text(encoding="utf-8") == "x = 1\n"
