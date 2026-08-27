"""Unit tests for KarsaSec CLI patch apply command (Sprint Phase 6)."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
from typer.testing import CliRunner

from karsasec.cli.main import app
from karsasec.ai.remediation.applier import ApplicationResult, ApplicationStatus
from karsasec.ai.remediation.verification import VerificationResult, VerificationStatus, VerificationContract

runner = CliRunner()


def test_patch_apply_command_success():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        token_file = tmp_path / "token.json"
        proposal_file = tmp_path / "proposal.json"

        from karsasec.ai.remediation.approval import PatchApprovalToken

        token_obj = PatchApprovalToken.create(
            finding_id="F-101",
            proposal_fingerprint="mock_fp",
            source_snapshot_hash="snap_hash",
            target_files=("app.py",),
            repository_identity=str(tmp_path),
            approved_by="reviewer",
        )
        token_data = token_obj.to_dict()
        token_file.write_text(json.dumps(token_data), encoding="utf-8")

        prop_data = {
            "proposal_id": "prop_123",
            "finding_id": "F-101",
            "target_files": ["app.py"],
            "hunks": [],
            "proposal_fingerprint": "mock_fp"
        }
        proposal_file.write_text(json.dumps(prop_data), encoding="utf-8")

        # Mock scan pipeline & agent transaction
        with patch("karsasec.cli.commands.patch._run_scan_pipeline") as mock_scan, \
             patch("karsasec.cli.commands.patch.RemediationApplicationAgent.execute_transaction") as mock_tx, \
             patch("karsasec.cli.commands.patch.GitRepo") as mock_git_class:

            # Mock scan results (returns 1 finding)
            mock_finding = MagicMock()
            mock_finding.finding_id = "F-101"
            mock_scan.return_value = ([mock_finding], None, 0.0)

            # Mock transaction results (successful apply + verified fix)
            app_res = ApplicationResult(
                transaction_id="tx_123",
                finding_id="F-101",
                proposal_fingerprint="mock_fp",
                token_id="tok_123",
                status=ApplicationStatus.APPLIED,
                target_files=("app.py",),
                pre_apply_snapshot_hash="snap_pre",
                post_apply_snapshot_hash="snap_post",
                rollback_status="NOT_NEEDED",
                failure_reason=None
            )
            contract = VerificationContract(
                finding_id="F-101",
                rule_id="CWE-79",
                cwe_id="CWE-79",
                sink_category="HTML_OUTPUT",
                file_path="app.py",
                line_number=1,
                affected_symbol="x",
                evidence_fingerprint="mock_fp"
            )
            ver_res = VerificationResult(
                verification_id="ver_123",
                finding_id="F-101",
                pre_apply_verdict_status="VULNERABLE",
                post_apply_verdict_status="SAFE",
                status=VerificationStatus.VERIFIED_FIXED,
                contract=contract,
                matching_findings_count=0,
                details="Fixed"
            )
            # Mock token mark used
            mock_token = MagicMock()
            mock_token.to_dict.return_value = token_data
            mock_tx.return_value = (app_res, ver_res, mock_token)

            # Mock GitRepo methods
            mock_git = MagicMock()
            mock_git.is_git_repo.return_value = True
            mock_git.get_current_branch.return_value = "main"
            mock_git.commit.return_value = True
            mock_git_class.return_value = mock_git

            result = runner.invoke(app, [
                "patch", "apply",
                "--token", str(token_file),
                "--proposal", str(proposal_file),
                "--repo", str(tmp_path),
                "--create-branch"
            ])

            assert result.exit_code == 0
            assert "Created/Switched to isolated branch" in result.output
            assert "Changes successfully committed" in result.output
            mock_git.create_and_checkout_branch.assert_called_once_with("fix/karsasec-finding-F-101")
            mock_git.add.assert_called_once_with(["app.py"])
            mock_git.commit.assert_called_once()


def test_patch_apply_command_failure():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        token_file = tmp_path / "token.json"
        proposal_file = tmp_path / "proposal.json"

        from karsasec.ai.remediation.approval import PatchApprovalToken

        token_obj = PatchApprovalToken.create(
            finding_id="F-101",
            proposal_fingerprint="mock_fp",
            source_snapshot_hash="snap_hash",
            target_files=("app.py",),
            repository_identity=str(tmp_path),
            approved_by="reviewer",
        )
        token_data = token_obj.to_dict()
        token_file.write_text(json.dumps(token_data), encoding="utf-8")

        prop_data = {
            "proposal_id": "prop_123",
            "finding_id": "F-101",
            "target_files": ["app.py"],
            "hunks": [],
            "proposal_fingerprint": "mock_fp"
        }
        proposal_file.write_text(json.dumps(prop_data), encoding="utf-8")

        # Mock scan pipeline & agent transaction
        with patch("karsasec.cli.commands.patch._run_scan_pipeline") as mock_scan, \
             patch("karsasec.cli.commands.patch.RemediationApplicationAgent.execute_transaction") as mock_tx, \
             patch("karsasec.cli.commands.patch.GitRepo") as mock_git_class:

            # Mock scan results
            mock_finding = MagicMock()
            mock_finding.finding_id = "F-101"
            mock_scan.return_value = ([mock_finding], None, 0.0)

            # Mock transaction results (failed apply / rolled back)
            app_res = ApplicationResult(
                transaction_id="tx_123",
                finding_id="F-101",
                proposal_fingerprint="mock_fp",
                token_id="tok_123",
                status=ApplicationStatus.ROLLED_BACK,
                target_files=("app.py",),
                pre_apply_snapshot_hash="snap_pre",
                post_apply_snapshot_hash="snap_post",
                rollback_status="SUCCESS",
                failure_reason="Failed"
            )
            # Mock token mark used
            mock_token = MagicMock()
            mock_token.to_dict.return_value = token_data
            mock_tx.return_value = (app_res, None, mock_token)

            # Mock GitRepo methods
            mock_git = MagicMock()
            mock_git.is_git_repo.return_value = True
            mock_git.get_current_branch.return_value = "main"
            mock_git_class.return_value = mock_git

            result = runner.invoke(app, [
                "patch", "apply",
                "--token", str(token_file),
                "--proposal", str(proposal_file),
                "--repo", str(tmp_path),
                "--create-branch"
            ])

            assert result.exit_code == 0
            assert "Verification failed/rolled back" in result.output
            mock_git.create_and_checkout_branch.assert_called_once_with("fix/karsasec-finding-F-101")
            mock_git.checkout.assert_called_once_with("main")
            mock_git.delete_branch.assert_called_once_with("fix/karsasec-finding-F-101")
