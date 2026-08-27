"""CLI command module for Git branch creation and patch application (Sprint Phase 6)."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from rich.panel import Panel
from rich.table import Table
import typer

from karsasec.ai.remediation.application_agent import RemediationApplicationAgent
from karsasec.ai.remediation.applier import ApplicationStatus
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.models import PatchProposal
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.ai.remediation.verification import VerificationStatus
from karsasec.cli.commands.scan import _run_scan_pipeline
from karsasec.utils.logging import console

patch_app = typer.Typer(
    name="patch",
    help="Apply and export KarsaSec patches to isolated Git branches.",
    no_args_is_help=True,
)


class GitRepo:
    """Safe wrapper for Git commands inside the target repository."""

    def __init__(self, repo_dir: Path) -> None:
        self.repo_dir = repo_dir

    def run_cmd(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            cwd=self.repo_dir,
            check=True
        )

    def is_git_repo(self) -> bool:
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                capture_output=True,
                text=True,
                cwd=self.repo_dir
            )
            return res.returncode == 0 and res.stdout.strip() == "true"
        except FileNotFoundError:
            return False

    def get_current_branch(self) -> str:
        res = self.run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        return res.stdout.strip()

    def branch_exists(self, branch_name: str) -> bool:
        try:
            self.run_cmd(["git", "show-ref", f"refs/heads/{branch_name}"])
            return True
        except subprocess.CalledProcessError:
            return False

    def create_and_checkout_branch(self, branch_name: str) -> None:
        if self.branch_exists(branch_name):
            self.run_cmd(["git", "checkout", branch_name])
        else:
            self.run_cmd(["git", "checkout", "-b", branch_name])

    def checkout(self, branch_name: str) -> None:
        self.run_cmd(["git", "checkout", branch_name])

    def add(self, files: list[str]) -> None:
        self.run_cmd(["git", "add"] + files)

    def commit(self, message: str) -> bool:
        try:
            self.run_cmd([
                "git",
                "-c", "user.name=KarsaSec Agent",
                "-c", "user.email=agent@karsasec.ai",
                "commit",
                "-m", message
            ])
            return True
        except subprocess.CalledProcessError:
            return False

    def delete_branch(self, branch_name: str) -> None:
        self.run_cmd(["git", "branch", "-D", branch_name])


@patch_app.command("apply")
def apply_command(
    token_file: Path = typer.Option(..., "--token", help="Path to JSON file containing PatchApprovalToken."),
    proposal_file: Path = typer.Option(..., "--proposal", help="Path to JSON file containing PatchProposal."),
    repo: Path = typer.Option(Path("."), "--repo", help="Target repository directory."),
    create_branch: bool = typer.Option(
        False,
        "--create-branch",
        help="Create and apply the patch to a new isolated Git branch (fix/karsasec-finding-<id>)."
    ),
) -> None:
    """Execute controlled patch application, rescan verification, and optional Git branch export."""
    repo_path = repo.resolve()
    if not token_file.exists() or not proposal_file.exists():
        console.print("[bold red]Error:[/bold red] Token file or proposal file missing.")
        sys.exit(1)

    try:
        token_data = json.loads(token_file.read_text(encoding="utf-8"))
        token = PatchApprovalToken.from_dict(token_data)
    except Exception as e:
        console.print(f"[bold red]Error parsing token file:[/bold red] {e}")
        sys.exit(1)

    try:
        prop_data = json.loads(proposal_file.read_text(encoding="utf-8"))
        proposal = PatchProposal(
            proposal_id=prop_data["proposal_id"],
            finding_id=prop_data["finding_id"],
            target_files=tuple(prop_data["target_files"]),
            hunks=(),
            unified_diff=prop_data.get("unified_diff", ""),
            rationale=prop_data.get("rationale", ""),
            root_cause_reference=prop_data.get("root_cause_reference", ""),
            evidence_references=tuple(prop_data.get("evidence_references", [])),
            expected_effect=prop_data.get("expected_effect", ""),
            risk_level=prop_data.get("risk_level", "MEDIUM"),
            assumptions=tuple(prop_data.get("assumptions", [])),
            validation_status=prop_data.get("validation_status", "VALID"),
            proposal_fingerprint=prop_data["proposal_fingerprint"],
        )
    except Exception as e:
        console.print(f"[bold red]Error parsing proposal file:[/bold red] {e}")
        sys.exit(1)

    git = GitRepo(repo_path)
    original_branch = None
    target_branch = None

    if create_branch:
        if not git.is_git_repo():
            console.print("[bold red]Error: Target repository is not a Git repository.[/bold red]")
            sys.exit(1)
        try:
            original_branch = git.get_current_branch()
            target_branch = f"fix/karsasec-finding-{proposal.finding_id}"
            git.create_and_checkout_branch(target_branch)
            console.print(f"[bold green]Created/Switched to isolated branch: {target_branch}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to prepare Git branch: {e}[/bold red]")
            sys.exit(1)

    agent = RemediationApplicationAgent(repository_root=repo_path)

    # SAST scan callback
    def _rescan():
        findings, _, _ = _run_scan_pipeline(target_path=repo_path)
        return findings

    # Finding placeholder
    findings, _, _ = _run_scan_pipeline(target_path=repo_path)
    finding = findings[0] if findings else None

    if not finding:
        console.print("[bold yellow]No findings detected in target repository for initial contract.[/bold yellow]")
        if create_branch and target_branch and original_branch:
            try:
                git.checkout(original_branch)
                git.delete_branch(target_branch)
            except Exception:
                pass
        sys.exit(0)

    try:
        app_res, ver_res, used_token = agent.execute_transaction(
            proposal=proposal,
            token=token,
            finding=finding,
            rescan_callback=_rescan,
        )

        # Save updated used token
        token_file.write_text(json.dumps(used_token.to_dict(), indent=2), encoding="utf-8")

        # Git branch export post-processing
        if create_branch and target_branch:
            if app_res.status == ApplicationStatus.APPLIED and ver_res and ver_res.status == VerificationStatus.VERIFIED_FIXED:
                try:
                    git.add(list(proposal.target_files))
                    committed = git.commit(f"fix(security): KarsaSec patch for finding {proposal.finding_id}")
                    if committed:
                        console.print(f"[bold green]Changes successfully committed to branch {target_branch}.[/bold green]")
                    else:
                        console.print("[bold yellow]No changes to commit or commit failed.[/bold yellow]")
                except Exception as e:
                    console.print(f"[bold red]Failed to commit changes to Git: {e}[/bold red]")
            else:
                # Rollback checkout/branch
                if original_branch:
                    try:
                        git.checkout(original_branch)
                        git.delete_branch(target_branch)
                        console.print(f"[bold yellow]Verification failed/rolled back. Restored branch {original_branch} and deleted {target_branch}.[/bold yellow]")
                    except Exception as e:
                        console.print(f"[bold red]Failed to restore original Git branch: {e}[/bold red]")

        table = Table(title="KarsaSec Patch Application Execution Summary")
        table.add_column("Property", style="bold cyan")
        table.add_column("Value", style="bold white")

        table.add_row("Transaction ID", app_res.transaction_id)
        table.add_row("Application Status", str(app_res.status))
        table.add_row("Post-Apply Verification", str(ver_res.status) if ver_res else "N/A")
        table.add_row("Rollback Status", app_res.rollback_status)

        if app_res.failure_reason:
            table.add_row("Failure Reason", app_res.failure_reason)

        console.print(table)

    except Exception as tx_err:
        console.print(f"[bold red]Transaction execution error: {tx_err}[/bold red]")
        if create_branch and target_branch and original_branch:
            try:
                git.checkout(original_branch)
                git.delete_branch(target_branch)
            except Exception:
                pass
        sys.exit(1)
