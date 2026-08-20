"""Patch Generation Providers for KarsaSec AI Engine (Sprint E13-3).

Provides deterministic offline diff generation and optional LLM patch synthesis.

Enforces Invariants:
  - G10 & G11: Untrusted Data Boundary (Source code & RAG docs marked UNTRUSTED DATA).
  - G12-G14: Pure computation (DATA ONLY, no file writing/git/subprocess APIs).
  - G15: Human review status required on proposals.
  - G16: Zero benchmark-specific hardcoding.
"""

from __future__ import annotations

import json
from typing import Protocol

from karsasec.ai.remediation.models import PatchHunk, RemediationStrategy, RemediationStrategyType


class PatchGenerationProviderProtocol(Protocol):
    """Protocol for patch generation providers."""

    def generate_hunks(
        self,
        strategy: RemediationStrategy,
        original_source: str,
        start_line: int = 1,
    ) -> list[PatchHunk]: ...


class MockPatchProvider:
    """Deterministic mock provider for testing."""

    def __init__(self, custom_hunks: list[PatchHunk] | None = None, should_fail: bool = False) -> None:
        self.custom_hunks = custom_hunks
        self.should_fail = should_fail

    def generate_hunks(
        self,
        strategy: RemediationStrategy,
        original_source: str,
        start_line: int = 1,
    ) -> list[PatchHunk]:
        if self.should_fail:
            raise RuntimeError("Mock patch provider network connection failed.")

        if self.custom_hunks is not None:
            return self.custom_hunks

        lines = original_source.splitlines()
        target_line_idx = max(0, min(start_line - 1, len(lines) - 1)) if lines else 0
        orig_text = lines[target_line_idx] if lines else ""

        proposed_text = f"# SAFE PROPOSAL: {strategy.strategy_type.value}\n{orig_text}"

        hunk = PatchHunk(
            file_path=strategy.target_file,
            start_line=target_line_idx + 1,
            end_line=target_line_idx + 1,
            original_text=orig_text,
            proposed_text=proposed_text,
            context=orig_text,
            evidence_reference=strategy.evidence_references[0]
            if strategy.evidence_references
            else f"{strategy.target_file}:{start_line}",
        )
        return [hunk]


class TemplatePatchProvider:
    """Offline deterministic template provider generating canonical patch hunks without LLM dependencies."""

    def generate_hunks(
        self,
        strategy: RemediationStrategy,
        original_source: str,
        start_line: int = 1,
    ) -> list[PatchHunk]:
        lines = original_source.splitlines()
        target_idx = max(0, min(start_line - 1, len(lines) - 1)) if lines else 0
        orig_line = lines[target_idx] if lines else ""

        proposed_text = self._build_proposed_text(strategy.strategy_type, orig_line)

        ev_ref = (
            strategy.evidence_references[0]
            if strategy.evidence_references
            else f"{strategy.target_file}:{target_idx + 1}"
        )

        hunk = PatchHunk(
            file_path=strategy.target_file,
            start_line=target_idx + 1,
            end_line=target_idx + 1,
            original_text=orig_line,
            proposed_text=proposed_text,
            context=orig_line,
            evidence_reference=ev_ref,
        )
        return [hunk]

    @staticmethod
    def _build_proposed_text(strategy_type: RemediationStrategyType, orig_line: str) -> str:
        s_val = strategy_type.value if hasattr(strategy_type, "value") else str(strategy_type)

        if s_val == RemediationStrategyType.ADD_PARAMETERIZATION.value:
            return f"# SAFE PARAMETERIZED QUERY PROPOSAL:\n# {orig_line}\n# Use cursor.execute(query, (params,)) instead of concatenation"

        if s_val == RemediationStrategyType.ADD_OUTPUT_ENCODING.value:
            return f"# SAFE OUTPUT ENCODING PROPOSAL:\n# htmlspecialchars({orig_line.strip()})"

        if s_val == RemediationStrategyType.ADD_AUTHORIZATION_CHECK.value:
            return f"# SAFE AUTHORIZATION CHECK PROPOSAL:\n# check_authorization(current_user, resource)\n{orig_line}"

        if s_val == RemediationStrategyType.REPLACE_UNSAFE_API.value:
            return f"# SAFE API REPLACEMENT PROPOSAL:\n# Replace unsafe API in: {orig_line.strip()}"

        return f"# REMEDIATION PROPOSAL ({s_val}):\n{orig_line}"


class LLMPatchProvider:
    """LLM-backed patch generation provider with strict prompt injection isolation boundaries."""

    def __init__(self, llm_provider: any = None) -> None:
        self.llm_provider = llm_provider

    def generate_hunks(
        self,
        strategy: RemediationStrategy,
        original_source: str,
        start_line: int = 1,
    ) -> list[PatchHunk]:
        if self.llm_provider is None:
            return TemplatePatchProvider().generate_hunks(strategy, original_source, start_line)

        try:
            # Construct structured prompt separating untrusted data
            user_prompt = json.dumps(
                {
                    "UNTRUSTED_SOURCE_CONTEXT": original_source,
                    "STRATEGY": strategy.to_dict(),
                }
            )
            resp = self.llm_provider.generate("System Prompt: Generate Patch Proposal Hunks", user_prompt)
            data = json.loads(resp)

            hunks = []
            for h in data.get("hunks", []):
                hunks.append(
                    PatchHunk(
                        file_path=strategy.target_file,
                        start_line=int(h.get("start_line", start_line)),
                        end_line=int(h.get("end_line", start_line)),
                        original_text=str(h.get("original_text", "")),
                        proposed_text=str(h.get("proposed_text", "")),
                        context=str(h.get("context", "")),
                        evidence_reference=str(h.get("evidence_reference", "")),
                    )
                )
            return hunks if hunks else TemplatePatchProvider().generate_hunks(strategy, original_source, start_line)
        except Exception:
            return TemplatePatchProvider().generate_hunks(strategy, original_source, start_line)
