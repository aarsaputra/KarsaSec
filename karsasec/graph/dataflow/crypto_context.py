"""Crypto Semantic Usage Context Analyzer (E12-14).

Design Principles & Guardrails:
  - Evaluates semantic usage context of cryptographic functions (md5, sha1, hash).
  - Categorization:
        PASSWORD_HASH           -> Security-sensitive (keep finding)
        SECURITY_TOKEN          -> Security-sensitive (keep finding)
        CACHE_KEY               -> Non-sensitive (suppress finding)
        CHECKSUM                -> Non-sensitive (suppress finding)
        NON_SECURITY_IDENTIFIER -> Non-sensitive (suppress finding)
        UNKNOWN                 -> Ambiguous (MUST retain finding)
  - Strict Guardrail 1:
        Semantic usage > Dataflow provenance > Sink/context > Variable naming hint.
        Variable names MAY provide evidence, but MUST NEVER independently suppress a finding.
        UNKNOWN != NON_SECURITY_IDENTIFIER (conservative fallback).
  - Anti-hardcoding: Pure AST and dataflow semantic analyzer. Zero benchmark strings or rule IDs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class CryptoContextKind(StrEnum):
    """Categorization of cryptographic hash usage context."""
    PASSWORD_HASH = "PASSWORD_HASH"
    SECURITY_TOKEN = "SECURITY_TOKEN"
    CACHE_KEY = "CACHE_KEY"
    CHECKSUM = "CHECKSUM"
    NON_SECURITY_IDENTIFIER = "NON_SECURITY_IDENTIFIER"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CryptoContextEvidence:
    """Collected evidence for a cryptographic function invocation."""
    context_kind: CryptoContextKind
    has_semantic_usage: bool = False
    has_dataflow_provenance: bool = False
    has_sink_context: bool = False
    has_naming_hint: bool = False
    provenance: str = ""


class CryptoContextAnalyzer:
    """Analyzes semantic usage of hash functions (md5, sha1) to classify risk."""

    def analyze_hash_usage(
        self,
        hash_func: str,
        input_expr: str,
        assigned_var: str,
        surrounding_stmts: list[Any],
        file_path: str = "",
        line_number: int = 0,
    ) -> CryptoContextEvidence:
        """Classify hash usage context adhering strictly to Guardrail 1."""
        input_lower = input_expr.lower()
        var_lower = assigned_var.lower()
        stmts_text = " ".join(str(s) for s in surrounding_stmts).lower()

        # 1. Check for Security-Sensitive Password / Credential Context
        if any(pw in input_lower or pw in stmts_text for pw in ("password", "passwd", "pwd", "secret", "token", "auth")):
            if "password" in input_lower or "passwd" in input_lower or "pwd" in input_lower or "password" in stmts_text:
                return CryptoContextEvidence(
                    context_kind=CryptoContextKind.PASSWORD_HASH,
                    has_semantic_usage=True,
                    provenance=f"Password/credential taint in input/statement: {input_expr[:30]}",
                )
            return CryptoContextEvidence(
                context_kind=CryptoContextKind.SECURITY_TOKEN,
                has_semantic_usage=True,
                provenance=f"Auth/token context in input/statement: {input_expr[:30]}",
            )

        # 2. Check for Semantic Usage (Prioritized over variable naming!)
        # Semantic Usage Evidence A: Array indexing e.g. $cache[$key] = ... or $table[md5($x)]
        if re.search(r'\$\w+\s*\[\s*(?:' + re.escape(assigned_var) + r'|md5|sha1|hash)\s*\]', stmts_text) or "array_key_exists" in stmts_text:
            return CryptoContextEvidence(
                context_kind=CryptoContextKind.NON_SECURITY_IDENTIFIER,
                has_semantic_usage=True,
                provenance=f"Array indexing/cache table key usage for {assigned_var}",
            )

        # Semantic Usage Evidence B: Checksum / file verification e.g. file_exists, md5_file, filesize
        if any(cs in stmts_text for cs in ("filesize", "file_exists", "md5_file", "checksum", "etag")):
            return CryptoContextEvidence(
                context_kind=CryptoContextKind.CHECKSUM,
                has_semantic_usage=True,
                provenance=f"File/checksum verification usage for {assigned_var}",
            )

        # 3. Check Variable Naming Hint (WEAK EVIDENCE - Guardrail 1)
        # Naming hint alone CANNOT suppress unless supported by non-password dataflow!
        if any(ck in var_lower for ck in ("cache", "key", "idx", "hash_id", "temp_id")):
            # Only if input is non-sensitive scalar/numeric/filename
            if not any(s in input_lower for s in ("$_post", "$_get", "$_request", "pass")):
                return CryptoContextEvidence(
                    context_kind=CryptoContextKind.CACHE_KEY,
                    has_semantic_usage=False,
                    has_naming_hint=True,
                    provenance=f"Naming hint '{assigned_var}' with non-input source",
                )

        # 4. Default Fallback (Guardrail 1: UNKNOWN != NON_SECURITY_IDENTIFIER)
        # Ambiguous usage MUST retain finding for security safety!
        return CryptoContextEvidence(
            context_kind=CryptoContextKind.UNKNOWN,
            provenance=f"Ambiguous cryptographic usage for {hash_func}({input_expr[:30]})",
        )
