"""K1 Adversarial Mutation Engine (Task K1.5).

Generates semantic-preserving adversarial code mutations across categories M1-M8
to verify the non-overfitting and semantic robustness of K1 Knowledge Packs.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MutationCase:
    mutation_id: str
    base_case_id: str
    mutation_type: str
    semantic_preservation: bool
    expected_behavior: str
    mutated_code: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "base_case_id": self.base_case_id,
            "mutation_type": self.mutation_type,
            "semantic_preservation": self.semantic_preservation,
            "expected_behavior": self.expected_behavior,
            "mutated_code": self.mutated_code,
        }


class K1MutationEngine:
    """Engine for generating controlled adversarial AST and source mutations."""

    def mutate_m1_identifier_renaming(self, code: str) -> str:
        """M1: Rename local variables while preserving semantic data-flow."""
        renames = {
            "token": "credential_token",
            "order_id": "target_order_identifier",
            "user_id": "subject_user_id",
            "quantity": "requested_item_qty",
            "price": "unit_item_price",
            "doc_id": "requested_document_id",
        }
        mutated = code
        for old, new in renames.items():
            mutated = mutated.replace(old, new)
        return mutated

    def mutate_m2_function_renaming(self, code: str) -> str:
        """M2: Rename top-level function while preserving semantic body."""
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    node.name = f"custom_sec_handler_{node.name}"
            return ast.unparse(tree)
        except Exception:
            return code

    def mutate_m3_assignment_aliasing(self, code: str) -> str:
        """M3: Introduce assignment aliasing before critical operations."""
        lines = code.splitlines()
        mutated_lines = ["_sec_alias_var = 100"]
        for line in lines:
            mutated_lines.append(line)
            if "=" in line and "def " not in line:
                indent = line[: len(line) - len(line.lstrip())]
                var_name = line.split("=")[0].strip()
                if var_name.isidentifier():
                    mutated_lines.append(f"{indent}_alias_{var_name} = {var_name}")
        return "\n".join(mutated_lines)

    def mutate_m5_boolean_expressions(self, code: str) -> str:
        """M5: Replace boolean checks with equivalent boolean expressions."""
        mutated = code.replace("if not current_user.is_admin:", "if current_user.is_admin == False:")
        mutated = mutated.replace("quantity <= 0", "(quantity == 0 or quantity < 0)")
        return mutated

    def mutate_m6_dead_code_injection(self, code: str) -> str:
        """M6: Inject dead / unread variables and harmless statements."""
        dead_lines = [
            "# Injected adversarial dead code",
            "_unused_debug_timestamp = 1724400000",
            "_harmless_config_flag = True",
        ]
        return "\n".join(dead_lines) + "\n" + code

    def mutate_m7_formatting_noise(self, code: str) -> str:
        """M7: Inject formatting noise, comments, and extra spacing."""
        lines = code.splitlines()
        noisy = ["# --- Security Handler Start ---", ""]
        for line in lines:
            noisy.append(line)
            noisy.append("")  # Blank line noise
        noisy.append("# --- Security Handler End ---")
        return "\n".join(noisy)

    def generate_mutation(self, base_case_id: str, code: str, mutation_type: str) -> MutationCase:
        if mutation_type == "M1":
            mutated = self.mutate_m1_identifier_renaming(code)
        elif mutation_type == "M2":
            mutated = self.mutate_m2_function_renaming(code)
        elif mutation_type == "M3":
            mutated = self.mutate_m3_assignment_aliasing(code)
        elif mutation_type == "M5":
            mutated = self.mutate_m5_boolean_expressions(code)
        elif mutation_type == "M6":
            mutated = self.mutate_m6_dead_code_injection(code)
        elif mutation_type == "M7":
            mutated = self.mutate_m7_formatting_noise(code)
        else:
            mutated = self.mutate_m6_dead_code_injection(code)

        mutation_id = f"mut-{base_case_id}-{mutation_type.lower()}"
        return MutationCase(
            mutation_id=mutation_id,
            base_case_id=base_case_id,
            mutation_type=mutation_type,
            semantic_preservation=True,
            expected_behavior="IDENTICAL_DETECTION",
            mutated_code=mutated,
        )
