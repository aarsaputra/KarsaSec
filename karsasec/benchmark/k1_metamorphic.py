"""K1 Metamorphic Security Engine & Layered Semantic Equivalence Validator (Task K1.6).

Taxonomy Alignment:
- M1-M7: Metamorphic Semantic Transformations (semantic-preserving)
- M8: Adversarial Safe-Control Transformation
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import re


@dataclass
class MetamorphicCase:
    mutation_id: str
    source: str
    transformed_source: str
    transformation: str
    semantic_equivalent: bool


class LayeredSemanticEquivalenceValidator:
    """Layered Semantic Equivalence Validator for Metamorphic Transformations."""

    def validate(self, original_code: str, transformed_code: str, transformation: str) -> bool:
        # Layer 1: Syntax Validity
        try:
            tree_orig = ast.parse(original_code)
            tree_trans = ast.parse(transformed_code)
        except SyntaxError:
            return False

        # Layer 2: AST Structural Transformation Validity
        orig_funcs = {node.name for node in ast.walk(tree_orig) if isinstance(node, ast.FunctionDef)}
        trans_funcs = {node.name for node in ast.walk(tree_trans) if isinstance(node, ast.FunctionDef)}

        if not (len(orig_funcs.intersection(trans_funcs)) > 0 or len(trans_funcs) > len(orig_funcs)):
            return False

        # Layer 3: Transformation-Specific Invariants
        if transformation == "M7_HELPER_WRAPPER":
            # Helper wrapper must introduce wrapper function while preserving original entry points
            if "_helper_extract_param" not in transformed_code:
                return False

        elif transformation == "M1_IDENTIFIER_RENAME":
            # Renaming must maintain call/assignment node counts
            orig_calls = len([n for n in ast.walk(tree_orig) if isinstance(n, ast.Call)])
            trans_calls = len([n for n in ast.walk(tree_trans) if isinstance(n, ast.Call)])
            if orig_calls != trans_calls:
                return False

        return True


class K1MetamorphicEngine:
    """Generates metamorphic cases across M1-M7 transformations and M8 safe-controls."""

    def __init__(self) -> None:
        self.validator = LayeredSemanticEquivalenceValidator()

    def generate_metamorphic_case(
        self, fixture_id: str, code: str, transformation: str
    ) -> MetamorphicCase:
        transformed = code

        if transformation == "M1_IDENTIFIER_RENAME":
            transformed = re.sub(r"\btoken\b", "credential_token", code)
            transformed = re.sub(r"\breq\b", "http_request", transformed)
            transformed = re.sub(r"\bdoc_id\b", "target_doc_id", transformed)

        elif transformation == "M2_ASSIGNMENT_ALIAS":
            lines = code.splitlines()
            new_lines = []
            for line in lines:
                if line.strip().startswith("def "):
                    new_lines.append(line)
                    indent = " " * (len(line) - len(line.lstrip()) + 4)
                    new_lines.append(f"{indent}alias_var_ref = 100")
                else:
                    new_lines.append(line)
            transformed = "\n".join(new_lines)

        elif transformation == "M3_INTERMEDIATE_VARIABLE":
            if "req.json.get(" in code:
                transformed = code.replace(
                    "req.json.get(", "_temp_extracted = req.json.get("
                )
            else:
                lines = code.splitlines()
                new_lines = []
                for line in lines:
                    if "return " in line:
                        indent = " " * (len(line) - len(line.lstrip()))
                        expr = line.replace("return ", "").strip()
                        new_lines.append(f"{indent}_intermediate_ret = {expr}")
                        new_lines.append(f"{indent}return _intermediate_ret")
                    else:
                        new_lines.append(line)
                transformed = "\n".join(new_lines)

        elif transformation == "M4_EQUIVALENT_EXPRESSION":
            transformed = code.replace("* 100", "* (50 + 50)").replace("== True", "is True")

        elif transformation == "M5_DEAD_CODE":
            transformed = "# Harmless dead code\n_unused_debug = 42\n" + code

        elif transformation == "M6_FORMATTING_NOISE":
            transformed = "\n# Formatting noise header\n\n" + code.replace("\n", "\n\n# noise\n")

        elif transformation == "M7_HELPER_WRAPPER":
            wrapper = (
                "def _helper_extract_param(request, key):\n"
                "    return request.json.get(key) if hasattr(request, 'json') else request.args.get(key)\n\n"
            )
            transformed = wrapper + code

        is_equiv = self.validator.validate(code, transformed, transformation)

        return MetamorphicCase(
            mutation_id=f"{fixture_id}_{transformation}",
            source=code,
            transformed_source=transformed,
            transformation=transformation,
            semantic_equivalent=is_equiv,
        )
