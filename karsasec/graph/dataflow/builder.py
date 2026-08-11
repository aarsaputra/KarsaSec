"""Def/Use extraction and incremental Data-Flow Graph Builder (E11)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karsasec.graph.constant_resolver import ConstantResolver
from karsasec.graph.dataflow.sanitizers import sanitizer_registry
from karsasec.graph.dataflow.sources import source_registry


@dataclass(slots=True)
class VariableAssignmentDef:
    """Record of a variable definition/assignment in source text."""
    variable_name: str
    rhs_expression: str
    line: int
    referenced_variables: set[str] = field(default_factory=set)
    is_concatenation: bool = False
    contains_sanitizer: bool = False
    sanitizer_capability: str | None = None
    contains_source: bool = False
    source_symbol: str | None = None


@dataclass(slots=True)
class FunctionDef:
    """Record of a local function or method definition."""
    function_name: str
    parameters: list[str]
    start_line: int
    end_line: int
    body_source: str


class DefUseExtractor:
    """Extracts variable definitions, uses, assignments, and function boundaries from source text."""

    def extract_assignments(self, source_text: str, language: str = "php") -> list[VariableAssignmentDef]:
        """Extract statement-level variable assignments in source order."""
        if not source_text:
            return []

        lang = (language or "").strip().lower()
        assignments: list[VariableAssignmentDef] = []
        lines = source_text.splitlines()

        # Regular expressions for assignment parsing
        # Matches: $var = expr; or var = expr;
        if lang == "php":
            var_pattern = re.compile(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*(\.|\+|\-|\*|/)?=\s*([^;]+);?')
        else:
            var_pattern = re.compile(r'(?:let|const|var|\b)?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(\.|\+|\-|\*|/)?=\s*([^;]+);?')

        for idx, line_content in enumerate(lines, start=1):
            line_str = line_content.strip()
            if not line_str or line_str.startswith("//") or line_str.startswith("#") or line_str.startswith("/*"):
                continue

            for match in var_pattern.finditer(line_str):
                var_name = match.group(1).strip()
                op_prefix = match.group(2) or ""
                rhs_expr = match.group(3).strip()

                is_concat = "." in op_prefix or "." in rhs_expr or "+" in op_prefix

                # Extract referenced variables in RHS
                if lang == "php":
                    ref_vars = set(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', rhs_expr))
                else:
                    ref_vars = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', rhs_expr))

                # Check if RHS contains untrusted source
                has_source = source_registry.contains_source(rhs_expr, language=lang)
                matched_sources = source_registry.find_matching_sources(rhs_expr, language=lang)
                source_sym = matched_sources[0] if matched_sources else None

                # Check if RHS contains sanitizer
                sanitizer_cap = sanitizer_registry.identify_sanitizer("", rhs_expr, language=lang)

                assignments.append(VariableAssignmentDef(
                    variable_name=var_name,
                    rhs_expression=rhs_expr,
                    line=idx,
                    referenced_variables=ref_vars,
                    is_concatenation=is_concat,
                    contains_sanitizer=sanitizer_cap is not None,
                    sanitizer_capability=sanitizer_cap.value if sanitizer_cap else None,
                    contains_source=has_source,
                    source_symbol=source_sym,
                ))

        return assignments

    def extract_function_defs(self, source_text: str, language: str = "php") -> list[FunctionDef]:
        """Extract local function definitions and parameter lists."""
        if not source_text:
            return []

        lang = (language or "").strip().lower()
        functions: list[FunctionDef] = []

        if lang == "php":
            func_pattern = re.compile(
                r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*\{',
                re.IGNORECASE
            )
            lines = source_text.splitlines()
            for idx, line_str in enumerate(lines, start=1):
                m = func_pattern.search(line_str)
                if m:
                    fname = m.group(1).strip()
                    raw_params = m.group(2).strip()
                    params = [p.strip().split()[-1] for p in raw_params.split(",") if p.strip()]
                    params = [p if p.startswith("$") else f"${p}" for p in params if p]

                    # Extract body up to matching closing brace
                    body_lines: list[str] = []
                    brace_count = 0
                    start_found = False
                    end_idx = idx

                    for j in range(idx - 1, len(lines)):
                        l = lines[j]
                        brace_count += l.count("{") - l.count("}")
                        body_lines.append(l)
                        if "{" in l:
                            start_found = True
                        if start_found and brace_count <= 0:
                            end_idx = j + 1
                            break

                    functions.append(FunctionDef(
                        function_name=fname,
                        parameters=params,
                        start_line=idx,
                        end_line=end_idx,
                        body_source="\n".join(body_lines),
                    ))

        return functions


class DataFlowGraphBuilder:
    """Builds a statement-level Data-Flow Graph from source code and AST nodes."""

    def __init__(self) -> None:
        self.extractor = DefUseExtractor()
        self.const_resolver = ConstantResolver()

    def build_graph(self, source_text: str, file_path: Path | None = None, language: str = "php") -> dict[str, Any]:
        """Construct symbol tables, def-use maps, and function definitions."""
        assignments = self.extractor.extract_assignments(source_text, language=language)
        functions = self.extractor.extract_function_defs(source_text, language=language)
        const_decls = self.const_resolver.discover_declarations(source_text)

        # Build symbol def-use map (var_name -> list of assignments)
        def_use_map: dict[str, list[VariableAssignmentDef]] = {}
        for assign in assignments:
            def_use_map.setdefault(assign.variable_name, []).append(assign)

        func_map: dict[str, FunctionDef] = {f.function_name.lower(): f for f in functions}

        return {
            "source_text": source_text,
            "file_path": file_path,
            "language": language,
            "assignments": assignments,
            "def_use_map": def_use_map,
            "functions": func_map,
            "constant_declarations": const_decls,
        }
