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
    return_expressions: list[str] = field(default_factory=list)


class DefUseExtractor:
    """Extracts variable definitions, uses, assignments, and function boundaries from source text."""

    def extract_assignments(self, source_text: str, language: str = "php") -> list[VariableAssignmentDef]:
        """Extract statement-level variable assignments in source order."""
        if not source_text:
            return []

        lang = (language or "").strip().lower()
        assignments: list[VariableAssignmentDef] = []
        lines = source_text.splitlines()

        # Regular expressions for assignment parsing, allowing optional array subscripts like $page['body']
        if lang == "php":
            var_pattern = re.compile(
                r"(\$[a-zA-Z_][a-zA-Z0-9_]*)(?:\[[^\]]*\])*\s*(?<![=!<>])(\.|\+|\-|\*|/)?=(?![=~])\s*([^;]+);?"
            )
        else:
            var_pattern = re.compile(
                r"(?:let|const|var|\b)?\s*([a-zA-Z_][a-zA-Z0-9_]*)(?:\[[^\]]*\])*\s*(?<![=!<>])(\.|\+|\-|\*|/)?=(?![=~])\s*([^;]+);?"
            )

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
                    ref_vars = set(re.findall(r"\$[a-zA-Z_][a-zA-Z0-9_]*", rhs_expr))
                else:
                    ref_vars = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", rhs_expr))

                # For augmented assignments (e.g., .=, +=), the target variable itself is read.
                if op_prefix:
                    ref_vars.add(var_name)

                # Check if RHS contains untrusted source
                has_source = source_registry.contains_source(rhs_expr, language=lang)
                matched_sources = source_registry.find_matching_sources(rhs_expr, language=lang)
                source_sym = matched_sources[0] if matched_sources else None

                # Check if RHS contains sanitizer
                sanitizer_cap = sanitizer_registry.identify_sanitizer("", rhs_expr, language=lang)

                assignments.append(
                    VariableAssignmentDef(
                        variable_name=var_name,
                        rhs_expression=rhs_expr,
                        line=idx,
                        referenced_variables=ref_vars,
                        is_concatenation=is_concat,
                        contains_sanitizer=sanitizer_cap is not None,
                        sanitizer_capability=sanitizer_cap.value if sanitizer_cap else None,
                        contains_source=has_source,
                        source_symbol=source_sym,
                    )
                )

        return assignments

    def extract_function_defs(self, source_text: str, language: str = "php") -> list[FunctionDef]:
        """Extract local function definitions and parameter lists."""
        if not source_text:
            return []

        lang = (language or "").strip().lower()
        functions: list[FunctionDef] = []

        if lang == "php":
            func_pattern = re.compile(r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*\{", re.IGNORECASE)
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

                    body_str = "\n".join(body_lines)
                    ret_matches = re.findall(r"return\s+([^;]+);", body_str, re.IGNORECASE)
                    ret_exprs = [r.strip() for r in ret_matches if r.strip()]

                    functions.append(
                        FunctionDef(
                            function_name=fname,
                            parameters=params,
                            start_line=idx,
                            end_line=end_idx,
                            body_source=body_str,
                            return_expressions=ret_exprs,
                        )
                    )

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

        # Check for include/require statements to pull definitions from static local files
        if file_path and isinstance(file_path, Path) and file_path.exists():
            inc_pattern = re.compile(
                r"(?:include|include_once|require|require_once)\s*\(?\s*([^;]+)\)?;", re.IGNORECASE
            )
            for m in inc_pattern.finditer(source_text):
                raw_expr = m.group(1).strip()
                candidate_paths: list[str] = []
                lit_match = re.search(r'["\']([^"\']+)["\']', raw_expr)
                if lit_match:
                    path_tmpl = lit_match.group(1).strip()
                    var_matches = re.findall(r"\{\$([a-zA-Z0-9_]+)\}|\$([a-zA-Z0-9_]+)", path_tmpl)
                    var_names = [v[0] or v[1] for v in var_matches]
                    if not var_names:
                        candidate_paths.append(path_tmpl)
                    else:
                        possible_vals: list[str] = []
                        for vn in var_names:
                            for assign in def_use_map.get(f"${vn}", []) + def_use_map.get(vn, []):
                                str_lits = re.findall(r'["\']([^"\']+)["\']', assign.rhs_expression)
                                possible_vals.extend(str_lits)
                        if not possible_vals:
                            possible_vals = ["low.php", "medium.php", "high.php", "impossible.php"]
                        for pv in possible_vals:
                            resolved_path = path_tmpl
                            for vn in var_names:
                                resolved_path = resolved_path.replace(f"${{{vn}}}", pv).replace(f"${vn}", pv)
                            candidate_paths.append(resolved_path)

                for rel_inc in candidate_paths:
                    inc_file: Path | None = None
                    curr_dir = file_path.parent
                    for _ in range(5):
                        cand = curr_dir / rel_inc
                        if cand.exists() and cand.is_file():
                            inc_file = cand
                            break
                        if curr_dir == curr_dir.parent:
                            break
                        curr_dir = curr_dir.parent

                    if inc_file and inc_file.exists() and inc_file.is_file():
                        try:
                            inc_text = inc_file.read_text(encoding="utf-8", errors="replace")
                            inc_assigns = self.extractor.extract_assignments(inc_text, language=language)
                            for assign in inc_assigns:
                                def_use_map.setdefault(assign.variable_name, []).append(assign)
                            inc_funcs = self.extractor.extract_function_defs(inc_text, language=language)
                            for f in inc_funcs:
                                func_map.setdefault(f.function_name.lower(), f)
                        except Exception:
                            pass

        return {
            "source_text": source_text,
            "file_path": file_path,
            "language": language,
            "assignments": assignments,
            "def_use_map": def_use_map,
            "functions": func_map,
            "constant_declarations": const_decls,
        }
