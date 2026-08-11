"""AST Visitor for RBAC, role, and permission authorization requirements."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.auth.state import (
    AuthCandidate,
    FlaskAuthState,
    PermissionCandidate,
    RoleCandidate,
)
from karsasec.framework.origin import Evidence
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskRoleAuthorizationVisitor:
    """Visits FunctionDef and Call AST nodes to extract roles and permissions."""

    ROLE_DECORATORS = {"roles_required", "roles_accepted", "admin_required", "requires_roles", "has_role"}
    PERMISSION_DECORATORS = {"permission_required", "permissions_required", "requires_permission", "has_permission"}

    def __init__(self, state: FlaskAuthState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node

        if isinstance(raw, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function_def(raw, node)
        elif isinstance(raw, ast.Call):
            self._visit_call(raw, node)

    def _visit_function_def(self, func: ast.FunctionDef | ast.AsyncFunctionDef, node: ASTNodeWrapper) -> None:
        extracted_roles: list[str] = []
        extracted_permissions: list[str] = []
        matched_role_dec = False
        matched_perm_dec = False
        matched_dec = ""

        for dec in func.decorator_list:
            dec_name = self._resolve_decorator_name(dec)
            if not dec_name:
                continue

            base = dec_name.split(".")[-1]

            if base in self.ROLE_DECORATORS or "roles" in base or base == "admin_required":
                matched_dec = dec_name
                matched_role_dec = True
                if base == "admin_required":
                    extracted_roles.append("admin")
                elif isinstance(dec, ast.Call):
                    extracted_roles.extend(self._extract_string_args(dec))

            elif base in self.PERMISSION_DECORATORS or "permission" in base:
                matched_dec = dec_name
                matched_perm_dec = True
                if isinstance(dec, ast.Call):
                    extracted_permissions.extend(self._extract_string_args(dec))

        if matched_role_dec:
            evidence = Evidence(
                snippet=f"@{matched_dec}",
                rule_or_marker=f"rbac_roles:{','.join(extracted_roles)}",
                file_path=node.file_path,
                line=node.line,
            )
            role_cand = RoleCandidate(
                handler=func.name,
                roles=tuple(extracted_roles),
                file_path=node.file_path,
                line=node.line,
                evidence=(evidence,),
            )
            self.state.add_role_candidate(role_cand)

            if extracted_roles:
                auth_cand = AuthCandidate(
                    auth_type="RBAC",
                    provider="custom",
                    scheme="rbac",
                    handler=func.name,
                    decorator=matched_dec,
                    roles=tuple(extracted_roles),
                    file_path=node.file_path,
                    line=node.line,
                    confidence=0.98,
                    evidence=(evidence,),
                )
                self.state.add_auth_candidate(auth_cand)

        if matched_perm_dec:
            evidence = Evidence(
                snippet=f"@{matched_dec}",
                rule_or_marker=f"rbac_permissions:{','.join(extracted_permissions)}",
                file_path=node.file_path,
                line=node.line,
            )
            perm_cand = PermissionCandidate(
                handler=func.name,
                permissions=tuple(extracted_permissions),
                file_path=node.file_path,
                line=node.line,
                evidence=(evidence,),
            )
            self.state.add_permission_candidate(perm_cand)

            if extracted_permissions:
                auth_cand = AuthCandidate(
                    auth_type="RBAC",
                    provider="custom",
                    scheme="rbac",
                    handler=func.name,
                    decorator=matched_dec,
                    permissions=tuple(extracted_permissions),
                    file_path=node.file_path,
                    line=node.line,
                    confidence=0.98,
                    evidence=(evidence,),
                )
                self.state.add_auth_candidate(auth_cand)

    def _visit_call(self, call: ast.Call, node: ASTNodeWrapper) -> None:
        # Detect current_user.has_role("admin") or current_user.has_permission("write")
        func_name = self._resolve_name(call.func)
        if func_name in ("current_user.has_role", "user.has_role"):
            roles = self._extract_string_args(call)
            if roles:
                evidence = Evidence(
                    snippet=f"{func_name}({','.join(roles)})",
                    rule_or_marker="rbac:has_role",
                    file_path=node.file_path,
                    line=node.line,
                )
                role_cand = RoleCandidate(
                    handler="",
                    roles=tuple(roles),
                    file_path=node.file_path,
                    line=node.line,
                    evidence=(evidence,),
                )
                self.state.add_role_candidate(role_cand)

        elif func_name in ("current_user.has_permission", "user.has_permission"):
            perms = self._extract_string_args(call)
            if perms:
                evidence = Evidence(
                    snippet=f"{func_name}({','.join(perms)})",
                    rule_or_marker="rbac:has_permission",
                    file_path=node.file_path,
                    line=node.line,
                )
                perm_cand = PermissionCandidate(
                    handler="",
                    permissions=tuple(perms),
                    file_path=node.file_path,
                    line=node.line,
                    evidence=(evidence,),
                )
                self.state.add_permission_candidate(perm_cand)

    def _extract_string_args(self, call: ast.Call) -> list[str]:
        results: list[str] = []
        for arg in call.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                results.append(arg.value)
            elif isinstance(arg, (ast.Tuple, ast.List)):
                for elt in arg.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        results.append(elt.value)
        return results

    def _resolve_decorator_name(self, dec: ast.AST) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        elif isinstance(dec, ast.Attribute):
            val = self._resolve_decorator_name(dec.value)
            return f"{val}.{dec.attr}" if val else dec.attr
        elif isinstance(dec, ast.Call):
            return self._resolve_decorator_name(dec.func)
        return ""

    def _resolve_name(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        elif isinstance(expr, ast.Attribute):
            val = self._resolve_name(expr.value)
            return f"{val}.{expr.attr}" if val else expr.attr
        return ""
