"""2-Pass AST Collector for Flask Authentication & Authorization Intelligence."""

from __future__ import annotations

import ast
from collections.abc import Sequence

from karsasec.framework.extractors.flask.auth.state import FlaskAuthState
from karsasec.framework.extractors.flask.auth.visitors.cookie import FlaskCookieVisitor
from karsasec.framework.extractors.flask.auth.visitors.decorator import FlaskCustomDecoratorVisitor
from karsasec.framework.extractors.flask.auth.visitors.httpauth import FlaskHTTPAuthVisitor
from karsasec.framework.extractors.flask.auth.visitors.import_resolver import FlaskAuthImportResolverVisitor
from karsasec.framework.extractors.flask.auth.visitors.jwt import FlaskJWTVisitor
from karsasec.framework.extractors.flask.auth.visitors.login import FlaskLoginVisitor
from karsasec.framework.extractors.flask.auth.visitors.manager import FlaskAuthManagerVisitor
from karsasec.framework.extractors.flask.auth.visitors.role import FlaskRoleAuthorizationVisitor
from karsasec.framework.extractors.flask.auth.visitors.session import FlaskSessionVisitor
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper, PythonASTAdapter


class FlaskAuthCollector:
    """2-Pass AST Collector for Flask Authentication and Authorization Intelligence."""

    def __init__(self, state: FlaskAuthState | None = None) -> None:
        self.state = state or FlaskAuthState()

    def collect_from_asts(self, roots: Sequence[ASTNodeWrapper]) -> FlaskAuthState:
        valid_roots = [r for r in roots if r is not None]

        import_visitor = FlaskAuthImportResolverVisitor(self.state)
        manager_visitor = FlaskAuthManagerVisitor(self.state)
        decorator_visitor = FlaskCustomDecoratorVisitor(self.state)

        login_visitor = FlaskLoginVisitor(self.state)
        jwt_visitor = FlaskJWTVisitor(self.state)
        httpauth_visitor = FlaskHTTPAuthVisitor(self.state)
        role_visitor = FlaskRoleAuthorizationVisitor(self.state)
        session_visitor = FlaskSessionVisitor(self.state)
        cookie_visitor = FlaskCookieVisitor(self.state)

        # Pass 1: Discover imports, auth managers, custom decorators, and blueprint definitions across all files
        for root in valid_roots:

            def pass1(node: ASTNodeWrapper) -> None:
                self._discover_blueprints(node)
                import_visitor.visit(node)
                manager_visitor.visit(node)
                decorator_visitor.visit(node)

            PythonASTAdapter.walk(root, pass1)

        # Pass 2: Collect authentication, authorization, session, cookie, and role usage across all files
        for root in valid_roots:

            def pass2(node: ASTNodeWrapper) -> None:
                login_visitor.visit(node)
                jwt_visitor.visit(node)
                httpauth_visitor.visit(node)
                role_visitor.visit(node)
                session_visitor.visit(node)
                cookie_visitor.visit(node)

            PythonASTAdapter.walk(root, pass2)

        return self.state

    def _discover_blueprints(self, node: ASTNodeWrapper) -> None:
        raw = node.raw_node
        if isinstance(raw, ast.Assign):
            if isinstance(raw.value, ast.Call):
                func_name = ""
                if isinstance(raw.value.func, ast.Name):
                    func_name = raw.value.func.id
                elif isinstance(raw.value.func, ast.Attribute):
                    func_name = raw.value.func.attr

                if func_name == "Blueprint":
                    bp_name = ""
                    if (
                        raw.value.args
                        and isinstance(raw.value.args[0], ast.Constant)
                        and isinstance(raw.value.args[0].value, str)
                    ):
                        bp_name = raw.value.args[0].value
                    for target in raw.targets:
                        if isinstance(target, ast.Name):
                            self.state.register_blueprint(target.id, bp_name or target.id)
