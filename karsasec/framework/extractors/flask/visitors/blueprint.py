"""AST Visitor for Blueprint instantiations and register_blueprint calls."""

from __future__ import annotations

import ast

from karsasec.framework.extractors.flask.state import (
    BlueprintRecord,
    BlueprintRegistrationRecord,
    FlaskSemanticState,
)
from karsasec.framework.parser.ast_adapter import ASTNodeWrapper


class FlaskBlueprintVisitor:
    """Visits Assign and Call AST nodes for Blueprint definitions and register_blueprint calls."""

    def __init__(self, state: FlaskSemanticState) -> None:
        self.state = state

    def visit(self, node: ASTNodeWrapper) -> None:
        """Inspects Assign and Call nodes."""
        raw = node.raw_node

        # 1. Blueprint instantiation (bp = Blueprint('auth', __name__, url_prefix='/auth'))
        if isinstance(raw, ast.Assign):
            self._check_blueprint_assignment(raw, node)

        # 2. register_blueprint call (app.register_blueprint(bp, url_prefix='/api'))
        if isinstance(raw, ast.Call):
            self._check_blueprint_registration(raw, node)


    def _check_blueprint_assignment(self, assign_node: ast.Assign, node: ASTNodeWrapper) -> None:
        if not isinstance(assign_node.value, ast.Call):
            return

        call_node = assign_node.value
        func = call_node.func
        is_blueprint_call = False

        if isinstance(func, ast.Name) and func.id == "Blueprint":
            is_blueprint_call = True
        elif isinstance(func, ast.Attribute) and func.attr == "Blueprint":
            is_blueprint_call = True

        if not is_blueprint_call:
            return

        # Target variable name
        var_name = ""
        if assign_node.targets and isinstance(assign_node.targets[0], ast.Name):
            var_name = assign_node.targets[0].id

        if not var_name:
            return

        bp_name = var_name
        import_name = ""
        url_prefix = ""

        # Extract name (arg 0)
        if call_node.args and isinstance(call_node.args[0], ast.Constant) and isinstance(call_node.args[0].value, str):
            bp_name = call_node.args[0].value

        # Extract url_prefix keyword
        for kw in call_node.keywords:
            if kw.arg == "url_prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                url_prefix = kw.value.value

        bp_rec = BlueprintRecord(
            name=bp_name,
            variable_name=var_name,
            import_name=import_name,
            url_prefix=url_prefix,
            file_path=node.file_path,
            line=node.line,
        )
        self.state.blueprints[var_name] = bp_rec
        self.state.blueprints[bp_name] = bp_rec

    def _check_blueprint_registration(self, call_node: ast.Call, node: ASTNodeWrapper) -> None:
        func = call_node.func
        if not isinstance(func, ast.Attribute) or func.attr != "register_blueprint":
            return

        target_var = ""
        if isinstance(func.value, ast.Name):
            target_var = func.value.id

        if not call_node.args:
            return

        bp_arg = call_node.args[0]
        bp_var = ""
        if isinstance(bp_arg, ast.Name):
            bp_var = bp_arg.id

        url_prefix = ""
        for kw in call_node.keywords:
            if kw.arg == "url_prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                url_prefix = kw.value.value

        reg_rec = BlueprintRegistrationRecord(
            blueprint_var=bp_var,
            target_var=target_var or "app",
            url_prefix=url_prefix,
            file_path=node.file_path,
            line=node.line,
        )
        self.state.blueprint_registrations.append(reg_rec)
