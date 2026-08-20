"""Candidate records and state container for Flask Controller extraction."""

from __future__ import annotations

from dataclasses import dataclass

from karsasec.framework.origin import Evidence


@dataclass(frozen=True)
class HandlerCandidate:
    """Candidate representation of a Flask controller handler function or method."""

    name: str
    qualified_name: str
    function_name: str
    parameters: tuple[str, ...] = ()
    return_type: str = "Any"
    http_methods: tuple[str, ...] = ()
    file_path: str = ""
    line: int = 1
    confidence: float = 1.0
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ControllerCandidate:
    """Candidate representation of a Flask function-based or class-based controller."""

    name: str
    qualified_name: str
    controller_type: str = "function_controller"  # function_controller, method_view, class_view
    handlers: tuple[str, ...] = ()
    parent_class: str | None = None
    file_path: str = ""
    line: int = 1
    blueprint: str | None = None
    confidence: float = 1.0
    routes: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


class FlaskControllerState:
    """State accumulator for Flask controller extraction across project files."""

    def __init__(self) -> None:
        self.controllers: list[ControllerCandidate] = []
        self.handlers: list[HandlerCandidate] = []
        self.blueprints: dict[str, str] = {}  # var_name -> blueprint_name
        self.as_view_map: dict[str, str] = {}  # view_name -> class_name
        self.route_bindings: dict[str, list[str]] = {}  # handler_name -> list of route paths

    def register_blueprint(self, var_name: str, bp_name: str) -> None:
        self.blueprints[var_name] = bp_name

    def register_as_view(self, view_name: str, class_name: str) -> None:
        self.as_view_map[view_name] = class_name

    def register_route_binding(self, handler_name: str, route_path: str) -> None:
        if handler_name not in self.route_bindings:
            self.route_bindings[handler_name] = []
        if route_path not in self.route_bindings[handler_name]:
            self.route_bindings[handler_name].append(route_path)

    def add_controller(self, controller: ControllerCandidate) -> None:
        self.controllers.append(controller)

    def add_handler(self, handler: HandlerCandidate) -> None:
        self.handlers.append(handler)
