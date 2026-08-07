"""Flask Shared Semantic State container for cross-file and cross-extractor data sharing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RawRouteRecord:
    """Raw route candidate record captured by visitors."""
    path: str
    methods: tuple[str, ...] = ("GET",)
    endpoint: str = ""
    handler_name: str = ""
    blueprint_name: str | None = None
    file_path: str = ""
    line: int = 1
    decorators: tuple[str, ...] = ()
    confidence: float = 1.0
    evidence: tuple[str, ...] = ()
    is_method_view: bool = False
    is_add_url_rule: bool = False
    is_factory: bool = False


@dataclass
class BlueprintRecord:
    """Blueprint definition record."""
    name: str
    variable_name: str
    import_name: str = ""
    url_prefix: str = ""
    file_path: str = ""
    line: int = 1


@dataclass
class BlueprintRegistrationRecord:
    """Blueprint registration record (e.g. app.register_blueprint(bp, url_prefix='/api'))."""
    blueprint_var: str
    target_var: str = "app"
    url_prefix: str = ""
    file_path: str = ""
    line: int = 1


@dataclass
class MethodViewRecord:
    """MethodView class record."""
    class_name: str
    url_rule: str | None = None
    methods_map: dict[str, str] = field(default_factory=dict)  # HTTP method -> handler method name
    file_path: str = ""
    line: int = 1


@dataclass
class FlaskSemanticState:
    """Shared semantic state repository maintained across Flask visitors."""
    applications: dict[str, str] = field(default_factory=dict)  # var_name -> file_path
    blueprints: dict[str, BlueprintRecord] = field(default_factory=dict)  # var_name or name -> BlueprintRecord
    blueprint_registrations: list[BlueprintRegistrationRecord] = field(default_factory=list)
    routes: list[RawRouteRecord] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)  # alias_var -> target_decorator (e.g. 'r' -> 'app.route')
    method_views: dict[str, MethodViewRecord] = field(default_factory=dict)  # class_name -> MethodViewRecord
    handlers: dict[str, Any] = field(default_factory=dict)  # handler_name -> AST wrapper/info

    def add_alias(self, alias_name: str, target: str) -> None:
        """Registers a decorator or function alias."""
        self.aliases[alias_name] = target

    def resolve_decorator_target(self, decorator_name: str) -> str:
        """Resolves alias chain to target decorator root."""
        curr = decorator_name
        visited = set()
        while curr in self.aliases and curr not in visited:
            visited.add(curr)
            curr = self.aliases[curr]
        return curr

    def clear(self) -> None:
        """Resets state."""
        self.applications.clear()
        self.blueprints.clear()
        self.blueprint_registrations.clear()
        self.routes.clear()
        self.aliases.clear()
        self.method_views.clear()
        self.handlers.clear()
