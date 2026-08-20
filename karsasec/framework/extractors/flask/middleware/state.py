"""Flask Middleware State and Candidate dataclasses for middleware intelligence extraction."""

from __future__ import annotations

from dataclasses import dataclass

from karsasec.framework.origin import Evidence


@dataclass(frozen=True)
class MiddlewareCandidate:
    """Raw record for a Flask request hook or class-based middleware candidate."""

    name: str
    middleware_type: str  # BEFORE_REQUEST, AFTER_REQUEST, TEARDOWN, CLASS_MIDDLEWARE
    handler: str
    decorator: str = ""
    phase: str = "before_request"  # before_request, after_response, request_teardown, application_teardown
    file_path: str = ""
    line: int = 1
    blueprint: str | None = None
    evidence: tuple[Evidence, ...] = ()
    confidence: float = 1.0


@dataclass(frozen=True)
class ErrorHandlerCandidate:
    """Raw record for a Flask error handler candidate."""

    exception_type: str = "Exception"
    status_code: int | None = None
    handler: str = ""
    file_path: str = ""
    line: int = 1
    blueprint: str | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ExtensionCandidate:
    """Raw record for a Flask extension middleware initialization (CORS, Limiter, etc.)."""

    extension_name: str
    constructor: str = ""
    application: str = "app"
    file_path: str = ""
    line: int = 1
    evidence: tuple[Evidence, ...] = ()


class FlaskMiddlewareState:
    """Cross-file deterministic state accumulator for Flask middleware extraction."""

    def __init__(self) -> None:
        self.applications: dict[str, str] = {}  # var_name -> class_name
        self.blueprints: dict[str, str] = {}  # var_name -> bp_name
        self.middleware_candidates: list[MiddlewareCandidate] = []
        self.error_handlers: list[ErrorHandlerCandidate] = []
        self.extensions: list[ExtensionCandidate] = []
        self.class_middlewares: list[MiddlewareCandidate] = []

    def register_app(self, var_name: str, class_name: str = "Flask") -> None:
        self.applications[var_name] = class_name

    def register_blueprint(self, var_name: str, bp_name: str) -> None:
        self.blueprints[var_name] = bp_name

    def add_middleware_candidate(self, candidate: MiddlewareCandidate) -> None:
        self.middleware_candidates.append(candidate)

    def add_error_handler(self, candidate: ErrorHandlerCandidate) -> None:
        self.error_handlers.append(candidate)

    def add_extension(self, candidate: ExtensionCandidate) -> None:
        self.extensions.append(candidate)

    def add_class_middleware(self, candidate: MiddlewareCandidate) -> None:
        self.class_middlewares.append(candidate)
