"""Flask Auth State and Candidate dataclasses for Auth Intelligence extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.framework.origin import Evidence


@dataclass(frozen=True)
class ProviderCandidate:
    """Raw record for an identified authentication provider."""

    name: str  # flask-login, flask-jwt-extended, flask-httpauth, custom
    symbol: str
    source_module: str
    file_path: str = ""
    line: int = 1
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class AuthManagerCandidate:
    """Raw record for an authentication manager initialization (LoginManager, JWTManager, etc.)."""

    manager_type: str  # LoginManager, JWTManager, HTTPBasicAuth, HTTPTokenAuth
    provider: str
    variable_name: str = ""
    application_var: str = ""
    file_path: str = ""
    line: int = 1
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class AuthCandidate:
    """Raw record for an authentication policy candidate."""

    auth_type: str  # FLASK_LOGIN, JWT, BASIC_AUTH, TOKEN, RBAC, CUSTOM_DECORATOR, SESSION, COOKIE
    provider: str  # flask-login, flask-jwt-extended, flask-httpauth, custom, session
    scheme: str  # session, jwt, basic, bearer, token, custom
    handler: str = ""
    decorator: str = ""
    blueprint: str = ""
    manager: str = ""
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    session_keys: tuple[str, ...] = ()
    cookie_names: tuple[str, ...] = ()
    file_path: str = ""
    line: int = 1
    confidence: float = 1.0
    evidence: tuple[Evidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RoleCandidate:
    """Raw record for role-based authorization requirements."""

    handler: str
    roles: tuple[str, ...]
    file_path: str = ""
    line: int = 1
    blueprint: str = ""
    confidence: float = 0.98
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class PermissionCandidate:
    """Raw record for permission-based authorization requirements."""

    handler: str
    permissions: tuple[str, ...]
    file_path: str = ""
    line: int = 1
    blueprint: str = ""
    confidence: float = 0.98
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class SessionCandidate:
    """Raw record for session usage classification."""

    key: str
    operation: str  # READ, WRITE
    classification: str  # AUTH_SESSION, IDENTITY_SESSION, ROLE_SESSION, GENERIC_SESSION
    handler: str = ""
    file_path: str = ""
    line: int = 1
    blueprint: str = ""
    has_access_control: bool = False
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class CookieCandidate:
    """Raw record for cookie usage classification."""

    name: str
    operation: str  # SET, DELETE, READ
    classification: str  # AUTH_COOKIE, SESSION_COOKIE, REMEMBER_COOKIE, GENERIC_COOKIE
    handler: str = ""
    file_path: str = ""
    line: int = 1
    blueprint: str = ""
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class DecoratorCandidate:
    """Raw record for custom auth decorator candidate."""

    name: str
    func_name: str
    wrapper_name: str
    is_auth_related: bool = False
    auth_evidence_type: str = ""
    file_path: str = ""
    line: int = 1
    confidence: float = 0.85
    evidence: tuple[Evidence, ...] = ()


class FlaskAuthState:
    """Cross-file deterministic state accumulator for Flask auth intelligence."""

    def __init__(self) -> None:
        self.imports: dict[str, str] = {}  # local_symbol -> canonical_symbol (module.symbol)
        self.providers: dict[str, ProviderCandidate] = {}  # symbol -> ProviderCandidate
        self.managers: dict[str, AuthManagerCandidate] = {}  # var_name -> AuthManagerCandidate
        self.blueprints: dict[str, str] = {}  # var_name -> bp_name
        self.auth_candidates: list[AuthCandidate] = []
        self.role_candidates: list[RoleCandidate] = []
        self.permission_candidates: list[PermissionCandidate] = []
        self.session_candidates: list[SessionCandidate] = []
        self.cookie_candidates: list[CookieCandidate] = []
        self.decorator_candidates: list[DecoratorCandidate] = []

    def register_import(self, local_symbol: str, canonical_symbol: str) -> None:
        self.imports[local_symbol] = canonical_symbol

    def register_provider(self, candidate: ProviderCandidate) -> None:
        self.providers[candidate.symbol] = candidate

    def register_manager(self, candidate: AuthManagerCandidate) -> None:
        if candidate.variable_name:
            self.managers[candidate.variable_name] = candidate

    def register_blueprint(self, var_name: str, bp_name: str) -> None:
        self.blueprints[var_name] = bp_name

    def add_auth_candidate(self, candidate: AuthCandidate) -> None:
        self.auth_candidates.append(candidate)

    def add_role_candidate(self, candidate: RoleCandidate) -> None:
        self.role_candidates.append(candidate)

    def add_permission_candidate(self, candidate: PermissionCandidate) -> None:
        self.permission_candidates.append(candidate)

    def add_session_candidate(self, candidate: SessionCandidate) -> None:
        self.session_candidates.append(candidate)

    def add_cookie_candidate(self, candidate: CookieCandidate) -> None:
        self.cookie_candidates.append(candidate)

    def add_decorator_candidate(self, candidate: DecoratorCandidate) -> None:
        self.decorator_candidates.append(candidate)
