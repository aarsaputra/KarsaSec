"""Candidate records and state container for Flask Configuration extraction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from karsasec.framework.origin import Evidence


@dataclass(frozen=True)
class ConfigCandidate:
    """Candidate representation of a Flask configuration key-value setting."""
    key: str
    value: Any = None
    source_type: str = "direct_assign"  # direct_assign, attribute_assign, update, from_object, from_pyfile, from_envvar, from_mapping, env_var
    category: str = "app"
    loader: str | None = None
    file_path: str = ""
    line: int = 1
    confidence: float = 1.0
    is_sensitive: bool = False
    is_dynamic: bool = False
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class EnvironmentCandidate:
    """Candidate representation of an environment variable configuration lookup."""
    var_name: str
    default_value: Any = None
    source: str = "os.environ"  # os.environ, os.getenv, dotenv, decouple, django-environ
    file_path: str = ""
    line: int = 1
    confidence: float = 0.85
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ConfigClassCandidate:
    """Candidate representation of a configuration class definition (e.g. DevelopmentConfig)."""
    class_name: str
    parent_class: str | None = None
    settings: tuple[tuple[str, Any], ...] = ()
    file_path: str = ""
    line: int = 1
    confidence: float = 0.90
    evidence: tuple[Evidence, ...] = ()


class FlaskConfigState:
    """State accumulator for Flask configuration extraction across project files."""

    def __init__(self) -> None:
        self.configs: list[ConfigCandidate] = []
        self.env_vars: list[EnvironmentCandidate] = []
        self.config_classes: dict[str, ConfigClassCandidate] = {}  # class_name -> candidate
        self.class_inheritance: dict[str, str] = {}  # child -> parent
        self.override_chain: list[ConfigCandidate] = []
        self.imported_modules: dict[str, str] = {}  # alias -> module_path

    def add_config(self, candidate: ConfigCandidate) -> None:
        self.configs.append(candidate)
        self.override_chain.append(candidate)

    def add_env_var(self, candidate: EnvironmentCandidate) -> None:
        self.env_vars.append(candidate)

    def add_config_class(self, candidate: ConfigClassCandidate) -> None:
        self.config_classes[candidate.class_name] = candidate
        if candidate.parent_class:
            self.class_inheritance[candidate.class_name] = candidate.parent_class

    def register_import(self, alias: str, module_path: str) -> None:
        self.imported_modules[alias] = module_path
