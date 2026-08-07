"""Abstract Base Class for Framework Plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod

from karsasec.framework.models import FrameworkDefinition, FrameworkType


class FrameworkPlugin(ABC):
    """Abstract interface for all language/framework specific plugins."""

    @property
    @abstractmethod
    def framework_type(self) -> FrameworkType:
        """Returns the FrameworkType enum handled by this plugin."""
        pass

    @abstractmethod
    def get_definition(self) -> FrameworkDefinition:
        """Returns static FrameworkDefinition for this framework plugin."""
        pass

    @abstractmethod
    def get_manifest_names(self) -> tuple[str, ...]:
        """Returns dependency manifest filenames relevant to this framework (e.g. ('requirements.txt', 'pyproject.toml'))."""
        pass

    @abstractmethod
    def get_package_markers(self) -> tuple[str, ...]:
        """Returns package name strings in manifests triggering detection (e.g. ('flask',))."""
        pass

    @abstractmethod
    def get_import_markers(self) -> tuple[str, ...]:
        """Returns import module strings in AST/IR triggering detection (e.g. ('flask',))."""
        pass
