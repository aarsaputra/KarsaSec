"""Gin Framework Plugin Implementation."""

from __future__ import annotations

from karsasec.framework.capabilities import FRAMEWORK_CAPABILITIES_MAP
from karsasec.framework.models import FrameworkDefinition, FrameworkType
from karsasec.plugins.frameworks.base import FrameworkPlugin


class GinPlugin(FrameworkPlugin):
    """Plugin definition for Gin Go web framework."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.GIN

    def get_definition(self) -> FrameworkDefinition:
        return FrameworkDefinition(
            id="GIN",
            name="Gin",
            language="Go",
            supported_versions=("1.x",),
            capabilities=FRAMEWORK_CAPABILITIES_MAP[FrameworkType.GIN],
            default_entrypoints=("main.go", "app.go"),
            default_config_files=("go.mod", "go.sum"),
        )

    def get_manifest_names(self) -> tuple[str, ...]:
        return ("go.mod", "go.sum")

    def get_package_markers(self) -> tuple[str, ...]:
        return ("github.com/gin-gonic/gin",)

    def get_import_markers(self) -> tuple[str, ...]:
        return ("github.com/gin-gonic/gin",)
