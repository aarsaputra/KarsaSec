"""Express.js Framework Plugin Implementation."""

from __future__ import annotations

from karsasec.framework.capabilities import FRAMEWORK_CAPABILITIES_MAP
from karsasec.framework.models import FrameworkDefinition, FrameworkType
from karsasec.plugins.frameworks.base import FrameworkPlugin


class ExpressPlugin(FrameworkPlugin):
    """Plugin definition for Express.js web framework."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.EXPRESS

    def get_definition(self) -> FrameworkDefinition:
        return FrameworkDefinition(
            id="EXPRESS",
            name="Express",
            language="JavaScript",
            supported_versions=("4.x", "5.x"),
            capabilities=FRAMEWORK_CAPABILITIES_MAP[FrameworkType.EXPRESS],
            default_entrypoints=("index.js", "app.js", "server.js", "src/index.js"),
            default_config_files=("package.json", ".env"),
        )

    def get_manifest_names(self) -> tuple[str, ...]:
        return ("package.json", "package-lock.json")

    def get_package_markers(self) -> tuple[str, ...]:
        return ("express",)

    def get_import_markers(self) -> tuple[str, ...]:
        return ("express", "express-router")
