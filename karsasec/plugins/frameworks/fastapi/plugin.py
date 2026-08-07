"""FastAPI Framework Plugin Implementation."""

from __future__ import annotations

from karsasec.framework.capabilities import FRAMEWORK_CAPABILITIES_MAP
from karsasec.framework.models import FrameworkDefinition, FrameworkType
from karsasec.plugins.frameworks.base import FrameworkPlugin


class FastAPIPlugin(FrameworkPlugin):
    """Plugin definition for FastAPI web framework."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.FASTAPI

    def get_definition(self) -> FrameworkDefinition:
        return FrameworkDefinition(
            id="FASTAPI",
            name="FastAPI",
            language="Python",
            supported_versions=("0.x", "1.x"),
            capabilities=FRAMEWORK_CAPABILITIES_MAP[FrameworkType.FASTAPI],
            default_entrypoints=("main.py", "app/main.py", "app.py"),
            default_config_files=("config.py", ".env"),
        )

    def get_manifest_names(self) -> tuple[str, ...]:
        return ("requirements.txt", "pyproject.toml", "Pipfile")

    def get_package_markers(self) -> tuple[str, ...]:
        return ("fastapi", "FastAPI")

    def get_import_markers(self) -> tuple[str, ...]:
        return ("fastapi", "fastapi.routing", "fastapi.params")
