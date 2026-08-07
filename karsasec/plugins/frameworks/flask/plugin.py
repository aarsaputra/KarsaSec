"""Flask Framework Plugin Implementation."""

from __future__ import annotations

from karsasec.framework.capabilities import FRAMEWORK_CAPABILITIES_MAP
from karsasec.framework.models import FrameworkDefinition, FrameworkType
from karsasec.plugins.frameworks.base import FrameworkPlugin


class FlaskPlugin(FrameworkPlugin):
    """Plugin definition for Flask web framework."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.FLASK

    def get_definition(self) -> FrameworkDefinition:
        return FrameworkDefinition(
            id="FLASK",
            name="Flask",
            language="Python",
            supported_versions=("2.x", "3.x"),
            capabilities=FRAMEWORK_CAPABILITIES_MAP[FrameworkType.FLASK],
            default_entrypoints=("app.py", "wsgi.py", "main.py"),
            default_config_files=("config.py", "settings.py", ".env"),
        )

    def get_manifest_names(self) -> tuple[str, ...]:
        return ("requirements.txt", "pyproject.toml", "Pipfile")

    def get_package_markers(self) -> tuple[str, ...]:
        return ("flask", "Flask")

    def get_import_markers(self) -> tuple[str, ...]:
        return ("flask", "flask.views", "flask.blueprints")
