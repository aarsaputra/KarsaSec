"""Django Framework Plugin Implementation."""

from __future__ import annotations

from karsasec.framework.capabilities import FRAMEWORK_CAPABILITIES_MAP
from karsasec.framework.models import FrameworkDefinition, FrameworkType
from karsasec.plugins.frameworks.base import FrameworkPlugin


class DjangoPlugin(FrameworkPlugin):
    """Plugin definition for Django web framework."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.DJANGO

    def get_definition(self) -> FrameworkDefinition:
        return FrameworkDefinition(
            id="DJANGO",
            name="Django",
            language="Python",
            supported_versions=("3.x", "4.x", "5.x"),
            capabilities=FRAMEWORK_CAPABILITIES_MAP[FrameworkType.DJANGO],
            default_entrypoints=("manage.py", "wsgi.py", "asgi.py"),
            default_config_files=("settings.py", "settings/base.py"),
        )

    def get_manifest_names(self) -> tuple[str, ...]:
        return ("requirements.txt", "pyproject.toml", "Pipfile")

    def get_package_markers(self) -> tuple[str, ...]:
        return ("django", "Django")

    def get_import_markers(self) -> tuple[str, ...]:
        return ("django", "django.db", "django.http", "django.urls")
