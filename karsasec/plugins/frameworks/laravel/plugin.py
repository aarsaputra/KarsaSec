"""Laravel Framework Plugin Implementation."""

from __future__ import annotations

from karsasec.framework.capabilities import FRAMEWORK_CAPABILITIES_MAP
from karsasec.framework.models import FrameworkDefinition, FrameworkType
from karsasec.plugins.frameworks.base import FrameworkPlugin


class LaravelPlugin(FrameworkPlugin):
    """Plugin definition for Laravel PHP framework."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.LARAVEL

    def get_definition(self) -> FrameworkDefinition:
        return FrameworkDefinition(
            id="LARAVEL",
            name="Laravel",
            language="PHP",
            supported_versions=("8.x", "9.x", "10.x", "11.x"),
            capabilities=FRAMEWORK_CAPABILITIES_MAP[FrameworkType.LARAVEL],
            default_entrypoints=("public/index.php", "artisan"),
            default_config_files=("composer.json", ".env", "config/app.php"),
        )

    def get_manifest_names(self) -> tuple[str, ...]:
        return ("composer.json", "composer.lock")

    def get_package_markers(self) -> tuple[str, ...]:
        return ("laravel/framework", "illuminate/support")

    def get_import_markers(self) -> tuple[str, ...]:
        return ("Illuminate\\Support", "Illuminate\\Routing", "Illuminate\\Http")
