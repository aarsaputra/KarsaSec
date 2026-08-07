"""Next.js Framework Plugin Implementation."""

from __future__ import annotations

from karsasec.framework.capabilities import FRAMEWORK_CAPABILITIES_MAP
from karsasec.framework.models import FrameworkDefinition, FrameworkType
from karsasec.plugins.frameworks.base import FrameworkPlugin


class NextJsPlugin(FrameworkPlugin):
    """Plugin definition for Next.js web framework."""

    @property
    def framework_type(self) -> FrameworkType:
        return FrameworkType.NEXTJS

    def get_definition(self) -> FrameworkDefinition:
        return FrameworkDefinition(
            id="NEXTJS",
            name="Next.js",
            language="JavaScript",
            supported_versions=("12.x", "13.x", "14.x", "15.x"),
            capabilities=FRAMEWORK_CAPABILITIES_MAP[FrameworkType.NEXTJS],
            default_entrypoints=("pages/index.js", "app/page.tsx", "pages/api"),
            default_config_files=("next.config.js", "next.config.mjs"),
        )

    def get_manifest_names(self) -> tuple[str, ...]:
        return ("package.json",)

    def get_package_markers(self) -> tuple[str, ...]:
        return ("next",)

    def get_import_markers(self) -> tuple[str, ...]:
        return ("next", "next/router", "next/navigation", "next/server")
