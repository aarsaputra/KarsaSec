"""Built-in Framework Plugin Loader."""

from __future__ import annotations

from karsasec.framework.registry import framework_registry
from karsasec.plugins.frameworks.base import FrameworkPlugin
from karsasec.plugins.frameworks.django.plugin import DjangoPlugin
from karsasec.plugins.frameworks.express.plugin import ExpressPlugin
from karsasec.plugins.frameworks.fastapi.plugin import FastAPIPlugin
from karsasec.plugins.frameworks.flask.plugin import FlaskPlugin
from karsasec.plugins.frameworks.gin.plugin import GinPlugin
from karsasec.plugins.frameworks.laravel.plugin import LaravelPlugin
from karsasec.plugins.frameworks.nextjs.plugin import NextJsPlugin

BUILTIN_PLUGINS: tuple[FrameworkPlugin, ...] = (
    FlaskPlugin(),
    DjangoPlugin(),
    FastAPIPlugin(),
    ExpressPlugin(),
    NextJsPlugin(),
    LaravelPlugin(),
    GinPlugin(),
)


def register_builtin_plugins() -> None:
    """Registers all built-in framework plugins into global framework_registry."""
    for plugin in BUILTIN_PLUGINS:
        framework_registry.register(plugin.get_definition())


# Auto-register on import
register_builtin_plugins()
