"""Flask Framework Semantic Intelligence Package."""

from karsasec.framework.extractors.flask.auth import (
    FlaskAuthCollector,
    FlaskAuthExtractor,
    FlaskAuthNormalizer,
    FlaskAuthState,
)
from karsasec.framework.extractors.flask.collector import FlaskRouteCollector
from karsasec.framework.extractors.flask.config import (
    FlaskConfigCollector,
    FlaskConfigExtractor,
    FlaskConfigNormalizer,
    FlaskConfigState,
)
from karsasec.framework.extractors.flask.controllers import (
    FlaskControllerCollector,
    FlaskControllerExtractor,
    FlaskControllerNormalizer,
    FlaskControllerState,
)
from karsasec.framework.extractors.flask.middleware import (
    FlaskMiddlewareCollector,
    FlaskMiddlewareExtractor,
    FlaskMiddlewareNormalizer,
    FlaskMiddlewareState,
)
from karsasec.framework.extractors.flask.normalizer import FlaskRouteNormalizer
from karsasec.framework.extractors.flask.routes import FlaskRouteExtractor
from karsasec.framework.extractors.flask.state import FlaskSemanticState
from karsasec.framework.extractors.registry import extractor_registry

# Auto-register Flask Extractor singletons
flask_route_extractor = FlaskRouteExtractor()
flask_middleware_extractor = FlaskMiddlewareExtractor()
flask_controller_extractor = FlaskControllerExtractor()
flask_config_extractor = FlaskConfigExtractor()
flask_auth_extractor = FlaskAuthExtractor()

extractor_registry.register(flask_route_extractor)
extractor_registry.register(flask_middleware_extractor)
extractor_registry.register(flask_controller_extractor)
extractor_registry.register(flask_config_extractor)
extractor_registry.register(flask_auth_extractor)

__all__ = [
    "FlaskRouteExtractor",
    "FlaskSemanticState",
    "FlaskRouteCollector",
    "FlaskRouteNormalizer",
    "FlaskMiddlewareExtractor",
    "FlaskMiddlewareState",
    "FlaskMiddlewareCollector",
    "FlaskMiddlewareNormalizer",
    "flask_middleware_extractor",
    "FlaskControllerExtractor",
    "FlaskControllerState",
    "FlaskControllerCollector",
    "FlaskControllerNormalizer",
    "flask_controller_extractor",
    "FlaskConfigExtractor",
    "FlaskConfigState",
    "FlaskConfigCollector",
    "FlaskConfigNormalizer",
    "flask_config_extractor",
    "FlaskAuthExtractor",
    "FlaskAuthState",
    "FlaskAuthCollector",
    "FlaskAuthNormalizer",
    "flask_auth_extractor",
]
