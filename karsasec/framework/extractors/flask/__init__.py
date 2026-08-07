"""Flask Framework Semantic Intelligence Package."""

from karsasec.framework.extractors.flask.collector import FlaskRouteCollector
from karsasec.framework.extractors.flask.normalizer import FlaskRouteNormalizer
from karsasec.framework.extractors.flask.routes import FlaskRouteExtractor
from karsasec.framework.extractors.flask.state import FlaskSemanticState
from karsasec.framework.extractors.registry import extractor_registry

# Auto-register FlaskRouteExtractor singleton
flask_route_extractor = FlaskRouteExtractor()
extractor_registry.register(flask_route_extractor)

__all__ = [
    "FlaskRouteExtractor",
    "FlaskSemanticState",
    "FlaskRouteCollector",
    "FlaskRouteNormalizer",
    "flask_route_extractor",
]
