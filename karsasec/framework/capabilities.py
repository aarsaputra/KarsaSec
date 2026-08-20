"""Capability matrix utilities for Framework Semantic Layer."""

from __future__ import annotations

from karsasec.framework.models import FrameworkCapability, FrameworkType

# Capability matrix mapping framework types to standard capabilities
FRAMEWORK_CAPABILITIES_MAP: dict[FrameworkType, tuple[FrameworkCapability, ...]] = {
    FrameworkType.FLASK: (
        FrameworkCapability.ROUTES,
        FrameworkCapability.MIDDLEWARE,
        FrameworkCapability.ORM,
        FrameworkCapability.TEMPLATE,
        FrameworkCapability.SESSION,
        FrameworkCapability.COOKIE,
        FrameworkCapability.CONFIG,
    ),
    FrameworkType.DJANGO: (
        FrameworkCapability.ROUTES,
        FrameworkCapability.MIDDLEWARE,
        FrameworkCapability.ORM,
        FrameworkCapability.TEMPLATE,
        FrameworkCapability.AUTH,
        FrameworkCapability.AUTHZ,
        FrameworkCapability.SESSION,
        FrameworkCapability.COOKIE,
        FrameworkCapability.CONFIG,
    ),
    FrameworkType.FASTAPI: (
        FrameworkCapability.ROUTES,
        FrameworkCapability.MIDDLEWARE,
        FrameworkCapability.ORM,
        FrameworkCapability.AUTH,
        FrameworkCapability.JWT,
        FrameworkCapability.CONFIG,
        FrameworkCapability.API,
    ),
    FrameworkType.EXPRESS: (
        FrameworkCapability.ROUTES,
        FrameworkCapability.MIDDLEWARE,
        FrameworkCapability.TEMPLATE,
        FrameworkCapability.SESSION,
        FrameworkCapability.COOKIE,
        FrameworkCapability.JWT,
        FrameworkCapability.CONFIG,
        FrameworkCapability.API,
    ),
    FrameworkType.NEXTJS: (
        FrameworkCapability.ROUTES,
        FrameworkCapability.MIDDLEWARE,
        FrameworkCapability.TEMPLATE,
        FrameworkCapability.CONFIG,
        FrameworkCapability.API,
    ),
    FrameworkType.LARAVEL: (
        FrameworkCapability.ROUTES,
        FrameworkCapability.MIDDLEWARE,
        FrameworkCapability.ORM,
        FrameworkCapability.TEMPLATE,
        FrameworkCapability.AUTH,
        FrameworkCapability.AUTHZ,
        FrameworkCapability.SESSION,
        FrameworkCapability.COOKIE,
        FrameworkCapability.CONFIG,
    ),
    FrameworkType.GIN: (
        FrameworkCapability.ROUTES,
        FrameworkCapability.MIDDLEWARE,
        FrameworkCapability.ORM,
        FrameworkCapability.CONFIG,
        FrameworkCapability.API,
    ),
    FrameworkType.GENERIC: (FrameworkCapability.CONFIG,),
}


def get_framework_capabilities(framework_type: FrameworkType | str) -> tuple[FrameworkCapability, ...]:
    """Returns capabilities associated with a given FrameworkType."""
    if isinstance(framework_type, str):
        try:
            framework_type = FrameworkType(framework_type.upper())
        except ValueError:
            framework_type = FrameworkType.GENERIC
    return FRAMEWORK_CAPABILITIES_MAP.get(framework_type, (FrameworkCapability.CONFIG,))


def has_capability(framework_type: FrameworkType | str, capability: FrameworkCapability | str) -> bool:
    """Checks if a given framework provides a specific capability."""
    caps = get_framework_capabilities(framework_type)
    if isinstance(capability, str):
        try:
            capability = FrameworkCapability(capability.upper())
        except ValueError:
            return False
    return capability in caps
