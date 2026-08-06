"""KarsaSec Plugin SDK and Versioned Analysis API.

Provides stable extension interfaces for third-party parsers, rule packs, custom reporters,
and AI extension modules.
"""

from karsasec.sdk.api import AnalysisAPIVersion, PluginManifest, PluginSDK

__all__ = [
    "PluginSDK",
    "PluginManifest",
    "AnalysisAPIVersion",
]
