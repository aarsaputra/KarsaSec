"""Unit tests for karsasec.server.config."""

from __future__ import annotations

from karsasec.server.config import ServerSettings


class TestServerSettings:
    def test_default_host_is_loopback(self):
        cfg = ServerSettings()
        assert cfg.host == "127.0.0.1"

    def test_default_port(self):
        cfg = ServerSettings()
        assert cfg.port == 8000

    def test_api_prefix(self):
        cfg = ServerSettings()
        assert cfg.api_prefix == "/api/v1"

    def test_debug_defaults_false(self):
        cfg = ServerSettings()
        assert cfg.debug is False

    def test_cors_origins_defaults_to_star(self):
        cfg = ServerSettings()
        assert "*" in cfg.cors_origins
