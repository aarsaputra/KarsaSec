"""FrameworkGraphSerializer for JSON, Compressed JSON, MessagePack, and Binary Snapshot formats."""

from __future__ import annotations

import gzip
import json
import logging
import struct
from typing import Any

from karsasec.framework.semantic_models import (
    FrameworkSemanticGraph,
)

logger = logging.getLogger("karsasec.framework.serializer")


class SerializationError(Exception):
    """Exception raised for errors during graph serialization/deserialization."""
    pass


class FrameworkGraphSerializer:
    """Serializer supporting JSON, compressed JSON (gzip), MessagePack, and binary snapshot formats."""

    @staticmethod
    def to_dict(graph: FrameworkSemanticGraph) -> dict[str, Any]:
        """Converts graph into dictionary payload."""
        return graph.to_dict()

    @staticmethod
    def from_dict(data: dict[str, Any]) -> FrameworkSemanticGraph:
        """Parses graph from dictionary payload."""
        return FrameworkSemanticGraph.from_dict(data)

    @classmethod
    def to_json(cls, graph: FrameworkSemanticGraph, indent: int | None = None) -> str:
        """Serializes graph to JSON string."""
        data = cls.to_dict(graph)
        return json.dumps(data, indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, json_str: str) -> FrameworkSemanticGraph:
        """Deserializes graph from JSON string."""
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except Exception as exc:
            raise SerializationError(f"Failed to parse JSON graph: {exc}") from exc

    @classmethod
    def to_compressed_json(cls, graph: FrameworkSemanticGraph) -> bytes:
        """Serializes graph to gzip-compressed JSON bytes."""
        json_bytes = cls.to_json(graph).encode("utf-8")
        return gzip.compress(json_bytes)

    @classmethod
    def from_compressed_json(cls, compressed_bytes: bytes) -> FrameworkSemanticGraph:
        """Deserializes graph from gzip-compressed JSON bytes."""
        try:
            json_bytes = gzip.decompress(compressed_bytes)
            return cls.from_json(json_bytes.decode("utf-8"))
        except Exception as exc:
            raise SerializationError(f"Failed to decompress compressed JSON graph: {exc}") from exc

    @classmethod
    def to_msgpack(cls, graph: FrameworkSemanticGraph) -> bytes:
        """Serializes graph to MessagePack bytes (or fallback msgpack payload)."""
        data = cls.to_dict(graph)
        try:
            import msgpack
            return msgpack.packb(data, use_bin_type=True)
        except ImportError:
            logger.debug("msgpack package not installed; falling back to UTF-8 JSON bytes wrapper")
            return ("MSGPACK_FALLBACK:" + json.dumps(data, sort_keys=True)).encode("utf-8")

    @classmethod
    def from_msgpack(cls, msgpack_bytes: bytes) -> FrameworkSemanticGraph:
        """Deserializes graph from MessagePack bytes (or fallback payload)."""
        if msgpack_bytes.startswith(b"MSGPACK_FALLBACK:"):
            json_str = msgpack_bytes[len(b"MSGPACK_FALLBACK:"):].decode("utf-8")
            return cls.from_json(json_str)
        try:
            import msgpack
            data = msgpack.unpackb(msgpack_bytes, raw=False)
            return cls.from_dict(data)
        except Exception as exc:
            raise SerializationError(f"Failed to unpack MessagePack graph: {exc}") from exc

    @classmethod
    def to_binary(cls, graph: FrameworkSemanticGraph) -> bytes:
        """Serializes graph into custom high-speed binary snapshot format.

        Header: Magic (4B) + Version (2B) + Compressed JSON Length (4B) + Payload
        """
        magic = b"KSG1"
        version = 1
        compressed_payload = cls.to_compressed_json(graph)
        header = struct.pack(">4sHI", magic, version, len(compressed_payload))
        return header + compressed_payload

    @classmethod
    def from_binary(cls, binary_bytes: bytes) -> FrameworkSemanticGraph:
        """Deserializes graph from custom binary snapshot format."""
        if len(binary_bytes) < 10:
            raise SerializationError("Invalid binary snapshot length")

        magic, version, payload_len = struct.unpack(">4sHI", binary_bytes[:10])
        if magic != b"KSG1":
            raise SerializationError(f"Invalid binary snapshot magic header: {magic!r}")

        payload = binary_bytes[10:10 + payload_len]
        return cls.from_compressed_json(payload)
