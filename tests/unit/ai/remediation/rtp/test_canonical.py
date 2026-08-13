"""Unit tests for Canonical Serialization Engine in RTP Subsystem (Sprint F0)."""

from __future__ import annotations

from enum import Enum
import pytest

from karsasec.ai.remediation.rtp.canonical import canonicalize, compute_canonical_hash
from karsasec.ai.remediation.rtp.errors import RTPSerializationError


class DummyEnum(Enum):
    ALPHA = "ALPHA"
    BETA = "BETA"


def test_canonicalize_dictionary_key_sorting() -> None:
    dict_a = {"z": 100, "a": 1, "m": 50}
    dict_b = {"a": 1, "m": 50, "z": 100}

    assert canonicalize(dict_a) == canonicalize(dict_b)
    assert compute_canonical_hash(dict_a) == compute_canonical_hash(dict_b)


def test_canonicalize_nested_dict_and_enum() -> None:
    data_1 = {
        "finding_id": "F-100",
        "status": DummyEnum.ALPHA,
        "metadata": {"cwe": "CWE-89", "severity": "HIGH"},
    }
    data_2 = {
        "metadata": {"severity": "HIGH", "cwe": "CWE-89"},
        "finding_id": "F-100",
        "status": "ALPHA",
    }

    assert canonicalize(data_1) == canonicalize(data_2)
    assert compute_canonical_hash(data_1) == compute_canonical_hash(data_2)


def test_canonicalize_set_sorting() -> None:
    set_a = {"cat", "apple", "banana"}
    set_b = {"apple", "banana", "cat"}

    assert canonicalize(set_a) == canonicalize(set_b)
    assert compute_canonical_hash(set_a) == compute_canonical_hash(set_b)


def test_canonicalize_unsupported_type_raises_error() -> None:
    class UnsupportedObject:
        pass

    with pytest.raises(RTPSerializationError, match="Unsupported non-canonical value type"):
        canonicalize(UnsupportedObject())
