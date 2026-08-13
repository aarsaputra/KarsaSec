"""Domain Error Hierarchy for RTP Subsystem (Sprint F0).

Defines explicit exceptions for RTP integrity, privacy, binding, freshness, and schema validation.
Strictly avoids leaking raw secrets or source code in exception error strings.
"""

from __future__ import annotations


class RTPError(Exception):
    """Base exception for all Remediation Transaction Package (RTP) errors."""


class RTPValidationError(RTPError):
    """Raised when RTP validation fails general structural or security constraints."""


class RTPIntegrityError(RTPValidationError):
    """Raised when cryptographic fingerprint commitments mismatch or tamper is detected."""


class RTPPrivacyError(RTPValidationError):
    """Raised when sensitive source code, diff text, or credentials violate the privacy boundary."""


class RTPSchemaError(RTPValidationError):
    """Raised when RTP schema version is unsupported or incompatible."""


class RTPBindingError(RTPValidationError):
    """Raised when finding, proposal, snapshot, provenance, or ledger cross-component binding fails."""


class RTPStaleVerificationError(RTPValidationError):
    """Raised when verification evidence is stale or bound to a different run/proposal/snapshot."""


class RTPSerializationError(RTPError):
    """Raised when RTP export, import, or canonical JSON conversion fails."""
