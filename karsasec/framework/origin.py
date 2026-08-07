"""Provenance tracking and OriginMetadata engine for Framework Semantic Layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Confidence(StrEnum):
    """Confidence levels for semantic extraction and framework detection."""
    CONFIDENT = "CONFIDENT"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"


@dataclass(frozen=True)
class SourceLocation:
    """Source code position tracking."""
    file_path: str = ""
    line: int = 1
    column: int = 0
    end_line: int = 1
    end_column: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceLocation:
        return cls(
            file_path=data.get("file_path", ""),
            line=data.get("line", 1),
            column=data.get("column", 0),
            end_line=data.get("end_line", 1),
            end_column=data.get("end_column", 0),
        )


@dataclass(frozen=True)
class Evidence:
    """Evidence snippet supporting semantic extraction."""
    snippet: str = ""
    rule_or_marker: str = ""
    file_path: str = ""
    line: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "snippet": self.snippet,
            "rule_or_marker": self.rule_or_marker,
            "file_path": self.file_path,
            "line": self.line,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        return cls(
            snippet=data.get("snippet", ""),
            rule_or_marker=data.get("rule_or_marker", ""),
            file_path=data.get("file_path", ""),
            line=data.get("line", 1),
        )


@dataclass(frozen=True)
class ExtractorInfo:
    """Information regarding the semantic extractor that produced an artifact."""
    extractor_name: str = "GenericExtractor"
    version: str = "1.0.0"
    framework: str = "GENERIC"

    def to_dict(self) -> dict[str, Any]:
        return {
            "extractor_name": self.extractor_name,
            "version": self.version,
            "framework": self.framework,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExtractorInfo:
        return cls(
            extractor_name=data.get("extractor_name", "GenericExtractor"),
            version=data.get("version", "1.0.0"),
            framework=data.get("framework", "GENERIC"),
        )


@dataclass(frozen=True)
class OriginMetadata:
    """Provenance metadata attached to semantic nodes and definitions."""
    extractor_info: ExtractorInfo = field(default_factory=ExtractorInfo)
    location_info: SourceLocation = field(default_factory=SourceLocation)
    confidence: Confidence = Confidence.CONFIDENT
    reason_str: str = "Extracted from source code AST/CPG"
    evidence_list: tuple[Evidence, ...] = ()
    parser_name: str = "TreeSitter"
    framework_name: str = "GENERIC"

    def reason(self) -> str:
        """Returns descriptive reason for extraction."""
        return self.reason_str

    def explain(self) -> str:
        """Returns human-readable explanation of origin."""
        loc = f"{self.location_info.file_path}:{self.location_info.line}" if self.location_info.file_path else "unknown location"
        return (
            f"Extracted by {self.extractor_info.extractor_name} (v{self.extractor_info.version}) "
            f"for {self.framework_name} framework at {loc} with {self.confidence.value} confidence. "
            f"Reason: {self.reason_str}"
        )

    def location(self) -> SourceLocation:
        """Returns SourceLocation."""
        return self.location_info

    def evidence(self) -> tuple[Evidence, ...]:
        """Returns evidence list."""
        return self.evidence_list

    def to_dict(self) -> dict[str, Any]:
        return {
            "extractor_info": self.extractor_info.to_dict(),
            "location_info": self.location_info.to_dict(),
            "confidence": self.confidence.value,
            "reason_str": self.reason_str,
            "evidence_list": [e.to_dict() for e in self.evidence_list],
            "parser_name": self.parser_name,
            "framework_name": self.framework_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OriginMetadata:
        conf_str = data.get("confidence", "CONFIDENT").upper()
        try:
            conf = Confidence(conf_str)
        except ValueError:
            conf = Confidence.CONFIDENT

        return cls(
            extractor_info=ExtractorInfo.from_dict(data.get("extractor_info", {})),
            location_info=SourceLocation.from_dict(data.get("location_info", {})),
            confidence=conf,
            reason_str=data.get("reason_str", "Extracted from source code AST/CPG"),
            evidence_list=tuple(Evidence.from_dict(e) for e in data.get("evidence_list", [])),
            parser_name=data.get("parser_name", "TreeSitter"),
            framework_name=data.get("framework_name", "GENERIC"),
        )
