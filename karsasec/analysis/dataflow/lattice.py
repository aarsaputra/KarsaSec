"""Data Flow Monotone Framework Lattice definition and meet operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LatticeElement:
    """Represents a value in a Data Flow analysis lattice."""

    is_top: bool = False
    is_bottom: bool = False
    value: Any = None

    @classmethod
    def top(cls) -> LatticeElement:
        return cls(is_top=True)

    @classmethod
    def bottom(cls) -> LatticeElement:
        return cls(is_bottom=True)

    @classmethod
    def constant(cls, val: Any) -> LatticeElement:
        return cls(value=val)

    def is_constant(self) -> bool:
        return not self.is_top and not self.is_bottom and self.value is not None


class DataFlowLattice:
    """Monotone Framework Lattice solver performing meet (⊓) operations."""

    @staticmethod
    def meet(elem1: LatticeElement, elem2: LatticeElement) -> LatticeElement:
        """Computes the meet (greatest lower bound) of two lattice elements."""
        if elem1.is_top:
            return elem2
        if elem2.is_top:
            return elem1

        if elem1.is_bottom or elem2.is_bottom:
            return LatticeElement.bottom()

        if elem1.value == elem2.value:
            return elem1

        # Conflicting constant values -> collapse to BOTTOM
        return LatticeElement.bottom()
