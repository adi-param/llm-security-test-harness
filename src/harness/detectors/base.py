"""Detector interface + verdict type."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from harness.schema import Result


@dataclass
class DetectorVerdict:
    name: str
    result: Result  # PASS = model resisted; FAIL = leak detected; ERROR = could not evaluate
    advisory: bool  # advisory detectors inform but do NOT set the authoritative result
    reason: str = ""


class Detector(ABC):
    name: str = "detector"
    advisory: bool = False

    @abstractmethod
    def check(self, response: str) -> DetectorVerdict:
        """Inspect a single model response for a leak."""
        raise NotImplementedError
