"""The scanner adapter interface.

Every attack tool implements this: run against a target, return normalized Findings.
The rest of the harness never imports a tool directly — only this interface — so tools
are swappable and the report layer stays tool-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from harness.schema import Finding


class ScannerAdapter(ABC):
    """Base class for all attack-tool adapters."""

    #: short tool name recorded on every Finding, e.g. "promptfoo"
    name: str = "base"

    @abstractmethod
    def run(self, target: str) -> list[Finding]:
        """Run the tool against ``target`` and return normalized findings.

        ``target`` is a label identifying the model under test (e.g.
        ``"ollama:chat:llama3.2:3b"``). Adapters that get their provider from a
        tool-specific config still record this label on each Finding for traceability.
        """
        raise NotImplementedError
