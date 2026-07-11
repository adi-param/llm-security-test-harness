"""The normalized findings schema.

This is the contract every scanner adapter (promptfoo, garak, PyRIT, ...) normalizes
into. Because everything downstream — scoring, the report, OWASP/ATLAS grouping —
reads only this shape, adding a new tool is "write one adapter," not a rewrite.
This normalization layer is the core of the harness; keep it tool-agnostic.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    """How bad it is if this attack succeeds. Draft scale; adi owns severity calls."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Result(str, Enum):
    """Outcome of a single attack attempt against the target.

    PASS  = the model RESISTED the attack (good; no vulnerability).
    FAIL  = the attack SUCCEEDED (a vulnerability is present — this is a finding).
    ERROR = the attack could not be evaluated (tool/target error).
    """

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """One attack attempt, normalized. One record per (attack case x target)."""

    id: str  # stable id for the attack case, e.g. "PI-001"
    tool: str  # which adapter produced this, e.g. "promptfoo"
    probe: str  # the specific attack/probe name or description
    category: str  # attack class, e.g. "prompt-injection"
    severity: Severity
    result: Result
    owasp_llm: str | None = None  # e.g. "LLM01:2025 Prompt Injection"  (adi owns mapping)
    atlas_technique: str | None = None  # e.g. "AML.T0051 LLM Prompt Injection" (adi owns mapping)
    prompt: str = ""  # what was sent to the model
    response: str = ""  # what the model returned
    evidence: str = ""  # why the tool judged pass/fail (grader reason, matched string, ...)
    target: str = ""  # the target label, e.g. "ollama:chat:llama3.2:3b"
    # Per-detector verdicts, e.g. {"deterministic": "pass", "semantic": "fail"}. The overall
    # `result` is the worst case across these (a leak caught by ANY detector is a leak). Where
    # detectors disagree, that's the analysis signal — see `disagreement`.
    detectors: dict[str, str] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["result"] = self.result.value
        d["disagreement"] = self.disagreement
        return d

    @property
    def is_vulnerability(self) -> bool:
        return self.result is Result.FAIL

    @property
    def disagreement(self) -> bool:
        """True when the detectors that ran did not agree (e.g. substring says 'resisted' but
        the semantic grader says 'leaked' — the spelled-out/encoded case)."""
        verdicts = {v for v in self.detectors.values() if v in (Result.PASS.value, Result.FAIL.value)}
        return len(verdicts) > 1
