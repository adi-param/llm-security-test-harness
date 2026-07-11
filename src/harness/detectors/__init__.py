"""Detectors: the harness's own detection layer.

Detection lives HERE, not inside any attack tool, so the same detectors + disagreement
analysis apply to responses captured from any adapter (promptfoo, garak, PyRIT). This is
the analysis layer that makes the project a harness rather than a single-tool wrapper.

Detectors are either RELIABLE (deterministic, decide the authoritative verdict) or ADVISORY
(e.g. an LLM judge — informative but not trusted to set the verdict; reported for review).
"""
