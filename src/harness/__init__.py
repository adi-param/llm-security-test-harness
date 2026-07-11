"""LLM Security Test Harness.

Runs adversarial attacks against an LLM endpoint via pluggable scanner adapters,
normalizes every tool's output into one findings schema, and renders a report
mapped to the OWASP LLM Top 10 and MITRE ATLAS.
"""

__version__ = "0.1.0"
