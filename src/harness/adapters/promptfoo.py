"""promptfoo adapter.

promptfoo is a Node CLI, so this adapter shells out to it, tells it to write JSON,
and normalizes that JSON into Finding records.

Semantics that matter: in promptfoo a test "succeeds" when its assertions pass, i.e.
the model behaved as we required (it did NOT leak / did NOT comply with the attack).
So promptfoo success == the model RESISTED == Result.PASS (no vulnerability).
A promptfoo failure == the attack worked == Result.FAIL (a finding). Do not flip this.

NOTE (M0): promptfoo's output JSON shape has drifted across versions. The parser below
is deliberately defensive and the raw output is saved alongside the report so we can
verify the shape against a real run and tighten this. See BUILD-PLAN M0.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from harness.adapters.base import ScannerAdapter
from harness.schema import Finding, Result, Severity


class PromptfooError(RuntimeError):
    pass


class PromptfooAdapter(ScannerAdapter):
    name = "promptfoo"

    def __init__(self, config_path: str | Path, binary: str = "npx") -> None:
        self.config_path = Path(config_path)
        # Default to `npx promptfoo`; override with binary="promptfoo" if globally installed.
        self.binary = binary

    # -- running -----------------------------------------------------------------

    def run(self, target: str, raw_out: str | Path | None = None) -> list[Finding]:
        if not self.config_path.exists():
            raise PromptfooError(f"promptfoo config not found: {self.config_path}")

        out_path = Path(raw_out) if raw_out else Path(tempfile.mkstemp(suffix=".json")[1])

        if self.binary == "npx":
            cmd = ["npx", "-y", "promptfoo@latest", "eval"]
        else:
            cmd = [self.binary, "eval"]
        cmd += ["-c", str(self.config_path), "-o", str(out_path), "--no-cache"]

        env = {
            **os.environ,
            "PROMPTFOO_DISABLE_TELEMETRY": "1",
            "PROMPTFOO_DISABLE_UPDATE": "1",
        }

        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        # promptfoo exits non-zero when tests fail — which for us is normal (findings!).
        # So don't treat a non-zero exit as an error; only treat a missing/empty output as one.
        if not out_path.exists() or out_path.stat().st_size == 0:
            raise PromptfooError(
                "promptfoo produced no output.\n"
                f"cmd: {' '.join(cmd)}\n"
                f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
            )

        raw = json.loads(out_path.read_text())
        return self._normalize(raw, target)

    # -- normalizing -------------------------------------------------------------

    @staticmethod
    def _extract_results(raw: dict) -> list[dict]:
        """Find the per-test result list across promptfoo output shapes."""
        results = raw.get("results")
        if isinstance(results, dict) and isinstance(results.get("results"), list):
            return results["results"]
        if isinstance(results, list):
            return results
        return []

    @staticmethod
    def _provider_id(r: dict, fallback: str) -> str:
        """promptfoo records the provider per result; shape is a string id or {id,label}."""
        prov = r.get("provider")
        if isinstance(prov, dict):
            return prov.get("id") or prov.get("label") or fallback
        if isinstance(prov, str):
            return prov
        return fallback

    def _normalize(self, raw: dict, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, r in enumerate(self._extract_results(raw)):
            test_case = r.get("testCase") or {}
            meta = test_case.get("metadata") or r.get("metadata") or {}

            # The adapter no longer decides pass/fail — detection is the harness's job
            # (see harness.detectors). We only capture what the model returned. The detector
            # suite fills in `result`, `evidence`, and `detectors` downstream.
            response_obj = r.get("response") or {}
            response = response_obj.get("output") or r.get("output") or ""

            prompt = r.get("prompt")
            if isinstance(prompt, dict):
                prompt = prompt.get("raw") or prompt.get("label") or json.dumps(prompt)
            elif prompt is None:
                prompt = json.dumps(test_case.get("vars") or {})

            severity_raw = str(meta.get("severity", "medium")).lower()
            try:
                severity = Severity(severity_raw)
            except ValueError:
                severity = Severity.MEDIUM

            findings.append(
                Finding(
                    id=str(meta.get("id", f"PF-{i + 1:03d}")),
                    tool=self.name,
                    probe=test_case.get("description") or meta.get("category", "unknown"),
                    category=str(meta.get("category", "unknown")),
                    severity=severity,
                    result=Result.ERROR,  # provisional; the detector suite sets the real verdict
                    owasp_llm=meta.get("owasp_llm"),
                    atlas_technique=meta.get("atlas"),
                    prompt=str(prompt),
                    response=str(response),
                    evidence="",
                    target=self._provider_id(r, target),
                )
            )
        return findings
