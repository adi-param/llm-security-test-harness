"""CLI entry point: run an adapter against a target, write reports, print a summary.

M0 wires the promptfoo adapter only. Later milestones register more adapters and let
you select which to run.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from harness.adapters.promptfoo import PromptfooAdapter
from harness.detectors.deterministic import ExactMatchDetector, NormalizedMatchDetector
from harness.detectors.semantic import SemanticJudgeDetector
from harness.detectors.suite import DetectorSuite
from harness.report import summarize, summarize_by_target, write_json, write_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="harness",
        description="Run adversarial attacks against an LLM endpoint and report findings.",
    )
    parser.add_argument(
        "--config",
        default="configs/promptfoo.yaml",
        help="Path to the promptfoo config (default: configs/promptfoo.yaml).",
    )
    parser.add_argument(
        "--target",
        default="ollama:chat:llama3.2:3b",
        help="Target label recorded on findings (the actual provider lives in the config).",
    )
    parser.add_argument(
        "--out-dir",
        default="reports",
        help="Directory to write the report + raw tool output (default: reports/).",
    )
    parser.add_argument(
        "--promptfoo-bin",
        default="npx",
        help='"npx" (default) or "promptfoo" if installed globally.',
    )
    parser.add_argument(
        "--scenario",
        default="configs/scenario.json",
        help="Detection scenario (canary secret + chunks). Default: configs/scenario.json.",
    )
    parser.add_argument(
        "--judge-model",
        default="llama3.1:8b",
        help="Ollama model for the advisory semantic detector (default: llama3.1:8b).",
    )
    parser.add_argument(
        "--judge-url",
        default="http://127.0.0.1:11434",
        help="Ollama base URL for the judge (default loopback IP, avoids the LAN prompt).",
    )
    parser.add_argument(
        "--no-semantic",
        action="store_true",
        help="Skip the advisory semantic judge (deterministic detectors only).",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = out_dir / f"promptfoo-raw-{stamp}.json"

    # 1. Capture: promptfoo sends the attacks and returns the raw model responses.
    adapter = PromptfooAdapter(args.config, binary=args.promptfoo_bin)
    # Which models get tested comes from the providers list in the config, not --target.
    print(f"[harness] running {adapter.name} using config {args.config} ...")
    findings = adapter.run(args.target, raw_out=raw_path)

    # 2. Detect: the harness's own detector suite decides the verdicts (tool-agnostic).
    canary = json.loads(Path(args.scenario).read_text())["canary"]
    detectors = [
        ExactMatchDetector(canary["secret"], canary.get("chunks", [])),
        NormalizedMatchDetector(canary["secret"]),
    ]
    if not args.no_semantic:
        detectors.append(
            SemanticJudgeDetector(canary["secret"], model=args.judge_model, base_url=args.judge_url)
        )
    print(f"[harness] detectors: {', '.join(d.name for d in detectors)}")
    DetectorSuite(detectors).evaluate(findings)

    json_path = write_json(findings, out_dir / f"report-{stamp}.json", args.target)
    md_path = write_markdown(findings, out_dir / f"report-{stamp}.md", args.target)

    s = summarize(findings)
    by_target = summarize_by_target(findings)
    print(f"[harness] targets tested: {', '.join(by_target) or '(none — no results)'}")
    for t, ts in by_target.items():
        print(
            f"[harness]   {t}: {ts['total_attempts']} attempts · "
            f"{ts['vulnerabilities']} vulns · {ts['resisted']} resisted · risk={ts['risk_score']}"
        )
    print(
        f"[harness] TOTAL: {s['total_attempts']} attempts · "
        f"{s['vulnerabilities']} vulnerabilities · "
        f"{s['resisted']} resisted · {s['errors']} errors · risk={s['risk_score']}"
    )
    if s.get("detector_disagreements"):
        print(
            f"[harness] detector disagreements: {s['detector_disagreements']} "
            f"({s['advisory_flags_for_review']} advisory-only flags for review — not counted as vulns)"
        )
    print(f"[harness] report:     {md_path}")
    print(f"[harness] report:     {json_path}")
    print(f"[harness] raw output: {raw_path}")

    # Non-zero exit if any vulnerability found — useful as a CI gate later.
    return 1 if s["vulnerabilities"] else 0


if __name__ == "__main__":
    sys.exit(main())
