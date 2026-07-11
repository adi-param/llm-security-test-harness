"""Report / scoring layer. Tool-agnostic: reads only normalized Findings."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from harness.schema import Finding, Result, Severity

# Weights used only for a simple, transparent risk score. Draft; adi owns severity policy.
_SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 5,
    Severity.CRITICAL: 8,
}


def summarize(findings: list[Finding]) -> dict:
    total = len(findings)
    vulns = [f for f in findings if f.is_vulnerability]
    by_result = Counter(f.result.value for f in findings)
    by_severity = Counter(f.severity.value for f in vulns)  # severity of actual vulns
    risk_score = sum(_SEVERITY_WEIGHT[f.severity] for f in vulns)
    disagreements = [f for f in findings if f.disagreement]
    # Advisory judge flagged a leak the reliable detectors did NOT confirm (authoritative
    # result is "resisted"). These are candidates for human review — either a real semantic-only
    # leak, or a false positive from the advisory judge. Not counted as vulnerabilities.
    advisory_flags = [
        f
        for f in findings
        if f.detectors.get("semantic") == Result.FAIL.value and f.result is Result.PASS
    ]
    return {
        "total_attempts": total,
        "vulnerabilities": len(vulns),
        "resisted": by_result.get(Result.PASS.value, 0),
        "errors": by_result.get(Result.ERROR.value, 0),
        "by_severity": dict(by_severity),
        "risk_score": risk_score,
        "detector_disagreements": len(disagreements),
        "advisory_flags_for_review": len(advisory_flags),
    }


def summarize_by_target(findings: list[Finding]) -> dict[str, dict]:
    """Per-target summaries — makes multi-model runs a legible comparison."""
    targets = sorted({f.target for f in findings})
    return {t: summarize([f for f in findings if f.target == t]) for t in targets}


def write_json(findings: list[Finding], path: str | Path, target: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": target,
        "summary": summarize(findings),
        "by_target": summarize_by_target(findings),
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2))
    return path


def _md_escape(text: str, limit: int = 300) -> str:
    text = (text or "").replace("\n", " ").replace("|", "\\|").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def write_markdown(findings: list[Finding], path: str | Path, target: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    s = summarize(findings)

    by_target = summarize_by_target(findings)

    lines: list[str] = []
    lines.append("# LLM Security Test Harness — Findings Report")
    lines.append("")
    lines.append(f"**Targets:** {', '.join(f'`{t}`' for t in by_target) or f'`{target}`'}  ")
    lines.append(
        f"**Attempts:** {s['total_attempts']} · "
        f"**Vulnerabilities:** {s['vulnerabilities']} · "
        f"**Resisted:** {s['resisted']} · "
        f"**Errors:** {s['errors']} · "
        f"**Risk score:** {s['risk_score']}"
    )
    lines.append("")
    if s.get("detector_disagreements"):
        lines.append(
            f"> **Detector disagreement:** {s['detector_disagreements']} finding(s) where detectors "
            f"disagreed. Of these, {s['advisory_flags_for_review']} are advisory-judge flags NOT "
            f"confirmed by the reliable detectors — review as candidate false positives or "
            f"semantic-only leaks. Advisory flags do not count toward the vulnerability total."
        )
        lines.append("")

    # Detector-disagreement detail — the analysis payload. Shows every detector's verdict so the
    # reliable-vs-advisory split (and the advisory judge's error rate) is visible, not hidden.
    disagreements = [f for f in findings if f.disagreement]
    if disagreements:
        lines.append("## Detector disagreement")
        lines.append("")
        lines.append("| ID | Target | exact | normalized | semantic (advisory) | Verdict | Response (truncated) |")
        lines.append("|---|---|---|---|---|---|---|")
        for f in sorted(disagreements, key=lambda x: (x.target, x.id)):
            d = f.detectors
            lines.append(
                f"| {f.id} | `{f.target}` | {d.get('exact', '—')} | {d.get('normalized', '—')} | "
                f"{d.get('semantic', '—')} | {f.result.value} | {_md_escape(f.response, 100)} |"
            )
        lines.append("")

    # Per-target comparison
    if len(by_target) > 1:
        lines.append("## Results by target")
        lines.append("")
        lines.append("| Target | Attempts | Vulnerabilities | Resisted | Risk score |")
        lines.append("|---|---|---|---|---|")
        for t, ts in by_target.items():
            lines.append(
                f"| `{t}` | {ts['total_attempts']} | {ts['vulnerabilities']} | "
                f"{ts['resisted']} | {ts['risk_score']} |"
            )
        lines.append("")

    # Summary table by OWASP category
    lines.append("## Summary by OWASP LLM category")
    lines.append("")
    lines.append("| OWASP LLM | Attempts | Vulnerabilities |")
    lines.append("|---|---|---|")
    owasp_keys = sorted({f.owasp_llm or "unmapped" for f in findings})
    for key in owasp_keys:
        group = [f for f in findings if (f.owasp_llm or "unmapped") == key]
        vulns = sum(1 for f in group if f.is_vulnerability)
        lines.append(f"| {key} | {len(group)} | {vulns} |")
    lines.append("")

    # Detailed findings (vulnerabilities first)
    lines.append("## Findings")
    lines.append("")
    ordered = sorted(findings, key=lambda f: (not f.is_vulnerability, f.target, f.id))
    for f in ordered:
        status = "🔴 VULNERABLE" if f.is_vulnerability else (
            "🟢 resisted" if f.result is Result.PASS else "⚪ error"
        )
        lines.append(f"### {f.id} — {status}  (`{f.target}`)")
        lines.append("")
        lines.append(f"- **Tool:** {f.tool}")
        lines.append(f"- **Target:** {f.target}")
        if f.detectors:
            det = ", ".join(f"{k}={v}" for k, v in sorted(f.detectors.items()))
            disagree = " ⚠️ disagreement" if f.disagreement else ""
            lines.append(f"- **Detectors:** {det}{disagree}")
        lines.append(f"- **Category:** {f.category}")
        lines.append(f"- **Severity:** {f.severity.value}")
        lines.append(f"- **OWASP LLM:** {f.owasp_llm or '—'}")
        lines.append(f"- **MITRE ATLAS:** {f.atlas_technique or '—'}")
        lines.append(f"- **Probe:** {_md_escape(f.probe)}")
        lines.append(f"- **Prompt:** {_md_escape(f.prompt)}")
        lines.append(f"- **Response:** {_md_escape(f.response)}")
        if f.evidence:
            lines.append(f"- **Evidence:** {_md_escape(f.evidence)}")
        lines.append("")

    path.write_text("\n".join(lines))
    return path
