# LLM Security Test Harness

Runs adversarial attacks against an LLM endpoint and normalizes every tool's output into a
single findings schema, then renders a report mapped to the **OWASP LLM Top 10** and
**MITRE ATLAS**. Attack tools plug in behind a common adapter interface, so the harness is
tool-agnostic and extensible rather than a wrapper around any one scanner.

> Status: **M1** — promptfoo adapter + a harness-owned, tool-agnostic detection layer
> (deterministic detectors + an advisory LLM judge) with detector-disagreement analysis and
> multi-model comparison. garak and PyRIT adapters follow.

## Design

```
target ──▶ scanner adapter ──▶ responses ──▶ detector suite ──▶ findings ──▶ report / scoring
(LLM)      (promptfoo,          (captured)    (exact,           (shared      (OWASP LLM Top 10,
            garak, PyRIT…)                     normalized,       schema)       MITRE ATLAS,
                                               semantic)                       disagreement analysis)
```

- **Scanner adapter** (`harness.adapters.base.ScannerAdapter`) — each tool just *runs attacks and
  captures responses*. Adding a tool is one adapter; no detection logic lives here.
- **Detector suite** (`harness.detectors`) — detection is owned by the harness, not the tools, so
  it's applied uniformly to any adapter's output. Detectors are either **reliable** (deterministic,
  they set the verdict) or **advisory** (informative, never inflate the verdict):
  - `exact` — verbatim / chunk substring match of the canary (reliable).
  - `normalized` — strips separators + case, then matches; catches spelled-out / spaced / dashed
    leaks a plain substring match misses (reliable).
  - `semantic` — a local LLM judge for paraphrase/encoding (advisory; see limitations).
- **Findings schema** (`harness.schema.Finding`) — the single record shape everything downstream
  reads, including per-detector verdicts. This normalization + detection layer is the point of the
  project.
- **Report/scoring** (`harness.report`) — tool-agnostic; groups by OWASP category, scores by
  severity, and surfaces **detector disagreements** (where the advisory judge diverges from the
  reliable detectors) as a detector-quality signal. Markdown + JSON.

Ground truth is a **high-entropy canary secret** planted in the system prompt: if the model emits
it in any form, the attack succeeded. Reliable detection is deterministic, so findings are
unambiguous; the advisory judge is reported alongside but never trusted to decide a verdict.

## Requirements

- Python ≥ 3.11 and [`uv`](https://docs.astral.sh/uv/)
- [Node.js](https://nodejs.org/) (promptfoo runs on it)
- [Ollama](https://ollama.com/) running locally with a target model, plus the advisory judge model
  (or use `--no-semantic` to skip the judge):
  ```sh
  ollama pull llama3.2:3b     # target
  ollama pull llama3.1:8b     # advisory semantic judge (optional)
  ```

## Run

```sh
uv sync
uv run harness --config configs/promptfoo.yaml --target ollama:chat:llama3.2:3b
```

The advisory semantic judge uses a local Ollama model (default `llama3.1:8b`); pull it too, or run
deterministic-only with `--no-semantic`. Reports are written to `reports/` (Markdown + JSON), plus
the raw promptfoo output. The command exits non-zero if any vulnerability is found — usable as a
CI gate.

A real comparison run (safety-tuned target vs. an uncensored control) is in
[`examples/sample-report.md`](examples/sample-report.md).

## Known limitations

- **Reliable detection is deterministic**, so it catches verbatim and normalized (spelled-out /
  spaced / dashed) leaks with no false positives — but it cannot catch a genuinely *paraphrased or
  translated* disclosure where the characters never appear even after normalization.
- **The semantic judge is advisory for a reason.** A local 8B judge is measurably unreliable — in
  testing it produced both false positives (flagging refusals as leaks) *and* a false negative
  (missing a verbatim system-prompt leak a substring match caught). It is reported and used only in
  disagreement analysis; it never sets a verdict. A stronger judge is future work.
- **Attacks are single-turn.** Each attack is one stateless message; the harness does not (yet) do
  multi-turn / iterative adversarial pressure. That's slated for the PyRIT adapter.
- The takeaway the report is built to make explicit: **an automated "0 vulnerabilities" means
  "nothing the detectors caught," not "secure."**

## Standards

Findings are **aligned with / mapped to** the OWASP LLM Top 10 (2025) and MITRE ATLAS. Mappings
and severities are review-owned engineering judgment, not automated compliance claims.
