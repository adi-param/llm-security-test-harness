# LLM Security Test Harness

Runs adversarial attacks against an LLM endpoint and normalizes every tool's output into a
single findings schema, then renders a report mapped to the **OWASP LLM Top 10** and
**MITRE ATLAS**. Attack tools plug in behind a common adapter interface, so the harness is
tool-agnostic and extensible rather than a wrapper around any one scanner.

> Status: **M0** — a runnable vertical slice. One tool (promptfoo) wired end-to-end against a
> local model, producing a normalized report. garak and PyRIT adapters follow.

## Design

```
target ──▶ scanner adapter ──▶ normalize ──▶ findings (shared schema) ──▶ report / scoring
(LLM)      (promptfoo,                                                     (OWASP LLM Top 10
            garak, PyRIT…)                                                  + MITRE ATLAS)
```

- **Scanner adapter** (`harness.adapters.base.ScannerAdapter`) — each tool implements `run(target)`
  and returns normalized findings. Adding a tool is one adapter.
- **Findings schema** (`harness.schema.Finding`) — the single record shape everything downstream
  reads. This normalization layer is the point of the project.
- **Report/scoring** (`harness.report`) — tool-agnostic; groups by OWASP category, scores by
  severity, writes Markdown + JSON.

The M0 slice uses a **canary secret** planted in the system prompt: if the model ever emits it,
the attack succeeded. Deterministic string-match ground truth means findings are unambiguous.

## Requirements

- Python ≥ 3.11 and [`uv`](https://docs.astral.sh/uv/)
- [Node.js](https://nodejs.org/) (promptfoo runs on it)
- [Ollama](https://ollama.com/) running locally with a model pulled:
  ```sh
  ollama pull llama3.2:3b
  ```

## Run

```sh
uv sync
uv run harness --config configs/promptfoo.yaml --target ollama:chat:llama3.2:3b
```

Reports are written to `reports/` (Markdown + JSON), plus the raw promptfoo output for
traceability. The command exits non-zero if any vulnerability is found — usable as a CI gate.

## Standards

Findings are **aligned with / mapped to** the OWASP LLM Top 10 (2025) and MITRE ATLAS. Mappings
and severities are review-owned engineering judgment, not automated compliance claims.
