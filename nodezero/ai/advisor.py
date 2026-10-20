"""AI advisor: turns raw findings into prioritized, plain-English guidance.

The advisor is strictly read-only with respect to the engagement: it never
decides what to scan or triggers new module runs on its own (no
"autonomous" pivoting against new hosts) — it only summarizes and
prioritizes findings that modules already produced against already-in-scope
targets. This keeps a human in the loop for anything beyond analysis.

Two backends:

* :class:`HeuristicAdvisor` — zero dependencies, zero network calls. Groups
  and ranks findings using the severity model already attached to each
  Finding. Always available.
* :class:`ClaudeAdvisor` — calls the Anthropic API (optional dependency) to
  produce a narrative executive summary and remediation guidance. Falls back
  to the heuristic advisor if no API key is configured.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from nodezero.findings import Finding, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Advisory:
    """AI-generated summary attached to a report."""

    executive_summary: str
    top_risks: list[Finding]
    generated_by: str


class HeuristicAdvisor:
    """Deterministic, offline advisor — no API key or network access needed."""

    name = "heuristic"

    def summarize(self, findings: list[Finding]) -> Advisory:
        ranked = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
        top = [f for f in ranked if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)][:10]

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        targets = sorted({f.target for f in findings})
        summary_lines = [
            f"Assessed {len(targets)} target(s), producing {len(findings)} findings.",
            "Severity breakdown: "
            + ", ".join(f"{sev}={counts.get(sev, 0)}" for sev in
                        ("critical", "high", "medium", "low", "info")),
        ]
        if top:
            summary_lines.append(
                "Highest-priority items to address first: "
                + "; ".join(f"[{f.severity.value}] {f.title} ({f.target})" for f in top[:5])
            )
        else:
            summary_lines.append("No medium-or-higher severity findings were identified.")

        return Advisory(
            executive_summary="\n".join(summary_lines),
            top_risks=top,
            generated_by=self.name,
        )


class ClaudeAdvisor:
    """Uses the Anthropic API to write a narrative summary over findings.

    Requires the ``anthropic`` package and an ``ANTHROPIC_API_KEY``. Falls
    back to :class:`HeuristicAdvisor` automatically if either is missing, so
    callers never need a try/except around this.
    """

    name = "claude"

    def __init__(self, model: str = "claude-sonnet-5-5"):
        self.model = model
        self._fallback = HeuristicAdvisor()

    def _client(self):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return None
        try:
            import anthropic  # type: ignore
        except ImportError:
            return None
        return anthropic.Anthropic()

    def summarize(self, findings: list[Finding]) -> Advisory:
        client = self._client()
        if client is None:
            return self._fallback.summarize(findings)

        base = self._fallback.summarize(findings)
        finding_lines = [
            f"- [{f.severity.value}] {f.target}: {f.title} — {f.detail}"
            for f in sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])[:40]
        ]
        prompt = (
            "You are assisting a human penetration tester in writing an "
            "engagement report. Below are raw technical findings from "
            "AUTHORIZED, non-intrusive reconnaissance modules (port scans, "
            "header checks, TLS inspection, DNS lookups) against systems the "
            "client has given written permission to test. Write a concise "
            "executive summary (4-8 sentences) for a non-technical "
            "stakeholder: overall risk posture, the 2-4 most important issues "
            "to fix first, and no action items beyond what the findings "
            "support. Do not invent findings not listed below.\n\n"
            + "\n".join(finding_lines)
        )
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(
                block.text for block in response.content if getattr(block, "type", "") == "text"
            ).strip()
        except Exception:
            return base

        return Advisory(
            executive_summary=text or base.executive_summary,
            top_risks=base.top_risks,
            generated_by=self.name,
        )


def get_advisor(prefer_ai: bool = True):
    """Return the best available advisor: Claude if configured, else heuristic."""
    if prefer_ai and os.environ.get("ANTHROPIC_API_KEY"):
        return ClaudeAdvisor()
    return HeuristicAdvisor()
