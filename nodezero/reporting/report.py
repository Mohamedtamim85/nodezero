"""Render engagement results as Markdown or JSON reports."""

from __future__ import annotations

import datetime as _dt
import json

from nodezero.authorization import EngagementAuthorization
from nodezero.engine import EngagementResult
from nodezero.findings import Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render_markdown(authorization: EngagementAuthorization, result: EngagementResult) -> str:
    lines = [
        f"# Security Assessment Report: {authorization.engagement_name}",
        "",
        f"- **Authorized by:** {authorization.authorized_by}",
        f"- **Scope:** {authorization.scope.describe()}",
        f"- **Window:** {authorization.starts_at} → {authorization.ends_at} (UTC)",
        f"- **Report generated:** {_dt.datetime.utcnow().isoformat()}Z",
        "",
        "## Executive Summary",
        "",
        result.advisory.executive_summary if result.advisory else "(no advisory generated)",
        "",
        "## Findings",
        "",
    ]

    by_target: dict[str, list] = {}
    for f in result.findings:
        by_target.setdefault(f.target, []).append(f)

    for target in sorted(by_target):
        lines.append(f"### {target}")
        lines.append("")
        target_findings = sorted(
            by_target[target], key=lambda f: SEVERITY_ORDER.index(f.severity)
        )
        for f in target_findings:
            emoji = SEVERITY_EMOJI.get(f.severity, "")
            lines.append(f"- {emoji} **[{f.severity.value.upper()}]** {f.title} _(module: {f.module})_")
            if f.detail:
                lines.append(f"  - {f.detail}")
            if f.recommendation:
                lines.append(f"  - **Recommendation:** {f.recommendation}")
        lines.append("")

    lines.append("---")
    lines.append(
        "_This report covers only the non-intrusive reconnaissance checks listed "
        "above, run against targets explicitly included in the authorized scope "
        "above. It is not a complete security assessment._"
    )
    return "\n".join(lines)


def render_json(authorization: EngagementAuthorization, result: EngagementResult) -> str:
    payload = {
        "engagement": authorization.to_dict(),
        "generated_at": _dt.datetime.utcnow().isoformat() + "Z",
        "executive_summary": result.advisory.executive_summary if result.advisory else None,
        "advisory_generated_by": result.advisory.generated_by if result.advisory else None,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2, default=str)
