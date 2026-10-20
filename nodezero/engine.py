"""Engagement orchestrator.

:class:`Engagement` ties authorization, audit logging, module execution, and
AI advisory together into one entry point. This is the only object outside
``modules/base.py`` that is expected to call module ``run()`` — keeping a
single choke point makes it easy to confirm the authorization gate can't be
bypassed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from nodezero.ai.advisor import Advisory, get_advisor
from nodezero.audit import AuditLog
from nodezero.authorization import EngagementAuthorization
from nodezero.findings import Finding
from nodezero.modules import ALL_MODULES
from nodezero.modules.base import Module


@dataclass
class EngagementResult:
    findings: list[Finding] = field(default_factory=list)
    advisory: Advisory | None = None


class Engagement:
    """Runs a set of modules against an authorized scope and collects results."""

    def __init__(self, authorization: EngagementAuthorization, audit_path: str | Path):
        self.authorization = authorization
        self.audit = AuditLog(audit_path)
        self.authorization.validate()  # fail fast and loud, before anything else
        self.audit.record(
            "engagement_start",
            engagement_name=authorization.engagement_name,
            authorized_by=authorization.authorized_by,
            scope=authorization.scope.describe(),
        )

    def available_modules(self) -> dict[str, type[Module]]:
        return dict(ALL_MODULES)

    def run(
        self,
        targets: list[str],
        module_names: list[str] | None = None,
        include_intrusive: bool = False,
        use_ai: bool = True,
    ) -> EngagementResult:
        """Run the requested modules against ``targets`` and summarize results.

        Args:
            targets: Hosts/IPs to assess. Each is checked against the active
                authorization + scope before any module touches it.
            module_names: Which modules to run (default: all non-intrusive
                built-ins).
            include_intrusive: Must be explicitly set True to run any module
                flagged ``intrusive``. There are no intrusive built-in
                modules yet; this flag exists for future extension and is
                intentionally conservative.
            use_ai: Whether to prefer an AI-generated executive summary over
                the offline heuristic one (requires ANTHROPIC_API_KEY).
        """
        module_classes = (
            [ALL_MODULES[n] for n in module_names] if module_names else list(ALL_MODULES.values())
        )
        module_classes = [m for m in module_classes if include_intrusive or not m.intrusive]

        findings: list[Finding] = []
        for module_cls in module_classes:
            module = module_cls(self.authorization, self.audit)
            findings.extend(module.run(targets))

        advisor = get_advisor(prefer_ai=use_ai)
        advisory = advisor.summarize(findings)
        self.audit.record(
            "ai_suggestion", generated_by=advisory.generated_by, finding_count=len(findings)
        )
        self.audit.record("engagement_end", finding_count=len(findings))

        return EngagementResult(findings=findings, advisory=advisory)
