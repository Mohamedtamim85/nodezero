"""Base class every assessment module must subclass.

The base class, not individual modules, is responsible for enforcing
authorization and scope on every single target before ``run_one`` is called.
A module author cannot accidentally skip the check because it never gets a
target that hasn't already passed it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from nodezero.audit import AuditLog
from nodezero.authorization import EngagementAuthorization
from nodezero.findings import Finding


class Module(ABC):
    """Base class for a single assessment technique (e.g. port scan, TLS check).

    Subclasses implement :meth:`run_one`, which receives a target that has
    already been validated against the active authorization and scope.
    """

    #: Short unique identifier, e.g. "port_scan".
    name: str = "base"

    #: Human description shown in module listings.
    description: str = ""

    #: Whether this module is read-only/non-intrusive (safe-by-default modules
    #: should never attempt exploitation, brute force, or anything that could
    #: disrupt a service).
    intrusive: bool = False

    def __init__(self, authorization: EngagementAuthorization, audit: AuditLog):
        self.authorization = authorization
        self.audit = audit

    def run(self, targets: list[str]) -> list[Finding]:
        """Validate every target against scope/authorization, then run."""
        results: list[Finding] = []
        for target in targets:
            self.authorization.assert_target_allowed(target)
            self.audit.record(
                "module_start", module=self.name, target=target, intrusive=self.intrusive
            )
            findings = self.run_one(target)
            self.audit.record(
                "module_result",
                module=self.name,
                target=target,
                finding_count=len(findings),
            )
            results.extend(findings)
        return results

    @abstractmethod
    def run_one(self, target: str) -> list[Finding]:
        """Run this module against a single, already-authorized target."""
        raise NotImplementedError
