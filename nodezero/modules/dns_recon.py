"""Passive DNS reconnaissance using only standard resolver queries.

No zone transfers, no brute-force subdomain enumeration against third-party
nameservers — just the records a normal client would resolve for a target
that's already in scope.
"""

from __future__ import annotations

import socket

from nodezero.findings import Finding, Severity
from nodezero.modules.base import Module


class DnsReconModule(Module):
    name = "dns_recon"
    description = "Resolve A/AAAA records for the target via the system resolver."
    intrusive = False

    def run_one(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            infos = socket.getaddrinfo(target, None)
        except socket.gaierror as exc:
            return [
                Finding(
                    module=self.name,
                    target=target,
                    title="DNS resolution failed",
                    severity=Severity.INFO,
                    detail=str(exc),
                )
            ]

        addresses = sorted({info[4][0] for info in infos})
        findings.append(
            Finding(
                module=self.name,
                target=target,
                title=f"Resolved {len(addresses)} address(es)",
                severity=Severity.INFO,
                detail=", ".join(addresses),
                evidence={"addresses": addresses},
            )
        )

        try:
            ptr_names = set()
            for addr in addresses:
                try:
                    name, _, _ = socket.gethostbyaddr(addr)
                    ptr_names.add(name)
                except (socket.herror, socket.gaierror):
                    continue
            if ptr_names:
                findings.append(
                    Finding(
                        module=self.name,
                        target=target,
                        title="Reverse DNS (PTR) records found",
                        severity=Severity.INFO,
                        detail=", ".join(sorted(ptr_names)),
                        evidence={"ptr_names": sorted(ptr_names)},
                    )
                )
        except OSError:
            pass

        return findings
