"""Shared finding/result data model used by every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """One observation produced by a module.

    Modules should report facts, not conclusions dressed up as facts — e.g.
    "port 22 open, OpenSSH 6.6.1 banner (released 2014)" rather than "server
    is vulnerable". The AI advisor layer is responsible for turning raw
    findings into risk narrative and remediation guidance.
    """

    module: str
    target: str
    title: str
    severity: Severity
    detail: str = ""
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "target": self.target,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
