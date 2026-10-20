"""Engagement authorization records.

Nothing in this tool runs against a target until an operator has created and
accepted an :class:`EngagementAuthorization` — a local, explicit record that
the operator asserts they have written permission to test the declared scope.
This is a *self-attestation* control, not a cryptographic one: it cannot stop
someone determined to misuse the tool, but it does mean there is no path to
running a scan without first typing out what you're authorized to do and for
how long. That one deliberate step, logged alongside every report, is the
point.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from nodezero.scope import Scope

REQUIRED_ATTESTATION = (
    "I confirm I have documented, written authorization to perform security "
    "testing against the systems listed in this engagement's scope, for the "
    "stated time window, and that this testing complies with applicable law "
    "and any rules of engagement agreed with the system owner."
)


class AuthorizationError(Exception):
    """Raised when an engagement authorization is missing, invalid, or expired."""


@dataclass
class EngagementAuthorization:
    """A local record of authorization for one engagement.

    Args:
        engagement_name: Human-readable label (e.g. "Acme Corp Q4 webapp test").
        authorized_by: Name/role of the person who granted authorization
            (e.g. "Jane Doe, CISO, Acme Corp").
        scope: The :class:`~nodezero.scope.Scope` this authorization covers.
        starts_at: When testing is permitted to begin.
        ends_at: When testing must stop.
        attestation_accepted: Must be True — the operator has read and
            accepted :data:`REQUIRED_ATTESTATION`.
        notes: Free-text rules-of-engagement notes (e.g. "no DoS", "no social
            engineering", "business hours only").
    """

    engagement_name: str
    authorized_by: str
    scope: Scope
    starts_at: _dt.datetime
    ends_at: _dt.datetime
    attestation_accepted: bool = False
    notes: str = ""
    created_at: _dt.datetime = field(default_factory=_dt.datetime.utcnow)

    def validate(self, now: _dt.datetime | None = None) -> None:
        """Raise :class:`AuthorizationError` if this authorization isn't active."""
        if not self.attestation_accepted:
            raise AuthorizationError(
                "The engagement authorization has not been accepted. The operator "
                f"must explicitly accept this attestation:\n\n  {REQUIRED_ATTESTATION}"
            )
        now = now or _dt.datetime.utcnow()
        if now < self.starts_at:
            raise AuthorizationError(
                f"Engagement window has not started yet (starts {self.starts_at} UTC)."
            )
        if now > self.ends_at:
            raise AuthorizationError(
                f"Engagement window has expired (ended {self.ends_at} UTC). "
                "Create a new authorization to continue testing."
            )

    def assert_target_allowed(self, target: str, now: _dt.datetime | None = None) -> None:
        """Validate the authorization window, then the scope, for ``target``."""
        self.validate(now=now)
        self.scope.assert_in_scope(target)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["scope"] = {"allow": self.scope.allow, "deny": self.scope.deny}
        d["starts_at"] = self.starts_at.isoformat()
        d["ends_at"] = self.ends_at.isoformat()
        d["created_at"] = self.created_at.isoformat()
        return d

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: str | Path) -> "EngagementAuthorization":
        data = json.loads(Path(path).read_text())
        scope = Scope(allow=data["scope"]["allow"], deny=data["scope"]["deny"])
        return cls(
            engagement_name=data["engagement_name"],
            authorized_by=data["authorized_by"],
            scope=scope,
            starts_at=_dt.datetime.fromisoformat(data["starts_at"]),
            ends_at=_dt.datetime.fromisoformat(data["ends_at"]),
            attestation_accepted=data["attestation_accepted"],
            notes=data.get("notes", ""),
            created_at=_dt.datetime.fromisoformat(data["created_at"]),
        )
