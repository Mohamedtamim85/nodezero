"""Verifies modules cannot be run against out-of-scope targets — the core
safety property of the whole tool."""

import datetime as dt

import pytest

from nodezero.audit import AuditLog
from nodezero.authorization import EngagementAuthorization
from nodezero.findings import Finding, Severity
from nodezero.modules.base import Module
from nodezero.scope import OutOfScopeError, Scope


class _FakeModule(Module):
    name = "fake"
    description = "test double"

    def run_one(self, target):
        return [Finding(module=self.name, target=target, title="ok", severity=Severity.INFO)]


def _auth(tmp_path):
    now = dt.datetime.utcnow()
    return EngagementAuthorization(
        engagement_name="test",
        authorized_by="tester",
        scope=Scope(allow=["10.0.0.0/24"]),
        starts_at=now - dt.timedelta(hours=1),
        ends_at=now + dt.timedelta(days=1),
        attestation_accepted=True,
    )


def test_in_scope_target_runs(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    module = _FakeModule(_auth(tmp_path), audit)
    findings = module.run(["10.0.0.5"])
    assert len(findings) == 1


def test_out_of_scope_target_blocked(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    module = _FakeModule(_auth(tmp_path), audit)
    with pytest.raises(OutOfScopeError):
        module.run(["8.8.8.8"])


def test_expired_authorization_blocks_even_in_scope_target(tmp_path):
    now = dt.datetime.utcnow()
    auth = EngagementAuthorization(
        engagement_name="test",
        authorized_by="tester",
        scope=Scope(allow=["10.0.0.0/24"]),
        starts_at=now - dt.timedelta(days=2),
        ends_at=now - dt.timedelta(days=1),
        attestation_accepted=True,
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    module = _FakeModule(auth, audit)
    with pytest.raises(Exception):
        module.run(["10.0.0.5"])
