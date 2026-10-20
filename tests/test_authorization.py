import datetime as dt

import pytest

from nodezero.authorization import AuthorizationError, EngagementAuthorization
from nodezero.scope import OutOfScopeError, Scope


def _auth(**overrides):
    now = dt.datetime.utcnow()
    defaults = dict(
        engagement_name="Test Engagement",
        authorized_by="Jane Doe, CISO",
        scope=Scope(allow=["10.0.0.0/24"]),
        starts_at=now - dt.timedelta(hours=1),
        ends_at=now + dt.timedelta(days=1),
        attestation_accepted=True,
    )
    defaults.update(overrides)
    return EngagementAuthorization(**defaults)


def test_requires_attestation():
    auth = _auth(attestation_accepted=False)
    with pytest.raises(AuthorizationError):
        auth.validate()


def test_requires_window_started():
    now = dt.datetime.utcnow()
    auth = _auth(starts_at=now + dt.timedelta(days=1), ends_at=now + dt.timedelta(days=2))
    with pytest.raises(AuthorizationError):
        auth.validate()


def test_requires_window_not_expired():
    now = dt.datetime.utcnow()
    auth = _auth(starts_at=now - dt.timedelta(days=2), ends_at=now - dt.timedelta(days=1))
    with pytest.raises(AuthorizationError):
        auth.validate()


def test_valid_authorization_passes():
    auth = _auth()
    auth.validate()  # does not raise


def test_target_must_be_in_scope():
    auth = _auth()
    with pytest.raises(OutOfScopeError):
        auth.assert_target_allowed("8.8.8.8")
    auth.assert_target_allowed("10.0.0.5")  # does not raise


def test_roundtrip_save_load(tmp_path):
    auth = _auth()
    path = tmp_path / "engagement.json"
    auth.save(path)
    loaded = EngagementAuthorization.load(path)
    assert loaded.engagement_name == auth.engagement_name
    assert loaded.scope.allow == auth.scope.allow
    loaded.validate()
