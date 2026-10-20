import pytest

from nodezero.scope import OutOfScopeError, Scope


def test_empty_scope_rejected():
    with pytest.raises(ValueError):
        Scope(allow=[])


def test_ip_allow():
    scope = Scope(allow=["10.0.0.0/24"])
    assert scope.is_in_scope("10.0.0.5")
    assert not scope.is_in_scope("10.0.1.5")


def test_hostname_allow_exact():
    scope = Scope(allow=["app.example.test"])
    assert scope.is_in_scope("app.example.test")
    assert not scope.is_in_scope("other.example.test")


def test_hostname_wildcard():
    scope = Scope(allow=["*.example.test"])
    assert scope.is_in_scope("app.example.test")
    assert scope.is_in_scope("example.test")
    assert not scope.is_in_scope("example.org")


def test_deny_overrides_allow():
    scope = Scope(allow=["10.0.0.0/24"], deny=["10.0.0.5"])
    assert scope.is_in_scope("10.0.0.6")
    assert not scope.is_in_scope("10.0.0.5")


def test_assert_in_scope_raises():
    scope = Scope(allow=["10.0.0.0/24"])
    with pytest.raises(OutOfScopeError):
        scope.assert_in_scope("8.8.8.8")
    scope.assert_in_scope("10.0.0.1")  # does not raise
