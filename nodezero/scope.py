"""Target scope enforcement.

The :class:`Scope` object is the single authority on whether a given target is
allowed to be touched. Every module *must* call :meth:`Scope.assert_in_scope`
before sending a single packet to a target. Targets may be given as individual
hostnames, IPv4/IPv6 addresses, or CIDR networks. Hostnames are matched
literally (optionally with a leading ``*.`` wildcard for subdomains); IPs are
matched by membership in the allowed networks.

A deny-list always wins over the allow-list, so an operator can carve explicit
exclusions (e.g. a shared gateway, a production DB) out of an allowed range.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


class OutOfScopeError(Exception):
    """Raised when an operation targets a host outside the authorized scope."""


def _is_ip_or_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


@dataclass
class Scope:
    """An allow/deny list of targets for a single engagement.

    Args:
        allow: Hosts, IPs, or CIDRs that are in scope.
        deny: Hosts, IPs, or CIDRs explicitly excluded (takes precedence).
    """

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    _allow_networks: list = field(default_factory=list, init=False, repr=False)
    _allow_hosts: list[str] = field(default_factory=list, init=False, repr=False)
    _deny_networks: list = field(default_factory=list, init=False, repr=False)
    _deny_hosts: list[str] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._compile()

    def _compile(self) -> None:
        self._allow_networks, self._allow_hosts = self._split(self.allow)
        self._deny_networks, self._deny_hosts = self._split(self.deny)
        if not self.allow:
            raise ValueError(
                "Scope must declare at least one allowed target. An empty scope "
                "is refused so the tool can never be pointed at an arbitrary host."
            )

    @staticmethod
    def _split(entries: list[str]):
        networks, hosts = [], []
        for raw in entries:
            entry = raw.strip()
            if not entry:
                continue
            if _is_ip_or_network(entry):
                networks.append(ipaddress.ip_network(entry, strict=False))
            else:
                hosts.append(_normalize_host(entry))
        return networks, hosts

    @staticmethod
    def _host_matches(target: str, patterns: list[str]) -> bool:
        target = _normalize_host(target)
        for pattern in patterns:
            if pattern.startswith("*."):
                suffix = pattern[1:]  # keep the leading dot
                if target == pattern[2:] or target.endswith(suffix):
                    return True
            elif target == pattern:
                return True
        return False

    def _ip_in(self, target: str, networks: list) -> bool:
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False
        return any(addr in net for net in networks)

    def is_in_scope(self, target: str) -> bool:
        """Return True if ``target`` is allowed and not explicitly denied."""
        target = target.strip()
        if not target:
            return False

        # Deny list wins unconditionally.
        if self._ip_in(target, self._deny_networks):
            return False
        if self._host_matches(target, self._deny_hosts):
            return False

        if self._ip_in(target, self._allow_networks):
            return True
        if self._host_matches(target, self._allow_hosts):
            return True
        return False

    def assert_in_scope(self, target: str) -> None:
        """Raise :class:`OutOfScopeError` unless ``target`` is in scope."""
        if not self.is_in_scope(target):
            raise OutOfScopeError(
                f"Target {target!r} is not within the authorized engagement scope. "
                f"Refusing to act. Add it to the engagement 'allow' list if you are "
                f"authorized to test it."
            )

    def describe(self) -> str:
        allow = ", ".join(self.allow) or "(none)"
        deny = ", ".join(self.deny) or "(none)"
        return f"allow=[{allow}] deny=[{deny}]"
