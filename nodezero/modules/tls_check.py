"""Passive TLS/certificate inspection (connect + handshake only, no probing)."""

from __future__ import annotations

import datetime as _dt
import socket
import ssl

from nodezero.findings import Finding, Severity
from nodezero.modules.base import Module

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_WARNING_DAYS = 30


class TlsCheckModule(Module):
    name = "tls_check"
    description = "Inspect the TLS certificate and negotiated protocol on port 443."
    intrusive = False

    def __init__(self, *args, port: int = 443, timeout: float = 5.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.port = port
        self.timeout = timeout

    def run_one(self, target: str) -> list[Finding]:
        ctx = ssl.create_default_context()
        # We want to *see* the cert even if validation would fail (expired,
        # self-signed, mismatched hostname) — that's the finding we're
        # reporting on, not the error to crash on.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((target, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as tls_sock:
                    cert_bin = tls_sock.getpeercert(binary_form=True)
                    cert = tls_sock.getpeercert()
                    protocol = tls_sock.version()
                    cipher = tls_sock.cipher()
        except (OSError, socket.timeout, ssl.SSLError) as exc:
            return [
                Finding(
                    module=self.name,
                    target=target,
                    title="TLS connection failed",
                    severity=Severity.INFO,
                    detail=f"Could not establish TLS on port {self.port}: {exc}",
                )
            ]

        findings: list[Finding] = [
            Finding(
                module=self.name,
                target=target,
                title=f"TLS negotiated: {protocol}",
                severity=Severity.HIGH if protocol in WEAK_PROTOCOLS else Severity.INFO,
                detail=f"Cipher: {cipher[0] if cipher else 'unknown'}",
                evidence={"protocol": protocol, "cipher": cipher},
                recommendation=(
                    f"{protocol} is deprecated and should be disabled server-side; "
                    "require TLS 1.2 or 1.3 only." if protocol in WEAK_PROTOCOLS else ""
                ),
            )
        ]

        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expiry = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - _dt.datetime.utcnow()).days
                    if days_left < 0:
                        findings.append(
                            Finding(
                                module=self.name,
                                target=target,
                                title="TLS certificate is expired",
                                severity=Severity.HIGH,
                                detail=f"Expired on {not_after} ({-days_left} days ago)",
                                recommendation="Renew the certificate immediately.",
                            )
                        )
                    elif days_left < EXPIRY_WARNING_DAYS:
                        findings.append(
                            Finding(
                                module=self.name,
                                target=target,
                                title="TLS certificate expiring soon",
                                severity=Severity.MEDIUM,
                                detail=f"Expires {not_after} ({days_left} days left)",
                                recommendation="Renew the certificate before it lapses.",
                            )
                        )
                except ValueError:
                    pass
        elif cert_bin:
            findings.append(
                Finding(
                    module=self.name,
                    target=target,
                    title="Certificate presented but not parsed",
                    severity=Severity.INFO,
                    detail="Raw certificate bytes received; detailed parsing skipped "
                    "(install 'cryptography' for full certificate field extraction).",
                )
            )

        return findings
