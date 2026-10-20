"""Check HTTP/HTTPS security headers — a passive, read-only HTTP GET."""

from __future__ import annotations

import urllib.error
import urllib.request

from nodezero.findings import Finding, Severity
from nodezero.modules.base import Module

SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS header missing",
        Severity.MEDIUM,
        "Add 'Strict-Transport-Security' to force HTTPS on repeat visits and "
        "prevent protocol-downgrade / SSL-stripping attacks.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options missing",
        Severity.LOW,
        "Add 'X-Content-Type-Options: nosniff' to stop browsers from MIME-sniffing "
        "responses away from the declared Content-Type.",
    ),
    "x-frame-options": (
        "X-Frame-Options / frame-ancestors missing",
        Severity.LOW,
        "Add 'X-Frame-Options' or a CSP 'frame-ancestors' directive to mitigate "
        "clickjacking.",
    ),
    "content-security-policy": (
        "Content-Security-Policy missing",
        Severity.MEDIUM,
        "Add a Content-Security-Policy to reduce the impact of any XSS that does "
        "slip through input handling.",
    ),
}


class HttpHeadersModule(Module):
    name = "http_headers"
    description = "Fetch '/' over HTTP(S) and check common security response headers."
    intrusive = False

    def __init__(self, *args, schemes: tuple[str, ...] = ("https", "http"),
                 timeout: float = 5.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.schemes = schemes
        self.timeout = timeout

    def run_one(self, target: str) -> list[Finding]:
        for scheme in self.schemes:
            url = f"{scheme}://{target}/"
            req = urllib.request.Request(url, headers={"User-Agent": "nodezero-lite/0.1"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    status = resp.status
            except (urllib.error.URLError, OSError, ValueError):
                continue  # try next scheme

            findings = [
                Finding(
                    module=self.name,
                    target=target,
                    title=f"HTTP response observed ({scheme.upper()})",
                    severity=Severity.INFO,
                    detail=f"GET {url} -> {status}",
                    evidence={"url": url, "status": status},
                )
            ]
            for header, (title, severity, rec) in SECURITY_HEADERS.items():
                if header not in headers:
                    findings.append(
                        Finding(
                            module=self.name,
                            target=target,
                            title=title,
                            severity=severity,
                            detail=f"Observed on {url}",
                            evidence={"url": url, "missing_header": header},
                            recommendation=rec,
                        )
                    )
            server = headers.get("server")
            if server:
                findings.append(
                    Finding(
                        module=self.name,
                        target=target,
                        title="Server header discloses software/version",
                        severity=Severity.LOW,
                        detail=f"Server: {server}",
                        evidence={"server": server},
                        recommendation=(
                            "Consider suppressing or genericizing the 'Server' header "
                            "to reduce fingerprinting surface for automated attacks."
                        ),
                    )
                )
            return findings

        return [
            Finding(
                module=self.name,
                target=target,
                title="No HTTP(S) response",
                severity=Severity.INFO,
                detail=f"Tried schemes {self.schemes}; none responded within timeout.",
            )
        ]
