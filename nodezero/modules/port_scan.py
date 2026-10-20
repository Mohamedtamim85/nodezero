"""Non-intrusive TCP connect port scan with lightweight banner grabbing.

This deliberately uses plain TCP connect probes (the same thing a browser
does when it opens a socket) rather than raw-socket SYN scanning, so it needs
no elevated privileges and cannot be mistaken for anything disruptive. It is
slow and loud by design; it is a starting point for an authorized engagement,
not a stealth tool.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from nodezero.findings import Finding, Severity
from nodezero.modules.base import Module

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    9200,
    27017,
]

RISKY_PLAINTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}


def _grab_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(1.5)
        data = sock.recv(256)
        return data.decode(errors="replace").strip()
    except OSError:
        return ""


def _probe(target: str, port: int, timeout: float) -> tuple[int, bool, str]:
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            banner = _grab_banner(sock)
            return port, True, banner
    except (TimeoutError, OSError):
        return port, False, ""


class PortScanModule(Module):
    name = "port_scan"
    description = "TCP connect scan of common ports with best-effort banner grab."
    intrusive = False

    def __init__(
        self,
        *args,
        ports: list[int] | None = None,
        timeout: float = 1.5,
        max_workers: int = 50,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.ports = ports or COMMON_PORTS
        self.timeout = timeout
        self.max_workers = max_workers

    def run_one(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        open_ports: list[tuple[int, str]] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(_probe, target, p, self.timeout) for p in self.ports]
            for fut in as_completed(futures):
                port, is_open, banner = fut.result()
                if is_open:
                    open_ports.append((port, banner))

        for port, banner in sorted(open_ports):
            service = RISKY_PLAINTEXT_PORTS.get(port)
            severity = Severity.LOW if service else Severity.INFO
            title = f"Port {port}/tcp open"
            recommendation = ""
            if service:
                title += f" ({service} — unencrypted protocol)"
                severity = Severity.MEDIUM
                recommendation = (
                    f"{service} transmits credentials/data in cleartext. If this "
                    "service is required, migrate to an encrypted equivalent "
                    "(e.g. SFTP/FTPS for FTP, HTTPS for HTTP, IMAPS for IMAP) or "
                    "restrict access to a management VLAN/VPN."
                )
            findings.append(
                Finding(
                    module=self.name,
                    target=target,
                    title=title,
                    severity=severity,
                    detail=f"Banner: {banner!r}" if banner else "No banner received.",
                    evidence={"port": port, "banner": banner},
                    recommendation=recommendation,
                )
            )

        if not open_ports:
            findings.append(
                Finding(
                    module=self.name,
                    target=target,
                    title="No common ports open",
                    severity=Severity.INFO,
                    detail=f"Scanned {len(self.ports)} common ports; none responded.",
                )
            )
        return findings
