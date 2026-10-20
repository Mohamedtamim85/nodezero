"""Built-in assessment modules.

All built-in modules are non-intrusive: TCP connect probes, banner reads, and
protocol handshakes that any browser or client would normally perform. None
of them attempt exploitation, credential brute-forcing, or anything that
could degrade a target's availability. That's a deliberate scope boundary for
this project, not an oversight — see README.md.
"""

from nodezero.modules.base import Module
from nodezero.modules.dns_recon import DnsReconModule
from nodezero.modules.http_headers import HttpHeadersModule
from nodezero.modules.port_scan import PortScanModule
from nodezero.modules.tls_check import TlsCheckModule

ALL_MODULES: dict[str, type[Module]] = {
    m.name: m
    for m in (PortScanModule, HttpHeadersModule, TlsCheckModule, DnsReconModule)
}

__all__ = [
    "Module",
    "PortScanModule",
    "HttpHeadersModule",
    "TlsCheckModule",
    "DnsReconModule",
    "ALL_MODULES",
]
