"""nodezero-lite: a local, authorization-gated AI-assisted pentest console.

This package orchestrates *non-destructive* reconnaissance and assessment
workflows against systems the operator is explicitly authorized to test. Every
action is gated by a signed engagement authorization and an enforced target
scope; see :mod:`nodezero.authorization` and :mod:`nodezero.scope`.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
