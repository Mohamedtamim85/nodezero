"""Persisting and listing saved JSON reports, for the web UI (and anyone else
who wants a directory of past engagement reports instead of one-off files).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path

from nodezero.authorization import EngagementAuthorization
from nodezero.engine import EngagementResult
from nodezero.reporting.report import render_json

_SLUG_RE = re.compile(r"[^a-z0-9]+")

#: Filenames this module writes always match this pattern. Anything used to
#: look up a saved report (e.g. a filename coming from a URL) is checked
#: against it first, so a path-traversal attempt (`../../etc/passwd`, an
#: absolute path, a name with no `.json` suffix) is rejected before it ever
#: touches the filesystem.
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.-]+\.json$")


def _slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.lower()).strip("-")
    return slug or "engagement"


def save_report(
    reports_dir: str | Path,
    authorization: EngagementAuthorization,
    result: EngagementResult,
) -> Path:
    """Write a full JSON report into ``reports_dir`` and return its path."""
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = f"{timestamp}_{_slugify(authorization.engagement_name)}.json"
    path = reports_dir / filename
    path.write_text(render_json(authorization, result))
    return path


def list_reports(reports_dir: str | Path) -> list[dict]:
    """Return lightweight metadata for every saved report, newest first."""
    reports_dir = Path(reports_dir)
    if not reports_dir.exists():
        return []

    summaries = []
    for path in sorted(reports_dir.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        findings = data.get("findings", [])
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        summaries.append(
            {
                "filename": path.name,
                "engagement_name": data.get("engagement", {}).get("engagement_name", "(unknown)"),
                "generated_at": data.get("generated_at", ""),
                "finding_count": len(findings),
                "severity_counts": counts,
                "targets": sorted({f.get("target") for f in findings if f.get("target")}),
            }
        )
    return summaries


def load_report(reports_dir: str | Path, filename: str) -> dict:
    """Load one saved report's full JSON payload by filename.

    Raises:
        ValueError: ``filename`` doesn't match the safe pattern this module
            writes (guards against path traversal from untrusted input, e.g.
            a filename taken from a URL).
        FileNotFoundError: no such report exists.
    """
    if not SAFE_FILENAME_RE.match(filename):
        raise ValueError(f"Invalid report filename: {filename!r}")

    path = Path(reports_dir) / filename
    if not path.is_file():
        raise FileNotFoundError(filename)
    return json.loads(path.read_text())
