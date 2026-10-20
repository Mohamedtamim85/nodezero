"""Flask app factory for the report viewer.

Binds to localhost only unless the caller explicitly chooses otherwise (see
``nodezero serve`` in ``cli.py``). There is no authentication layer here —
this is meant to be run on an operator's own machine against their own
``nodezero_reports/`` directory, not exposed to a shared network.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, render_template

from nodezero.reporting.store import list_reports, load_report

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def create_app(reports_dir: str | Path) -> Flask:
    """Build the Flask app, scoped to reports living under ``reports_dir``."""
    app = Flask(__name__)
    app.config["REPORTS_DIR"] = Path(reports_dir)

    @app.route("/")
    def index():
        reports = list_reports(app.config["REPORTS_DIR"])
        return render_template("index.html", reports=reports, severity_order=SEVERITY_ORDER)

    @app.route("/reports/<filename>")
    def report_detail(filename: str):
        try:
            data = load_report(app.config["REPORTS_DIR"], filename)
        except (FileNotFoundError, ValueError):
            abort(404)

        findings_by_target: dict[str, list[dict]] = {}
        for f in data.get("findings", []):
            findings_by_target.setdefault(f.get("target", "(unknown)"), []).append(f)
        for target_findings in findings_by_target.values():
            target_findings.sort(key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info")))

        return render_template(
            "report.html",
            filename=filename,
            data=data,
            findings_by_target=dict(sorted(findings_by_target.items())),
        )

    return app
