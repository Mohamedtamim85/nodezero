import datetime as dt

import pytest

from nodezero.authorization import EngagementAuthorization
from nodezero.engine import EngagementResult
from nodezero.findings import Finding, Severity
from nodezero.reporting.store import save_report
from nodezero.scope import Scope

flask = pytest.importorskip("flask")  # noqa: F841 -- skip this module cleanly without Flask


def _auth():
    now = dt.datetime.utcnow()
    return EngagementAuthorization(
        engagement_name="Acme Corp Q4 Test",
        authorized_by="Jane Doe",
        scope=Scope(allow=["10.0.0.0/24"]),
        starts_at=now - dt.timedelta(hours=1),
        ends_at=now + dt.timedelta(days=1),
        attestation_accepted=True,
    )


def _result():
    findings = [
        Finding(
            module="port_scan",
            target="10.0.0.5",
            title="Port 23/tcp open (Telnet)",
            severity=Severity.MEDIUM,
            detail="Banner: ...",
            recommendation="Disable Telnet; use SSH.",
        ),
    ]
    return EngagementResult(findings=findings, advisory=None)


@pytest.fixture
def client(tmp_path):
    from nodezero.webui.app import create_app

    app = create_app(tmp_path)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c, tmp_path


def test_index_empty(client):
    c, _ = client
    resp = c.get("/")
    assert resp.status_code == 200
    assert b"No saved reports yet" in resp.data


def test_index_lists_saved_report(client):
    c, reports_dir = client
    save_report(reports_dir, _auth(), _result())
    resp = c.get("/")
    assert resp.status_code == 200
    assert b"Acme Corp Q4 Test" in resp.data


def test_report_detail_renders_findings(client):
    c, reports_dir = client
    path = save_report(reports_dir, _auth(), _result())
    resp = c.get(f"/reports/{path.name}")
    assert resp.status_code == 200
    assert b"Port 23/tcp open" in resp.data
    assert b"Disable Telnet" in resp.data


def test_report_detail_404_on_missing(client):
    c, _ = client
    resp = c.get("/reports/20260101T000000Z_nope.json")
    assert resp.status_code == 404


def test_report_detail_404_on_path_traversal(client):
    c, _ = client
    resp = c.get("/reports/..%2F..%2Fetc%2Fpasswd")
    assert resp.status_code == 404
