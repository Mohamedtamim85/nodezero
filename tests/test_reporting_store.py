import datetime as dt

import pytest

from nodezero.authorization import EngagementAuthorization
from nodezero.engine import EngagementResult
from nodezero.findings import Finding, Severity
from nodezero.reporting.store import list_reports, load_report, save_report
from nodezero.scope import Scope


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
        Finding(module="port_scan", target="10.0.0.5", title="Port open", severity=Severity.HIGH),
        Finding(module="dns_recon", target="10.0.0.5", title="Resolved", severity=Severity.INFO),
    ]
    return EngagementResult(findings=findings, advisory=None)


def test_save_report_writes_json_file(tmp_path):
    path = save_report(tmp_path, _auth(), _result())
    assert path.exists()
    assert path.suffix == ".json"
    assert "acme-corp-q4-test" in path.name


def test_list_reports_empty_dir(tmp_path):
    assert list_reports(tmp_path / "does-not-exist") == []


def test_list_reports_returns_metadata(tmp_path):
    save_report(tmp_path, _auth(), _result())
    reports = list_reports(tmp_path)
    assert len(reports) == 1
    r = reports[0]
    assert r["engagement_name"] == "Acme Corp Q4 Test"
    assert r["finding_count"] == 2
    assert r["severity_counts"] == {"high": 1, "info": 1}
    assert r["targets"] == ["10.0.0.5"]


def test_load_report_round_trip(tmp_path):
    path = save_report(tmp_path, _auth(), _result())
    data = load_report(tmp_path, path.name)
    assert data["engagement"]["engagement_name"] == "Acme Corp Q4 Test"
    assert len(data["findings"]) == 2


def test_load_report_rejects_path_traversal(tmp_path):
    save_report(tmp_path, _auth(), _result())
    for bad in ("../secrets.json", "/etc/passwd", "..\\..\\x.json", "no-extension", ""):
        with pytest.raises(ValueError):
            load_report(tmp_path, bad)


def test_load_report_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_report(tmp_path, "20260101T000000Z_nonexistent.json")
