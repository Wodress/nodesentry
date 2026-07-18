from nodesentry.models import Finding, Severity, Status, summarize


def finding(status: Status, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding("TEST-001", "Test", status, severity, "evidence", "remediation")


def test_critical_failure_forces_overall_fail():
    report = summarize([finding(Status.PASS), finding(Status.FAIL, Severity.CRITICAL)])
    assert report.status is Status.FAIL
    assert report.score < 100


def test_missing_evidence_is_unknown_not_pass():
    report = summarize([finding(Status.UNKNOWN)])
    assert report.status is Status.UNKNOWN
    assert report.score == 0


def test_warning_reduces_score_and_sets_warning_verdict():
    report = summarize([finding(Status.PASS), finding(Status.WARN)])
    assert report.status is Status.WARN
    assert report.score == 75


def test_report_json_has_stable_finding_fields():
    data = summarize([finding(Status.PASS)]).as_dict()
    assert list(data) == ["schema_version", "status", "score", "findings"]
    assert set(data["findings"][0]) == {
        "id",
        "title",
        "status",
        "severity",
        "evidence",
        "remediation",
    }
