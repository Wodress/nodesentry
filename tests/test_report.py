from nodesentry.models import Finding, Severity, Status, summarize
from nodesentry.report import render_terminal


def test_terminal_report_contains_evidence_and_remediation():
    report = summarize(
        [
            Finding(
                "RPC-001",
                "RPC exposure",
                Status.FAIL,
                Severity.CRITICAL,
                "Public wildcard detected.",
                "Bind to loopback.",
            )
        ]
    )
    output = render_terminal(report)
    assert "NODE SOVEREIGNTY" in output
    assert "RPC-001" in output
    assert "Public wildcard detected." in output
    assert "Bind to loopback." in output
