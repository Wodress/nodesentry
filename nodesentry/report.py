import json

from nodesentry.models import Report


def render_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=False)


def render_terminal(report: Report) -> str:
    lines = [f"NODE SOVEREIGNTY: {report.score}/100  {report.status.value.upper()}", ""]
    marks = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "unknown": "????", "skip": "SKIP"}
    for item in report.findings:
        lines.append(f"{marks[item.status.value]:4}  {item.check_id:10} {item.title}")
        lines.append(f"      {item.evidence}")
        if item.status.value in {"warn", "fail", "unknown"}:
            lines.append(f"      → {item.remediation}")
    return "\n".join(lines)
