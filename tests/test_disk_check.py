from pathlib import Path
from types import SimpleNamespace

from nodesentry.checks.disk import check_disk
from nodesentry.models import Status


def test_low_free_space_warns(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        "nodesentry.checks.disk.shutil.disk_usage", lambda path: SimpleNamespace(free=5 * 1024**3)
    )
    finding = check_disk(tmp_path, minimum_gib=20)
    assert finding.status is Status.WARN
    assert "5.0 GiB" in finding.evidence


def test_adequate_free_space_passes(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        "nodesentry.checks.disk.shutil.disk_usage", lambda path: SimpleNamespace(free=50 * 1024**3)
    )
    assert check_disk(tmp_path, minimum_gib=20).status is Status.PASS
