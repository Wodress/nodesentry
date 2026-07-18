from datetime import UTC, datetime

from nodesentry.checks.chain import check_chain
from nodesentry.models import Status


def by_id(findings):
    return {item.check_id: item for item in findings}


def test_fresh_synced_chain_passes():
    now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
    info = {
        "initialblockdownload": False,
        "blocks": 900000,
        "headers": 900000,
        "verificationprogress": 0.99999,
        "mediantime": int(now.timestamp()) - 600,
    }
    result = by_id(check_chain(info, now=now))
    assert result["CHAIN-001"].status is Status.PASS
    assert result["CHAIN-002"].status is Status.PASS


def test_stale_tip_fails_and_ibd_warns():
    now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
    info = {
        "initialblockdownload": True,
        "blocks": 800000,
        "headers": 900000,
        "verificationprogress": 0.80,
        "mediantime": int(now.timestamp()) - 7200,
    }
    result = by_id(check_chain(info, now=now))
    assert result["CHAIN-001"].status is Status.FAIL
    assert result["CHAIN-002"].status is Status.WARN
    assert result["CHAIN-003"].status is Status.WARN
