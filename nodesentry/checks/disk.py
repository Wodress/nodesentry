import shutil
from pathlib import Path

from nodesentry.models import Finding, Severity, Status


def check_disk(path: Path, minimum_gib: int = 20) -> Finding:
    free = shutil.disk_usage(path).free
    gib = free / (1024**3)
    status = Status.PASS if gib >= minimum_gib else Status.WARN
    return Finding(
        "DISK-001",
        "Data-directory free space",
        status,
        Severity.HIGH,
        f"Free space: {gib:.1f} GiB; safety floor: {minimum_gib} GiB.",
        "Free storage, enable pruning intentionally, or expand the volume.",
    )
