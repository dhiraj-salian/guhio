"""Security audit logging for vault operations.

Events are appended to an audit log co-located with the vault file. Only
non-secret metadata (event type, credential names, success/failure) is
recorded. No passwords, credential values, or session tokens are ever
written. Logging is best-effort: a failure to write the audit log never
blocks the triggering operation.
"""

import datetime
import os
from pathlib import Path
from typing import Any


def _audit_path(vault_path: Path) -> Path:
    """Return the audit log path for a given vault."""
    return vault_path.parent / "audit.log"


def log_event(vault_path: Path, event: str, **details: Any) -> None:
    """Append a timestamped audit event to the vault's audit log."""
    path = _audit_path(vault_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        fields = " ".join(f"{k}={v}" for k, v in details.items())
        line = f"{ts}\t{event}\t{fields}\n"
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
    except OSError:
        pass
