"""Persistent unlock session for the CLI.

A session lets commands that need the vault avoid prompting for the master
password.  The session token lives in the ``GUHIO_SESSION`` environment
variable; the token is used to decrypt a session file that stores an
encrypted copy of the master password.  Keeping the token out of the session
file means an attacker who can read the file still cannot unlock the vault
without also obtaining the token.
"""

import base64
import datetime
import json
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DEFAULT_SESSION_FILENAME = "session.json"

# Encrypted sessions older than this are rejected so a long-lived session
# file cannot be replayed indefinitely. 8 hours covers a typical work day.
SESSION_TTL_SECONDS = 8 * 3600


def _session_path(vault_path: Path) -> Path:
    """Return the path to the session file for a given vault."""
    return vault_path.parent / DEFAULT_SESSION_FILENAME


def _derive_key(token: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a session token and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(token.encode("utf-8")))


def _encrypt_password(password: str, token: str) -> tuple[bytes, bytes]:
    """Encrypt a master password with a session token."""
    salt = secrets.token_bytes(16)
    key = _derive_key(token, salt)
    ciphertext = Fernet(key).encrypt(password.encode("utf-8"))
    return salt, ciphertext


def _decrypt_password(token: str, salt: bytes, ciphertext: bytes) -> str | None:
    """Decrypt a master password with a session token, or None on failure."""
    try:
        key = _derive_key(token, salt)
        plaintext = Fernet(key).decrypt(ciphertext)
    except (InvalidToken, ValueError):
        return None
    return plaintext.decode("utf-8")


def save_session(vault_path: Path, password: str) -> str:
    """Save an encrypted session for the vault and return the session token."""
    token = secrets.token_urlsafe(32)
    salt, ciphertext = _encrypt_password(password, token)
    data: dict[str, Any] = {
        "version": 1,
        "vault": str(vault_path),
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        "created_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
    }
    path = _session_path(vault_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically with mode 0600 from creation so there is never a window
    # where the file is world-readable. O_NOFOLLOW rejects a pre-existing
    # symlink at the temp path (symlink attack defence).
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        fd = os.open(
            str(tmp_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return token


def load_session_password(vault_path: Path, token: str) -> str | None:
    """Return the master password for the vault if the session is valid."""
    path = _session_path(vault_path)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    if data.get("version") != 1:
        return None
    # Reject expired sessions so a stolen session file cannot be replayed
    # long after it was created.
    created_at_raw = data.get("created_at")
    if not created_at_raw:
        return None
    try:
        created_at = datetime.datetime.fromisoformat(created_at_raw)
    except ValueError:
        return None
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=datetime.timezone.utc)
    age = (datetime.datetime.now(tz=datetime.timezone.utc) - created_at).total_seconds()
    if age > SESSION_TTL_SECONDS or age < -300:
        return None
    stored_vault = Path(data.get("vault", ""))
    if stored_vault.resolve() != vault_path.resolve():
        return None
    try:
        salt = base64.urlsafe_b64decode(data["salt"].encode("ascii"))
        ciphertext = base64.urlsafe_b64decode(data["ciphertext"].encode("ascii"))
    except (KeyError, ValueError):
        return None

    return _decrypt_password(token, salt, ciphertext)


def clear_session(vault_path: Path) -> None:
    """Remove any saved session for the vault."""
    path = _session_path(vault_path)
    path.unlink(missing_ok=True)
