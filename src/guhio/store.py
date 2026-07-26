"""Encrypted credential store for the password vault."""

import base64
import datetime
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guhio import crypto


def _restrict_directory(path: Path) -> None:
    """Ensure a directory is owner-only (mode 0700).

    The vault directory must not be world- or group-accessible, otherwise
    another local user could read file metadata or race the atomic write.
    """
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


class VaultError(Exception):
    """Base exception for vault operations."""


class VaultNotFoundError(VaultError):
    """Raised when the vault file does not exist."""


class EntryNotFoundError(VaultError):
    """Raised when a requested entry does not exist."""


class InvalidPasswordError(VaultError):
    """Raised when the master password is incorrect."""


@dataclass(frozen=True)
class Entry:
    """A single credential entry."""

    name: str
    created_at: datetime.datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at.isoformat(),
        }


class Vault:
    """Encrypted local credential store.

    The vault file stores metadata and encrypted entries. It is kept locked
    until ``unlock`` is called with the master password. Once unlocked, the
    decrypted plaintext values live in memory for the lifetime of the object.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path) if path else self.default_path()
        self._salt: bytes | None = None
        self._entries: dict[str, bytes] = {}
        self._metadata: dict[str, Any] = {}
        self._unlocked_values: dict[str, str] | None = None
        self._master_password: str | None = None

    @staticmethod
    def default_path() -> Path:
        """Return the default vault file path."""
        home = Path.home()
        return home / ".guhio" / "vault.json"

    def exists(self) -> bool:
        """Return True if the vault file exists."""
        return self.path.exists()

    def is_unlocked(self) -> bool:
        """Return True if the vault has been unlocked."""
        return self._unlocked_values is not None

    def create(self, master_password: str) -> None:
        """Create a new empty vault with the given master password."""
        if self.exists():
            raise VaultError(f"Vault already exists at {self.path}")

        salt = crypto.generate_salt()
        verify = crypto.encrypt_value(master_password, "guhio-v1", salt=salt)
        data = {
            "version": 1,
            "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            "verify": base64.urlsafe_b64encode(verify).decode("ascii"),
            "entries": {},
        }
        self._write_vault(data)

        self._salt = salt
        self._entries = {}
        self._metadata = data
        self._unlocked_values = {}
        self._master_password = master_password

    def unlock(self, master_password: str) -> None:
        """Unlock the vault with the master password."""
        if not self.exists():
            raise VaultNotFoundError(f"Vault not found at {self.path}")

        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if data.get("version") != 1:
            raise VaultError("Unsupported vault version")

        salt = base64.urlsafe_b64decode(data["salt"].encode("ascii"))
        verify = base64.urlsafe_b64decode(data["verify"].encode("ascii"))

        # Verify the password before decrypting any entries.
        try:
            crypto.decrypt_value(master_password, salt, verify)
        except ValueError as exc:
            raise InvalidPasswordError(str(exc)) from exc

        entries = {
            name: base64.urlsafe_b64decode(payload["ciphertext"].encode("ascii"))
            for name, payload in data.get("entries", {}).items()
        }

        # Decrypt all entries now so the agent never touches ciphertext later.
        unlocked: dict[str, str] = {
            name: crypto.decrypt_value(master_password, salt, ciphertext)
            for name, ciphertext in entries.items()
        }

        self._salt = salt
        self._entries = entries
        self._metadata = data
        self._unlocked_values = unlocked
        self._master_password = master_password

    def ensure_unlocked(self) -> None:
        """Raise if the vault is not unlocked."""
        if not self.is_unlocked():
            raise VaultError("Vault is locked. Run 'guhio unlock' or provide a password.")

    def _write_vault(self, data: dict[str, Any]) -> None:
        """Persist ``data`` to disk atomically with restrictive permissions.

        Writing to a temporary file in the same directory and renaming it
        into place prevents a crash mid-write from corrupting or truncating
        the vault. The file is created with mode 0600 so only the owner can
        read the encrypted contents. ``O_NOFOLLOW`` rejects a symlink placed
        at the temp path, preventing a symlink-redirect attack on the write.
        The vault directory is also restricted to 0700.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _restrict_directory(self.path.parent)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
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
            os.replace(tmp_path, self.path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

    def _save(self) -> None:
        """Persist the current state to disk."""
        self.ensure_unlocked()
        assert self._salt is not None
        assert self._master_password is not None

        entries: dict[str, dict[str, Any]] = {}
        for name, plaintext in self._unlocked_values.items():
            ciphertext = crypto.encrypt_value(self._master_password, plaintext, salt=self._salt)
            entries[name] = {
                "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
                "created_at": self._metadata.get("entries", {}).get(name, {}).get(
                    "created_at", datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
                ),
            }

        data = {
            "version": 1,
            "salt": base64.urlsafe_b64encode(self._salt).decode("ascii"),
            "verify": self._metadata.get("verify", ""),
            "entries": entries,
        }
        self._write_vault(data)
        self._metadata = data

    def add(self, name: str, value: str) -> None:
        """Add or overwrite a credential in the vault."""
        self.ensure_unlocked()
        assert self._unlocked_values is not None
        if name in self._unlocked_values:
            raise VaultError(f"Entry '{name}' already exists. Remove it first.")
        self._unlocked_values[name] = value
        self._save()

    def overwrite(self, name: str, value: str) -> None:
        """Overwrite a credential in the vault, creating it if needed."""
        self.ensure_unlocked()
        assert self._unlocked_values is not None
        self._unlocked_values[name] = value
        self._save()

    def remove(self, name: str) -> None:
        """Remove a credential from the vault."""
        self.ensure_unlocked()
        assert self._unlocked_values is not None
        if name not in self._unlocked_values:
            raise EntryNotFoundError(f"Entry '{name}' not found")
        del self._unlocked_values[name]
        self._save()

    def get(self, name: str) -> str:
        """Return the plaintext value of a credential."""
        self.ensure_unlocked()
        assert self._unlocked_values is not None
        if name not in self._unlocked_values:
            raise EntryNotFoundError(f"Entry '{name}' not found")
        return self._unlocked_values[name]

    def list_entries(self) -> list[Entry]:
        """Return a list of all credential entries (without values)."""
        self.ensure_unlocked()
        assert self._unlocked_values is not None
        meta_entries = self._metadata.get("entries", {})
        return [
            Entry(
                name=name,
                created_at=datetime.datetime.fromisoformat(
                    meta_entries.get(name, {}).get("created_at", datetime.datetime.now(tz=datetime.timezone.utc).isoformat())
                ),
            )
            for name in sorted(self._unlocked_values)
        ]

    def has(self, name: str) -> bool:
        """Return True if the named credential exists."""
        self.ensure_unlocked()
        assert self._unlocked_values is not None
        return name in self._unlocked_values
