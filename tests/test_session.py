import datetime
import json
import os

import pytest

from guhio import session as session_store


def test_save_session_creates_file_with_restrictive_permissions(tmp_path):
    if os.name != "posix":
        pytest.skip("file permissions are POSIX-only")

    vault_path = tmp_path / "vault.json"
    session_store.save_session(vault_path, "secret")
    session_path = vault_path.parent / "session.json"
    mode = session_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_save_session_leaves_no_temp_file(tmp_path):
    vault_path = tmp_path / "vault.json"
    session_store.save_session(vault_path, "secret")
    assert not (vault_path.parent / "session.json.tmp").exists()


def test_valid_session_returns_password(tmp_path):
    vault_path = tmp_path / "vault.json"
    token = session_store.save_session(vault_path, "secret")
    assert session_store.load_session_password(vault_path, token) == "secret"


def test_expired_session_is_rejected(tmp_path):
    vault_path = tmp_path / "vault.json"
    token = session_store.save_session(vault_path, "secret")

    session_path = vault_path.parent / "session.json"
    data = json.loads(session_path.read_text())
    old = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=10)
    data["created_at"] = old.isoformat()
    session_path.write_text(json.dumps(data))

    assert session_store.load_session_password(vault_path, token) is None


def test_future_dated_session_is_rejected(tmp_path):
    """A session with a created_at far in the future is rejected (clock tampering)."""
    vault_path = tmp_path / "vault.json"
    token = session_store.save_session(vault_path, "secret")

    session_path = vault_path.parent / "session.json"
    data = json.loads(session_path.read_text())
    future = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=10)
    data["created_at"] = future.isoformat()
    session_path.write_text(json.dumps(data))

    assert session_store.load_session_password(vault_path, token) is None


def test_session_wrong_vault_rejected(tmp_path):
    vault_path = tmp_path / "vault.json"
    other_path = tmp_path / "other" / "vault.json"
    token = session_store.save_session(vault_path, "secret")
    assert session_store.load_session_password(other_path, token) is None


def test_session_wrong_token_rejected(tmp_path):
    vault_path = tmp_path / "vault.json"
    session_store.save_session(vault_path, "secret")
    assert session_store.load_session_password(vault_path, "wrong-token") is None


def test_clear_session_removes_file(tmp_path):
    vault_path = tmp_path / "vault.json"
    session_store.save_session(vault_path, "secret")
    session_path = vault_path.parent / "session.json"
    assert session_path.exists()
    session_store.clear_session(vault_path)
    assert not session_path.exists()
