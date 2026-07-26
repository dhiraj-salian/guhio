import json

import pytest

from guhio.store import (
    EntryNotFoundError,
    InvalidPasswordError,
    Vault,
    VaultError,
)


def test_create_and_unlock(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")
    assert vault_path.exists()

    locked_vault = Vault(vault_path)
    locked_vault.unlock("master-password")
    assert locked_vault.is_unlocked()


def test_unlock_with_wrong_password(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")

    with pytest.raises(InvalidPasswordError):
        vault.unlock("wrong-password")


def test_add_and_get(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")
    vault.add("github", "ghp_token")

    same_vault = Vault(vault_path)
    same_vault.unlock("master-password")
    assert same_vault.get("github") == "ghp_token"


def test_add_duplicate_fails(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")
    vault.add("github", "ghp_token")

    with pytest.raises(VaultError):
        vault.add("github", "another-token")


def test_list_entries(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")
    vault.add("github", "ghp_token")
    vault.add("aws", "aws_key")

    entries = vault.list_entries()
    names = [entry.name for entry in entries]
    assert names == ["aws", "github"]


def test_remove(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")
    vault.add("github", "ghp_token")
    vault.remove("github")

    with pytest.raises(EntryNotFoundError):
        vault.get("github")


def test_remove_missing_raises(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")

    with pytest.raises(EntryNotFoundError):
        vault.remove("github")


def test_vault_persists_after_reopen(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")
    vault.add("github", "ghp_token")

    data = json.loads(vault_path.read_text())
    assert data["version"] == 1
    assert "salt" in data
    assert "github" in data["entries"]


def test_vault_file_has_restrictive_permissions(tmp_path):
    import os

    if os.name != "posix":
        pytest.skip("file permissions are POSIX-only")

    vault_path = tmp_path / "vault.json"
    Vault(vault_path).create("master-password")
    mode = vault_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_save_preserves_restrictive_permissions(tmp_path):
    import os

    if os.name != "posix":
        pytest.skip("file permissions are POSIX-only")

    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")
    vault.add("github", "ghp_token")
    mode = vault_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_save_leaves_no_temp_file(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.create("master-password")
    vault.add("github", "ghp_token")
    assert not (tmp_path / "vault.json.tmp").exists()
