import time

import pytest

from guhio.dashboard import _unlock_failures, _vault_sessions, app
from guhio.store import Vault
from urllib.parse import quote


@pytest.fixture
def client(tmp_path, monkeypatch):
    Vault.default_path = classmethod(lambda cls: tmp_path / "vault.json")
    _vault_sessions.clear()
    _unlock_failures.clear()
    vault = Vault()
    vault.create("master-password")
    vault.add("github", "ghp_token")

    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client
    _vault_sessions.clear()
    _unlock_failures.clear()


def test_index_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Guhio Vault" in response.data


def test_status_when_locked(client):
    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.get_json() == {"unlocked": False}


def test_unlock_with_wrong_password(client):
    response = client.post("/api/unlock", json={"password": "wrong"})
    assert response.status_code == 401


def test_unlock_and_list(client):
    unlock = client.post("/api/unlock", json={"password": "master-password"})
    assert unlock.status_code == 200
    assert unlock.get_json()["unlocked"] is True

    response = client.get("/api/credentials")
    assert response.status_code == 200
    data = response.get_json()
    names = [entry["name"] for entry in data]
    assert names == ["github"]


def test_add_and_remove(client):
    client.post("/api/unlock", json={"password": "master-password"})

    add = client.post("/api/credentials", json={"name": "aws", "value": "aws_key"})
    assert add.status_code == 200

    lst = client.get("/api/credentials")
    names = [entry["name"] for entry in lst.get_json()]
    assert sorted(names) == ["aws", "github"]

    rm = client.delete("/api/credentials/github")
    assert rm.status_code == 200

    lst = client.get("/api/credentials")
    names = [entry["name"] for entry in lst.get_json()]
    assert names == ["aws"]


def test_locked_routes_return_401(client):
    assert client.get("/api/credentials").status_code == 401
    assert client.post("/api/credentials", json={"name": "x", "value": "y"}).status_code == 401
    assert client.delete("/api/credentials/x").status_code == 401


def test_add_duplicate_returns_409(client):
    client.post("/api/unlock", json={"password": "master-password"})
    response = client.post("/api/credentials", json={"name": "github", "value": "other"})
    assert response.status_code == 409


def test_lock_clears_session(client):
    client.post("/api/unlock", json={"password": "master-password"})
    assert client.get("/api/status").get_json()["unlocked"] is True

    client.post("/api/lock")
    assert client.get("/api/status").get_json()["unlocked"] is False
    assert client.get("/api/credentials").status_code == 401


def test_index_has_no_inline_remove_handler(client):
    """Regression guard: credential removal must not use inline onclick or
    innerHTML with user-controlled names (stored XSS)."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"escapeHtml" not in response.data
    assert b"onclick=\"removeCredential(" not in response.data


def test_special_character_credential_name_round_trip(client):
    client.post("/api/unlock", json={"password": "master-password"})
    special = "a');alert(1);//"
    add = client.post("/api/credentials", json={"name": special, "value": "v"})
    assert add.status_code == 200

    lst = client.get("/api/credentials")
    names = [entry["name"] for entry in lst.get_json()]
    assert special in names

    rm = client.delete(f"/api/credentials/{quote(special, safe='')}")
    assert rm.status_code == 200

    lst = client.get("/api/credentials")
    names = [entry["name"] for entry in lst.get_json()]
    assert special not in names


# --- Security hardening tests ---


def test_cross_origin_post_rejected(client):
    """CSRF defence: a cross-origin Origin header is rejected on POST."""
    response = client.post(
        "/api/unlock",
        json={"password": "master-password"},
        headers={"Origin": "http://evil.com"},
    )
    assert response.status_code == 403


def test_cross_origin_delete_rejected(client):
    client.post("/api/unlock", json={"password": "master-password"})
    response = client.delete(
        "/api/credentials/github",
        headers={"Origin": "http://evil.com"},
    )
    assert response.status_code == 403


def test_same_origin_post_accepted(client):
    """A matching Origin header should be accepted."""
    response = client.post(
        "/api/unlock",
        json={"password": "master-password"},
        headers={"Origin": "http://localhost"},
    )
    assert response.status_code == 200


def test_security_headers_present(client):
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert "default-src" in response.headers.get("Content-Security-Policy", "")


def test_rate_limiting_on_failed_unlock(client):
    for _ in range(5):
        client.post("/api/unlock", json={"password": "wrong"})
    # 6th attempt should be rate-limited even with the correct password.
    response = client.post("/api/unlock", json={"password": "master-password"})
    assert response.status_code == 429


def test_successful_unlock_clears_rate_limit(client):
    for _ in range(3):
        client.post("/api/unlock", json={"password": "wrong"})
    # A successful unlock should reset the counter.
    response = client.post("/api/unlock", json={"password": "master-password"})
    assert response.status_code == 200


def test_unlock_error_does_not_leak_vault_path(client, tmp_path):
    response = client.post("/api/unlock", json={"password": "wrong"})
    assert response.status_code == 401
    body = response.get_data(as_text=True)
    assert str(tmp_path) not in body
    assert response.get_json()["error"] == "Unlock failed."


def test_expired_dashboard_session_rejected(client):
    client.post("/api/unlock", json={"password": "master-password"})
    assert client.get("/api/status").get_json()["unlocked"] is True

    for entry in _vault_sessions.values():
        entry["created_at"] = time.monotonic() - 3600

    assert client.get("/api/status").get_json()["unlocked"] is False
    assert client.get("/api/credentials").status_code == 401
