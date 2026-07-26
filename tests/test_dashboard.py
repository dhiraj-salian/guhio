import pytest

from guhio.dashboard import _vault_sessions, app
from guhio.store import Vault


@pytest.fixture
def client(tmp_path, monkeypatch):
    Vault.default_path = classmethod(lambda cls: tmp_path / "vault.json")
    _vault_sessions.clear()
    vault = Vault()
    vault.create("master-password")
    vault.add("github", "ghp_token")

    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client
    _vault_sessions.clear()


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
