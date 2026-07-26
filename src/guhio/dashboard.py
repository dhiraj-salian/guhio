"""Local web dashboard for managing the Guhio vault."""

import secrets

from flask import Flask, abort, jsonify, render_template, request, session

from guhio.store import EntryNotFoundError, Vault, VaultError

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Server-side session storage: maps a random token to an unlocked Vault instance.
# This keeps decrypted values out of cookies and is acceptable for the local,
# single-user dashboard. Do not use this for a multi-user service.
_vault_sessions: dict[str, Vault] = {}


def _require_vault() -> Vault:
    """Return the unlocked vault for the current session or abort with 401."""
    token = session.get("vault_token")
    vault = _vault_sessions.get(token) if token else None
    if vault is None or not vault.is_unlocked():
        abort(401)
    return vault


@app.route("/")
def index() -> str:
    """Render the dashboard page."""
    return render_template("dashboard.html")


@app.route("/api/status")
def status() -> dict:
    """Return whether the vault is unlocked for this session."""
    token = session.get("vault_token")
    vault = _vault_sessions.get(token) if token else None
    return jsonify({"unlocked": vault is not None and vault.is_unlocked()})


@app.route("/api/unlock", methods=["POST"])
def unlock() -> tuple[dict, int]:
    """Unlock the vault and create a server-side session."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    vault = Vault()
    try:
        vault.unlock(password)
    except VaultError as exc:
        return jsonify({"error": str(exc)}), 401

    token = secrets.token_urlsafe(32)
    _vault_sessions[token] = vault
    session["vault_token"] = token
    return jsonify({"unlocked": True})


@app.route("/api/lock", methods=["POST"])
def lock() -> dict:
    """Lock the vault and clear the server-side session."""
    token = session.pop("vault_token", None)
    if token:
        _vault_sessions.pop(token, None)
    return jsonify({"unlocked": False})


@app.route("/api/credentials", methods=["GET"])
def list_credentials() -> list[dict]:
    """List credential names and metadata without values."""
    vault = _require_vault()
    entries = vault.list_entries()
    return jsonify(
        [
            {"name": entry.name, "created_at": entry.created_at.isoformat()}
            for entry in entries
        ]
    )


@app.route("/api/credentials", methods=["POST"])
def add_credential() -> tuple[dict, int]:
    """Add a new credential to the vault."""
    vault = _require_vault()
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    value = data.get("value", "")

    if not name or not value:
        return jsonify({"error": "Name and value are required"}), 400

    try:
        vault.add(name, value)
    except VaultError as exc:
        return jsonify({"error": str(exc)}), 409

    return jsonify({"ok": True})


@app.route("/api/credentials/<path:name>", methods=["DELETE"])
def remove_credential(name: str) -> tuple[dict, int]:
    """Remove a credential from the vault."""
    vault = _require_vault()
    try:
        vault.remove(name)
    except EntryNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"ok": True})


def run_dashboard(host: str = "127.0.0.1", port: int = 5000, debug: bool = False) -> None:
    """Start the Flask development server."""
    # Do not use the reloader: it forks a child process and clears the
    # in-memory _vault_sessions dictionary, which would lock users out after
    # every auto-reload.
    app.run(host=host, port=port, debug=debug, use_reloader=False)
