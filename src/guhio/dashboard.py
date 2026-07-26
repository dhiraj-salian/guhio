"""Local web dashboard for managing the Guhio vault."""

import logging
import os
import secrets
import time

from flask import Flask, abort, jsonify, render_template, request, session

from guhio import session as session_store
from guhio.store import EntryNotFoundError, Vault, VaultError

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Cookie hardening: the session cookie that carries the vault-token reference
# must never be readable by JavaScript or sent on cross-site requests.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,  # local HTTP; set True behind HTTPS
)

logger = logging.getLogger("guhio.dashboard")

# Server-side session storage: maps a random token to an unlocked Vault and
# the time it was created. This keeps decrypted values out of cookies and is
# acceptable for the local, single-user dashboard. Do not use this for a
# multi-user service.
_vault_sessions: dict[str, dict] = {}

# Dashboard sessions expire after this many seconds of inactivity.
DASHBOARD_SESSION_TTL_SECONDS = 30 * 60

# Brute-force protection for the unlock endpoint.
_MAX_UNLOCK_ATTEMPTS = 5
_LOCKOUT_SECONDS = 60
_unlock_failures: dict[str, list[float]] = {}


def _client_ip() -> str:
    """Return the client IP address for rate-limit keying."""
    return request.remote_addr or "unknown"


def _record_unlock_failure() -> None:
    """Record a failed unlock attempt and prune old entries."""
    ip = _client_ip()
    now = time.monotonic()
    attempts = _unlock_failures.setdefault(ip, [])
    attempts.append(now)
    # Keep only failures within the lockout window.
    _unlock_failures[ip] = [t for t in attempts if now - t < _LOCKOUT_SECONDS]


def _clear_unlock_failures() -> None:
    """Clear failed-attempt tracking for the current client (on success)."""
    _unlock_failures.pop(_client_ip(), None)


def _is_locked_out() -> bool:
    """Return True if the current client has too many recent failures."""
    ip = _client_ip()
    attempts = _unlock_failures.get(ip, [])
    now = time.monotonic()
    recent = [t for t in attempts if now - t < _LOCKOUT_SECONDS]
    _unlock_failures[ip] = recent
    return len(recent) >= _MAX_UNLOCK_ATTEMPTS


def _check_origin() -> None:
    """Reject cross-origin state-changing requests (CSRF defence-in-depth).

    Browsers send an ``Origin`` header on cross-site POST/DELETE requests.
    If it is present and does not match this server's host, the request is
    blocked. Same-origin requests and non-browser clients (no Origin) are
    allowed.
    """
    origin = request.headers.get("Origin")
    if not origin:
        return
    expected = request.host_url.rstrip("/")
    if origin.rstrip("/") != expected:
        abort(403)


def _cleanup_expired_sessions() -> None:
    """Remove expired dashboard sessions to bound memory and stale access."""
    now = time.monotonic()
    expired = [
        token
        for token, entry in _vault_sessions.items()
        if now - entry["created_at"] > DASHBOARD_SESSION_TTL_SECONDS
    ]
    for token in expired:
        _vault_sessions.pop(token, None)


def _require_vault() -> Vault:
    """Return the unlocked vault for the current session or abort with 401."""
    _cleanup_expired_sessions()
    token = session.get("vault_token")
    entry = _vault_sessions.get(token) if token else None
    if entry is None:
        abort(401)
    vault: Vault = entry["vault"]
    if not vault.is_unlocked():
        _vault_sessions.pop(token, None)
        abort(401)
    # Refresh the session TTL on each authenticated request.
    entry["created_at"] = time.monotonic()
    return vault


@app.after_request
def _set_security_headers(response):
    """Attach defensive security headers to every response."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'self'",
    )
    return response


@app.route("/")
def index() -> str:
    """Render the dashboard page."""
    return render_template("dashboard.html")


def _try_auto_unlock_from_cli() -> None:
    """Auto-unlock the vault if a CLI session token is in the environment.

    When the user runs ``eval $(guhio unlock)`` before ``guhio dashboard``,
    the ``GUHIO_SESSION`` env var holds the CLI session token. Use it to
    pre-unlock the vault so the dashboard starts in the unlocked state
    instead of asking for the master password again.
    """
    cli_token = os.environ.get("GUHIO_SESSION")
    if not cli_token:
        return
    vault = Vault()
    password = session_store.load_session_password(vault.path, cli_token)
    if password is None:
        return
    try:
        vault.unlock(password)
    except VaultError:
        return
    token = secrets.token_urlsafe(32)
    _vault_sessions[token] = {"vault": vault, "created_at": time.monotonic()}
    session["vault_token"] = token
    logger.info("vault auto-unlocked from CLI session")


@app.route("/api/status")
def status() -> dict:
    """Return whether the vault is unlocked for this session."""
    _cleanup_expired_sessions()
    token = session.get("vault_token")
    entry = _vault_sessions.get(token) if token else None
    vault = entry["vault"] if entry else None
    if vault is None:
        _try_auto_unlock_from_cli()
        token = session.get("vault_token")
        entry = _vault_sessions.get(token) if token else None
        vault = entry["vault"] if entry else None
    return jsonify({"unlocked": vault is not None and vault.is_unlocked()})


@app.route("/api/unlock", methods=["POST"])
def unlock() -> tuple[dict, int]:
    """Unlock the vault and create a server-side session."""
    _check_origin()
    if _is_locked_out():
        logger.warning("unlock rate-limited for %s", _client_ip())
        return jsonify({"error": "Too many failed attempts. Try again later."}), 429

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    vault = Vault()
    try:
        vault.unlock(password)
    except VaultError:
        # Do not echo the underlying exception: VaultNotFoundError leaks the
        # vault path and InvalidPasswordError confirms the vault exists.
        _record_unlock_failure()
        logger.warning("unlock failed for %s", _client_ip())
        return jsonify({"error": "Unlock failed."}), 401

    token = secrets.token_urlsafe(32)
    _vault_sessions[token] = {"vault": vault, "created_at": time.monotonic()}
    session["vault_token"] = token
    _clear_unlock_failures()
    logger.info("vault unlocked for %s", _client_ip())
    return jsonify({"unlocked": True})


@app.route("/api/lock", methods=["POST"])
def lock() -> dict:
    """Lock the vault and clear the server-side session.

    Also clears the CLI session file so that ``GUHIO_SESSION`` in the
    environment cannot immediately re-unlock the vault. Without this,
    locking from the dashboard would appear to do nothing when the
    dashboard was auto-unlocked from a CLI session.
    """
    _check_origin()
    token = session.pop("vault_token", None)
    if token:
        _vault_sessions.pop(token, None)
    # Clear the CLI session file so the env-var auto-unlock cannot
    # re-unlock immediately after the user explicitly locked.
    vault = Vault()
    session_store.clear_session(vault.path)
    logger.info("vault locked for %s", _client_ip())
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
    _check_origin()
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

    logger.info("credential '%s' added via dashboard", name)
    return jsonify({"ok": True})


@app.route("/api/credentials/<path:name>", methods=["DELETE"])
def remove_credential(name: str) -> tuple[dict, int]:
    """Remove a credential from the vault."""
    _check_origin()
    vault = _require_vault()
    try:
        vault.remove(name)
    except EntryNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    logger.info("credential '%s' removed via dashboard", name)
    return jsonify({"ok": True})


def run_dashboard(host: str = "127.0.0.1", port: int = 5000, debug: bool = False) -> None:
    """Start the Flask development server."""
    if debug:
        logging.warning(
            "Dashboard debug mode is ON. The Werkzeug debugger can execute "
            "arbitrary code if its PIN is compromised; do not use debug mode "
            "with real credentials."
        )
    if host not in ("127.0.0.1", "localhost", "::1"):
        logging.warning(
            "Dashboard is binding to %s, which may be reachable from other "
            "machines. The dashboard is designed for local single-user use.",
            host,
        )
    # Hide Werkzeug's development-server warning while keeping real errors.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    # Do not use the reloader: it forks a child process and clears the
    # in-memory _vault_sessions dictionary, which would lock users out after
    # every auto-reload.
    app.run(host=host, port=port, debug=debug, use_reloader=False)
