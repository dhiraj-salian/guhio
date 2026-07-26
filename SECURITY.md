# Security Model

Guhio is a local encrypted password vault for agent workflows. This
document describes the security architecture, the measures in place, and
known limitations.

## Threat model

Guhio assumes a **single-user local machine** where the user trusts the
operating system account. The primary threats are:

- **Offline vault theft**: an attacker obtains the vault file and attempts to
  brute-force the master password.
- **Local file-system access**: another local user or process tries to read
  vault contents, session files, or audit logs.
- **Web attacks on the dashboard**: a malicious website visited in the same
  browser attempts CSRF against the local dashboard.
- **Credential exposure in agent context**: an agent or script inadvertently
  logs or transmits a plaintext credential value.

Guhio does **not** protect against:

- An attacker with the master password.
- A compromised operating system (root/kernel-level keyloggers, memory
  scraping, swap inspection).
- A compromised Python runtime or supply-chain attacks on dependencies.
- Network attackers if the dashboard is bound to a non-loopback address.

## Cryptography

- **Key derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations and a 16-byte
  random salt. The iteration count meets OWASP 2023 recommendations.
- **Encryption**: Fernet (AES-128-CBC + HMAC-SHA256) provides authenticated
  encryption. Each encryption uses a fresh random nonce, so re-encrypting the
  same value produces different ciphertext.
- **Password verification**: a known plaintext ("guhio-v1") is encrypted at
  vault creation. On unlock, decrypting this verification token succeeds only
  with the correct key; Fernet's built-in HMAC provides constant-time
  authentication.

## File-system permissions

| File/Directory | Permissions | Notes |
|----------------|-------------|-------|
| Vault directory (`~/.guhio/`) | `0700` | Owner-only access. |
| Vault file (`vault.json`) | `0600` | Atomic write via temp + rename. |
| Session file (`session.json`) | `0600` | Atomic write via temp + rename. |
| Audit log (`audit.log`) | `0600` | Append-only, no secrets logged. |

All writes use `O_NOFOLLOW` to reject symlink redirection attacks on the
temporary file. Atomic write-then-rename prevents corruption on crash.

## CLI sessions

- `guhio unlock` creates a session token and encrypts the master password
  with it. The token is printed for `eval $(guhio unlock)`.
- Sessions **expire after 8 hours**. Expired or future-dated sessions are
  rejected to prevent replay.
- `guhio lock` removes the session file immediately.
- `guhio exec` strips `GUHIO_MASTER_PASSWORD` and `GUHIO_SESSION` from the
  child process environment so credentials do not leak to subprocesses.

## Dashboard security

- **Cookie hardening**: `HttpOnly`, `SameSite=Strict` prevent JavaScript
  access and cross-site cookie transmission.
- **CSRF protection**: state-changing endpoints (POST/DELETE) validate the
  `Origin` header against the server host.
- **Brute-force protection**: the unlock endpoint rate-limits after 5 failed
  attempts, with a 60-second lockout window. Successful unlock resets the
  counter.
- **Security headers**: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a restrictive
  `Content-Security-Policy` are set on every response.
- **Session expiry**: dashboard sessions expire after 30 minutes of
  inactivity. Expired sessions are cleaned up on each request.
- **Error messages**: unlock failures return a generic "Unlock failed."
  message that does not leak the vault path or distinguish wrong-password
  from missing-vault.
- **Debug mode**: warns loudly when enabled; the Werkzeug debugger can
  execute arbitrary code and should not be used with real credentials.

## Audit logging

Security-relevant CLI events are recorded in `~/.guhio/audit.log`:

- `vault_created`, `vault_locked`
- `unlock_succeeded`, `unlock_failed`
- `credential_added`, `credential_removed`
- `credential_revealed` (via `guhio get`)
- `credential_used` (via `guhio exec`)

Dashboard events are logged via Python's `logging` module at the `INFO`
and `WARNING` levels.

**No secrets are ever logged**: not passwords, credential values, or session
tokens. Only event types and credential names are recorded.

## Known limitations

- **PBKDF2 vs Argon2id**: PBKDF2 is currently acceptable but is not
  memory-hard. A future version may migrate to Argon2id.
- **In-memory plaintext**: while the vault is unlocked, plaintext values
  reside in process memory. Python strings are immutable and cannot be
  securely zeroed. This is a fundamental limitation of Python-based vaults.
- **Single key for all entries**: all entries share one Fernet key. An
  attacker who can modify the vault file could swap ciphertexts between
  entry names (the values would still decrypt, just under the wrong name).
  A future version may bind ciphertexts to names via AEAD associated data.
- **Flask development server**: the dashboard uses Flask's built-in server,
  which is designed for development. For production deployment behind a
  reverse proxy, use a WSGI server (e.g., gunicorn/waitress) and set
  `SESSION_COOKIE_SECURE=True` behind HTTPS.
- **`--password` flag**: visible in the process list. Use `GUHIO_MASTER_PASSWORD`
  or interactive prompts instead for production workflows.

## Reporting vulnerabilities

Please report security issues privately to the repository owner. Do not
open a public issue for security vulnerabilities.
