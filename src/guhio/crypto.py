"""Cryptographic helpers for the password vault."""

import base64
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def generate_salt(size: int = 16) -> bytes:
    """Generate a random salt."""
    return secrets.token_bytes(size)


def encrypt_value(password: str, plaintext: str, salt: bytes | None = None) -> bytes:
    """Encrypt a plaintext value with a password.

    If ``salt`` is provided it is used for key derivation; otherwise a new salt
    is generated and the caller is responsible for storing it.
    """
    if salt is None:
        salt = generate_salt()
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.encrypt(plaintext.encode("utf-8"))


def decrypt_value(password: str, salt: bytes, ciphertext: bytes) -> str:
    """Decrypt a ciphertext value with a password and salt."""
    key = derive_key(password, salt)
    f = Fernet(key)
    try:
        plaintext = f.decrypt(ciphertext)
    except InvalidToken as exc:
        raise ValueError("Invalid master password or corrupted vault") from exc
    return plaintext.decode("utf-8")
