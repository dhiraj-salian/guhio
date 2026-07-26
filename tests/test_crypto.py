import pytest

from guhio import crypto


def test_round_trip_encryption():
    password = "master-password"
    plaintext = "secret-api-token"
    salt = crypto.generate_salt()
    ciphertext = crypto.encrypt_value(password, plaintext, salt=salt)
    decrypted = crypto.decrypt_value(password, salt, ciphertext)
    assert decrypted == plaintext


def test_wrong_password_fails():
    password = "master-password"
    plaintext = "secret-api-token"
    salt = crypto.generate_salt()
    ciphertext = crypto.encrypt_value(password, plaintext, salt=salt)
    with pytest.raises(ValueError):
        crypto.decrypt_value("wrong-password", salt, ciphertext)


def test_different_plaintexts_produce_different_ciphertexts():
    password = "master-password"
    salt = crypto.generate_salt()
    ct1 = crypto.encrypt_value(password, "value-one", salt=salt)
    ct2 = crypto.encrypt_value(password, "value-two", salt=salt)
    assert ct1 != ct2


def test_re_encryption_changes_ciphertext():
    password = "master-password"
    plaintext = "secret-api-token"
    salt = crypto.generate_salt()
    ct1 = crypto.encrypt_value(password, plaintext, salt=salt)
    ct2 = crypto.encrypt_value(password, plaintext, salt=salt)
    assert ct1 != ct2
