import base64
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet, InvalidToken

from config import PRIVATE_KEY_ENCRYPTION_KEY


# -------------------------------------------------
# PRIVATE KEY ENCRYPTION AT REST
# -------------------------------------------------

def _get_private_key_cipher():
    """
    Load the separate master key used to protect
    RSA private keys stored in the database.
    """
    try:
        key = PRIVATE_KEY_ENCRYPTION_KEY.encode("ascii")
        decoded_key = base64.urlsafe_b64decode(key)

        if len(decoded_key) != 32:
            raise ValueError(
                "PRIVATE_KEY_ENCRYPTION_KEY must encode 32 bytes."
            )

        return Fernet(key)

    except Exception as exc:
        raise RuntimeError(
            "Invalid PRIVATE_KEY_ENCRYPTION_KEY configuration."
        ) from exc


def encrypt_private_key(private_key):
    """
    Encrypt an RSA private-key string before database storage.
    """
    if not isinstance(private_key, str):
        raise TypeError("private_key must be a string.")

    return _get_private_key_cipher().encrypt(
        private_key.encode("utf-8")
    ).decode("ascii")


def decrypt_private_key(encrypted_private_key):
    """
    Decrypt an RSA private key retrieved from the database.
    """
    if not isinstance(encrypted_private_key, str):
        raise TypeError("Encrypted private key must be a string.")

    try:
        plaintext = _get_private_key_cipher().decrypt(
            encrypted_private_key.encode("ascii")
        )
        return plaintext.decode("utf-8")

    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise ValueError(
            "Private-key decryption failed. Check the encryption key "
            "and confirm that this database record has been migrated."
        ) from exc


# -------------------------------------------------
# AES-256-GCM
# -------------------------------------------------

def generate_key():
    """Generate a 256-bit AES key."""
    return get_random_bytes(32)


def encrypt_data(data, key):
    """Encrypt data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return cipher.nonce, ciphertext, tag


def decrypt_data(nonce, ciphertext, tag, key):
    """Decrypt and authenticate AES-GCM data."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# -------------------------------------------------
# RSA KEY GENERATION
# -------------------------------------------------

def generate_rsa_key_pair():
    """Generate an RSA-2048 public/private key pair."""
    key = RSA.generate(2048)

    private_key = key.export_key().decode("utf-8")
    public_key = key.publickey().export_key().decode("utf-8")

    return private_key, public_key


# -------------------------------------------------
# RSA ENCRYPT AES KEY
# -------------------------------------------------

def encrypt_key_with_rsa(aes_key, public_key):
    """Encrypt an AES key using RSA-OAEP."""
    rsa_key = RSA.import_key(public_key.encode("utf-8"))
    cipher = PKCS1_OAEP.new(rsa_key)

    return cipher.encrypt(aes_key)


# -------------------------------------------------
# RSA DECRYPT AES KEY
# -------------------------------------------------

def decrypt_key_with_rsa(encrypted_key, private_key):
    """Decrypt an AES key using RSA-OAEP."""
    rsa_key = RSA.import_key(private_key.encode("utf-8"))
    cipher = PKCS1_OAEP.new(rsa_key)

    return cipher.decrypt(encrypted_key)
