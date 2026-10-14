"""
One-time migration:
Encrypt plaintext RSA private keys stored in MySQL.

Safety features:
- Uses a database transaction.
- Skips keys that are already encrypted.
- Verifies each encrypted key can be decrypted.
- Does not modify public keys or encrypted files.
"""

from database import get_connection
from crypto_utils import (
    encrypt_private_key,
    decrypt_private_key,
)


def looks_like_plaintext_rsa_key(value):
    """Return True if the value looks like an unencrypted RSA PEM key."""
    if not isinstance(value, str):
        return False

    return (
        "-----BEGIN RSA PRIVATE KEY-----" in value
        or "-----BEGIN PRIVATE KEY-----" in value
    )


def migrate_private_keys():
    connection = None
    cursor = None

    try:
        connection = get_connection()
        connection.start_transaction()

        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, email, private_key
            FROM users
            WHERE private_key IS NOT NULL
              AND private_key != ''
            FOR UPDATE
            """
        )

        users = cursor.fetchall()

        migrated = 0
        skipped = 0

        for user in users:
            user_id = user["id"]
            private_key = user["private_key"]

            if not looks_like_plaintext_rsa_key(private_key):
                # If it isn't recognizable plaintext, verify it is
                # a valid encrypted value before skipping it.
                try:
                    decrypt_private_key(private_key)
                    skipped += 1
                    print(f"Already encrypted: user ID {user_id}")
                    continue
                except Exception:
                    raise RuntimeError(
                        "Unexpected private-key format for user ID "
                        f"{user_id}. No changes will be committed."
                    )

            encrypted_key = encrypt_private_key(private_key)

            # Verify the encrypted result before updating the row.
            if decrypt_private_key(encrypted_key) != private_key:
                raise RuntimeError(
                    f"Verification failed for user ID {user_id}."
                )

            cursor.execute(
                """
                UPDATE users
                SET private_key = %s
                WHERE id = %s
                """,
                (encrypted_key, user_id),
            )

            migrated += 1
            print(f"Prepared encrypted key for user ID {user_id}")

        connection.commit()

        print("\nMigration completed successfully.")
        print(f"Encrypted keys: {migrated}")
        print(f"Already encrypted keys skipped: {skipped}")

    except Exception as exc:
        if connection:
            connection.rollback()

        print("\nMigration failed. Database transaction rolled back.")
        print(f"Reason: {exc}")
        raise

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


if __name__ == "__main__":
    confirmation = input(
        "Type MIGRATE to encrypt existing database private keys: "
    )

    if confirmation == "MIGRATE":
        migrate_private_keys()
    else:
        print("Cancelled. No database changes made.")
