from database import get_connection
from crypto_utils import decrypt_private_key
from Crypto.PublicKey import RSA


connection = None
cursor = None

try:
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT id, private_key
        FROM users
        WHERE private_key IS NOT NULL
          AND private_key != ''
        """
    )

    users = cursor.fetchall()

    for user in users:
        decrypted_key = decrypt_private_key(
            user["private_key"]
        )

        # Confirm the decrypted content is a valid RSA key.
        rsa_key = RSA.import_key(decrypted_key)

        if not rsa_key.has_private():
            raise ValueError(
                f"User ID {user['id']} does not have a private RSA key."
            )

    print("Verified RSA private keys:", len(users))
    print("All stored private keys decrypted successfully.")

except Exception as error:
    print("Verification failed:", error)
    raise

finally:
    if cursor:
        cursor.close()

    if connection:
        connection.close()
