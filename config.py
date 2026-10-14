import os
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "crypto_portal_flask")

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing. Set it in your .env file."
    )

# Separate key used to encrypt RSA private keys stored in MySQL.
PRIVATE_KEY_ENCRYPTION_KEY = os.getenv(
    "PRIVATE_KEY_ENCRYPTION_KEY"
)

if not PRIVATE_KEY_ENCRYPTION_KEY:
    raise RuntimeError(
        "PRIVATE_KEY_ENCRYPTION_KEY is missing. "
        "Set it in your .env file."
    )
