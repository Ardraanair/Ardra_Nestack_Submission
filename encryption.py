
import os
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Read the encryption key
ENCRYPTION_KEY = os.getenv("NESTACK_FERNET_KEY")

if not ENCRYPTION_KEY:
    raise RuntimeError(
        "Encryption key not found. Check your .env file."
    )

try:
    cipher = Fernet(ENCRYPTION_KEY.encode("utf-8"))
except (ValueError, TypeError):
    raise RuntimeError(
        "Invalid encryption key. Generate a valid Fernet key."
    )


# ==========================================
# ENCRYPT RECORD CONTENT
# ==========================================

def encrypt_text(plain_text):

    if not isinstance(plain_text, str):
        raise TypeError("Record content must be text.")

    encrypted_data = cipher.encrypt(
        plain_text.encode("utf-8")
    )

    return encrypted_data.decode("utf-8")


# ==========================================
# DECRYPT RECORD CONTENT
# ==========================================

def decrypt_text(encrypted_text):

    if not isinstance(encrypted_text, str):
        raise TypeError("Encrypted content must be text.")

    try:
        decrypted_data = cipher.decrypt(
            encrypted_text.encode("utf-8")
        )

        return decrypted_data.decode("utf-8")

    except InvalidToken:
        raise ValueError(
            "Unable to decrypt record. Invalid key or corrupted data."
        )
