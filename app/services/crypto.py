import base64

from cryptography.fernet import Fernet, InvalidToken

from app.services.config import settings


def get_fernet() -> Fernet:
    if not settings.encryption_key:
        raise RuntimeError("Missing ROUTERVAULT_ENCRYPTION_KEY")
    key = settings.encryption_key.encode("utf-8")
    if len(key) != 44:
        key = base64.urlsafe_b64encode(key)
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    try:
        return get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""
