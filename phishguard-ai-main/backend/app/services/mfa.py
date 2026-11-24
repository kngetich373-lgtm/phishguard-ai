import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


settings = get_settings()


def _fernet() -> Fernet:
    key_material = hashlib.sha256(
        ("phishguard-mfa:" + settings.secret_key).encode("utf-8")
    ).digest()
    return Fernet(base64.urlsafe_b64encode(key_material))


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("ascii")
    except (InvalidToken, UnicodeDecodeError):
        raise ValueError("Stored MFA secret cannot be decrypted with current SECRET_KEY") from None


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, timestamp: int | None = None) -> str:
    counter = int((timestamp if timestamp is not None else time.time()) // 30)
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str | None, timestamp: int | None = None) -> bool:
    if not code or len(code) != 6 or not code.isdigit():
        return False
    now = timestamp if timestamp is not None else int(time.time())
    return any(
        hmac.compare_digest(totp_code(secret, now + offset * 30), code)
        for offset in (-1, 0, 1)
    )


def provisioning_uri(secret: str, email: str) -> str:
    issuer = "PhishGuard AI"
    label = quote(f"{issuer}:{email}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )
