import base64
import hashlib
from cryptography.fernet import Fernet
from app.core.config import settings


def _derive_fernet_key(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest)


class CryptoService:
    def __init__(self):
        raw_key = (settings.encryption_key or '').strip()
        if raw_key:
            try:
                self.fernet = Fernet(raw_key.encode('utf-8'))
            except Exception:
                self.fernet = Fernet(_derive_fernet_key(raw_key))
        else:
            self.fernet = Fernet(Fernet.generate_key())

    def encrypt(self, value: str) -> str:
        return self.fernet.encrypt(value.encode('utf-8')).decode('utf-8')

    def decrypt(self, value: str) -> str:
        return self.fernet.decrypt(value.encode('utf-8')).decode('utf-8')


crypto_service = CryptoService()
