"""
encryption.py — Added in week 3.
Provides AES-128 encryption (via Fernet) for all documents stored on disk.
Files saved in week 2 were plaintext; all new uploads are now encrypted.
"""
import os
from cryptography.fernet import Fernet
from config import Config


class EncryptionService:
    def __init__(self):
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        key_path = Config.ENCRYPTION_KEY_FILE
        try:
            with open(key_path, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            # Generate and persist a new key on first run
            self.key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(self.key)
            print(f'[encryption] New key generated at {key_path} — keep this safe!')
        self.cipher = Fernet(self.key)

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)


encryption = EncryptionService()