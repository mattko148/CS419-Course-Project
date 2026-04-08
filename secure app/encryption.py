"""
encryption.py — Added in week 3.
Provides AES-128 encryption (via Fernet) for all documents stored on disk.
Files saved in week 2 were plaintext; all new uploads are now encrypted.
"""
import os
from cryptography.fernet import Fernet
from config import Config

#creating an object that holds an encryption key and also the methods to use it
class EncryptionService:
    #runs automatically
    def __init__(self):
        #make the data directory if it doesnt already exist
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        #getting file name
        key_path = Config.ENCRYPTION_KEY_FILE
        try:
            #try to open key_path file (which should be data/secret.key) and read it.
            with open(key_path, 'rb') as f:
                self.key = f.read()
        #if it doesnt exist, thats ok, just generate a new one
        except FileNotFoundError:
            #generate key using fernet
            self.key = Fernet.generate_key()
            #write it to the key_path file
            with open(key_path, 'wb') as f:
                f.write(self.key)
            print(f'[encryption] New key generated at {key_path} — keep this safe!')
        #preparing cipher to encrypt or decrypt stuff
        self.cipher = Fernet(self.key)


    def encrypt(self, data: bytes) -> bytes:
        #tells cipher "use the key youre holding to encrypt this data"
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        #"use the key youre holding to decrypt this data"
        return self.cipher.decrypt(data)

#create an instance of it so it generates/loads the key.
#when it is imported to another file it will use this instance
encryption = EncryptionService()