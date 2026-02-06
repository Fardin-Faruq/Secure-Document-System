from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class DocumentEncryption:
    def __init__(self, secret_key):
        """Initialize encryption with a secret key"""
        # Derive a key from the secret key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'secure_document_salt',  # In production, use a random salt per file
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
        self.cipher = Fernet(key)
    
    def encrypt_file(self, file_data):
        """Encrypt file data"""
        return self.cipher.encrypt(file_data)
    
    def decrypt_file(self, encrypted_data):
        """Decrypt file data"""
        return self.cipher.decrypt(encrypted_data)
    
    @staticmethod
    def generate_key():
        """Generate a new encryption key"""
        return Fernet.generate_key().decode()