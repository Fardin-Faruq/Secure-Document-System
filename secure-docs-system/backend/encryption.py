"""Document encryption module using AES-256-GCM"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import hashlib


class DocumentEncryption:
    """Handles AES-256 encryption/decryption of documents"""
    
    def __init__(self, secret_key):
        """Initialize with secret key"""
        self.secret_key = secret_key
        self.backend = default_backend()
    
    def _derive_key(self, salt):
        """Derive encryption key from secret key using PBKDF2"""
        key_bytes = self.secret_key.encode() if isinstance(self.secret_key, str) else self.secret_key
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode()
        
        # Use hashlib's pbkdf2_hmac for key derivation
        key = hashlib.pbkdf2_hmac(
            'sha256',
            key_bytes,
            salt,
            100000
        )
        return key
    
    def encrypt_file(self, file_data):
        """
        Encrypt file data using AES-256-GCM
        
        Format: salt(16) + nonce(12) + ciphertext + tag(16)
        """
        # Generate random salt and nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # Derive encryption key
        key = self._derive_key(salt)
        
        # Create cipher
        cipher = AESGCM(key)
        
        # Encrypt data (includes authentication tag)
        ciphertext = cipher.encrypt(nonce, file_data, None)
        
        # Return salt + nonce + ciphertext (tag is included in ciphertext)
        return salt + nonce + ciphertext
    
    def decrypt_file(self, encrypted_data):
        """
        Decrypt file data using AES-256-GCM
        
        Expected format: salt(16) + nonce(12) + ciphertext + tag(16)
        """
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        
        # Derive decryption key
        key = self._derive_key(salt)
        
        # Create cipher
        cipher = AESGCM(key)
        
        # Decrypt data
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        return plaintext
