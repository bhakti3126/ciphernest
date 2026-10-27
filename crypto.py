"""
CipherNest - Cryptographic Engine
=================================
Implements authenticated AES-256-GCM block encryption with HKDF key derivation.

Security Architecture:
- Master Key: 256-bit (32-byte) key stored exclusively on the backend (never sent to client).
- Key Derivation: Each file has a unique 16-byte cryptographically secure random salt.
  HKDF-SHA256 derives a dedicated 256-bit per-file key from the master key and salt.
- Authenticated Encryption: AES-256-GCM (Galois/Counter Mode).
- IV/Nonce: Unique 96-bit (12-byte) random nonce per encrypted block.
- Associated Authenticated Data (AAD): Binds the ciphertext to the file_id and block index,
  preventing block reordering, substitution, or cross-file splicing attacks.
"""

import os
import base64
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass

class TamperingDetectedError(CryptoError):
    """Raised when ciphertext authentication tag fails or data has been altered."""
    pass

class CipherService:
    def __init__(self, master_key_b64: str):
        if not master_key_b64 or master_key_b64.strip() == "":
            raise ValueError(
                "CIPHERNEST_ENCRYPTION_KEY is empty. "
                "Generate one using 'python generate_key.py' and set it in your .env file."
            )
        try:
            raw_key = base64.b64decode(master_key_b64)
        except Exception as e:
            raise ValueError(f"Invalid Base64 format for CIPHERNEST_ENCRYPTION_KEY: {e}")

        if len(raw_key) != 32:
            raise ValueError(
                f"Master key must be exactly 32 bytes (256 bits) for AES-256. Found {len(raw_key)} bytes."
            )
        self.master_key = raw_key

    def generate_salt(self) -> bytes:
        """Generates a cryptographically secure 16-byte random salt for a new file."""
        return os.urandom(16)

    def derive_file_key(self, file_id: str, salt: bytes) -> bytes:
        """
        Derives a unique 32-byte (256-bit) file-specific encryption key using HKDF-SHA256.
        Binds the master key, file-unique salt, and file_id info tag.
        """
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
            raise ValueError("Salt must be at least 16 bytes")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=f"ciphernest-v1-key:{file_id}".encode("utf-8"),
        )
        return hkdf.derive(self.master_key)

    def encrypt_chunk(
        self,
        file_key: bytes,
        plaintext: bytes,
        chunk_index: int,
        file_id: str,
    ) -> Tuple[bytes, bytes, str]:
        """
        Encrypts a single data block using AES-256-GCM.
        
        Returns:
            (ciphertext, nonce, ciphertext_sha256)
        """
        # 96-bit (12 bytes) standard nonce for AES-GCM
        nonce = os.urandom(12)
        
        # Additional Authenticated Data (AAD) binds the block to its file and sequence index
        aad = f"ciphernest-aad:{file_id}:{chunk_index}".encode("utf-8")
        
        aesgcm = AESGCM(file_key)
        # AESGCM.encrypt appends a 16-byte authentication tag to the returned ciphertext
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        
        # SHA-256 checksum of the encrypted block for integrity verification
        chunk_sha256 = hashlib.sha256(ciphertext).hexdigest()
        
        return ciphertext, nonce, chunk_sha256

    def decrypt_chunk(
        self,
        file_key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        chunk_index: int,
        file_id: str,
    ) -> bytes:
        """
        Decrypts an encrypted data block with AES-256-GCM and verifies authenticity.
        
        Raises:
            TamperingDetectedError: If the block was corrupted, modified, or reordered.
        """
        aad = f"ciphernest-aad:{file_id}:{chunk_index}".encode("utf-8")
        aesgcm = AESGCM(file_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext
        except InvalidTag as e:
            raise TamperingDetectedError(
                f"Tampering detected! Block {chunk_index} authentication tag verification failed. "
                "The encrypted data may be corrupted or modified."
            ) from e
        except Exception as e:
            raise CryptoError(f"Decryption failed for block {chunk_index}: {e}") from e
