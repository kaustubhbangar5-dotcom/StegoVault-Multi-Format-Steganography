"""
StegoVault - Cryptographic Security Layer
Implements AES-256-GCM authenticated encryption paired with Scrypt Key Derivation Function.

Payload Binary Layout:
[ Salt (16 bytes) | Nonce (12 bytes) | Ciphertext + Auth Tag (Variable + 16 bytes) ]
Total Overhead: 44 bytes
"""

import os
from typing import Dict, Any, Union
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class SecurityError(Exception):
    """Raised when encryption or decryption fails due to invalid parameters, bad password, or tampering."""
    pass


def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derive a 256-bit cryptographic key from a passphrase and salt using Scrypt KDF.
    
    Parameters:
        password: User-supplied passphrase string.
        salt: 16-byte cryptographically random salt.
        length: Desired key length in bytes (32 bytes = 256 bits).
        
    Returns:
        32-byte derived symmetric key.
    """
    if not password:
        raise SecurityError("Password cannot be empty.")
    if len(salt) < 16:
        raise SecurityError("Salt must be at least 16 bytes long.")

    kdf = Scrypt(
        salt=salt,
        length=length,
        n=2**14,  # CPU/memory cost parameter (16384)
        r=8,      # Block size parameter
        p=1,      # Parallelization parameter
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(plaintext: Union[str, bytes], password: str) -> bytes:
    """
    Encrypt a plaintext message using AES-256-GCM with a Scrypt-derived key.
    
    Parameters:
        plaintext: The message text or raw bytes to conceal.
        password: Secret key passphrase.
        
    Returns:
        Packaged binary payload: Salt (16B) + Nonce (12B) + Ciphertext & Auth Tag.
    """
    if isinstance(plaintext, str):
        data = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytes):
        data = plaintext
    else:
        raise SecurityError("Plaintext must be a string or bytes.")

    if not data:
        raise SecurityError("Plaintext payload cannot be empty.")
    if not password:
        raise SecurityError("Password is required for encryption.")

    # 1. Generate cryptographically secure random salt (16 bytes)
    salt = os.urandom(16)

    # 2. Derive 256-bit encryption key using Scrypt KDF
    key = derive_key(password, salt)

    # 3. Generate standard 96-bit (12-byte) nonce for AES-GCM
    nonce = os.urandom(12)

    # 4. Encrypt with AES-256-GCM (produces ciphertext + 16-byte authentication tag)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, associated_data=None)

    # 5. Pack: Salt (16B) + Nonce (12B) + [Ciphertext + Tag]
    return salt + nonce + ciphertext_with_tag


def decrypt_message(payload: bytes, password: str) -> str:
    """
    Authenticate and decrypt an AES-256-GCM payload using the provided password.
    
    Parameters:
        payload: Binary payload containing Salt (16B) + Nonce (12B) + Ciphertext + Tag.
        password: Secret key passphrase.
        
    Returns:
        Decrypted plaintext message as a UTF-8 string.
        
    Raises:
        SecurityError: If password is incorrect or payload has been tampered with.
    """
    if not isinstance(payload, bytes):
        raise SecurityError("Payload must be raw bytes.")
    if len(payload) < 44:  # 16 (salt) + 12 (nonce) + 16 (tag) + at least 0 byte data
        raise SecurityError("Invalid payload: Data is shorter than the minimum cryptographic envelope.")
    if not password:
        raise SecurityError("Password is required for decryption.")

    # Unpack components
    salt = payload[:16]
    nonce = payload[16:28]
    ciphertext_with_tag = payload[28:]

    try:
        # Derive key using extracted salt
        key = derive_key(password, salt)

        # Decrypt and authenticate using AES-GCM
        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
        return decrypted_bytes.decode("utf-8")
    except InvalidTag:
        raise SecurityError("Decryption failed: Incorrect password or corrupted payload (tag authentication failed).")
    except UnicodeDecodeError:
        raise SecurityError("Decryption failed: Decrypted bytes could not be decoded as UTF-8 text.")
    except Exception as e:
        if isinstance(e, SecurityError):
            raise
        raise SecurityError(f"Decryption error: {str(e)}")


def analyze_security_envelope(payload: bytes) -> Dict[str, Any]:
    """
    Extract security metadata from an encrypted envelope for auditing and UI inspection.
    """
    if len(payload) < 44:
        return {"valid": False, "reason": "Payload too small for AES-256-GCM envelope"}

    salt = payload[:16]
    nonce = payload[16:28]
    ciphertext_and_tag = payload[28:]
    tag = ciphertext_and_tag[-16:] if len(ciphertext_and_tag) >= 16 else b""
    ciphertext = ciphertext_and_tag[:-16] if len(ciphertext_and_tag) >= 16 else b""

    return {
        "valid": True,
        "algorithm": "AES-256-GCM",
        "kdf": "Scrypt (N=16384, r=8, p=1)",
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "auth_tag_hex": tag.hex(),
        "ciphertext_length_bytes": len(ciphertext),
        "envelope_overhead_bytes": 44,
        "total_payload_bytes": len(payload),
    }
