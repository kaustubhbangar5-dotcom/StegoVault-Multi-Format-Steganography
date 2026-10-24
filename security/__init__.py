"""
StegoVault Security Module
Provides authenticated AES-256-GCM encryption with Scrypt Key Derivation Function (KDF).
"""

from .encryption import encrypt_message, decrypt_message, derive_key, SecurityError

__all__ = ["encrypt_message", "decrypt_message", "derive_key", "SecurityError"]
