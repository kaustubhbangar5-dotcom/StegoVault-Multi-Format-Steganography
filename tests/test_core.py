"""
Unit and integration tests for StegoVault security and steganography engines.
"""

import os
import pytest
import numpy as np
from PIL import Image

from security.encryption import encrypt_message, decrypt_message, SecurityError, analyze_security_envelope
from steganography.encoder import encode_image, calculate_image_capacity, CapacityError
from steganography.decoder import decode_image, verify_carrier


def test_encryption_decryption_cycle():
    secret = "TopSecretPassword123! Classified Payload with Unicode: 🔐✨"
    passphrase = "MasterCyberKey#2026"

    # Encrypt
    encrypted_payload = encrypt_message(secret, passphrase)
    assert isinstance(encrypted_payload, bytes)
    assert len(encrypted_payload) > len(secret.encode("utf-8"))

    # Decrypt
    decrypted = decrypt_message(encrypted_payload, passphrase)
    assert decrypted == secret


def test_encryption_wrong_password():
    secret = "Confidential message"
    encrypted_payload = encrypt_message(secret, "CorrectPassword")

    with pytest.raises(SecurityError) as exc_info:
        decrypt_message(encrypted_payload, "WrongPassword")
    assert "Decryption failed" in str(exc_info.value)


def test_tampered_ciphertext():
    secret = "Integrity check message"
    encrypted_payload = bytearray(encrypt_message(secret, "Password123"))

    # Tamper with the last byte of ciphertext/tag
    encrypted_payload[-1] ^= 0xFF

    with pytest.raises(SecurityError):
        decrypt_message(bytes(encrypted_payload), "Password123")


def test_security_envelope_analysis():
    secret = "Audit test payload"
    encrypted_payload = encrypt_message(secret, "SecKey99")
    analysis = analyze_security_envelope(encrypted_payload)

    assert analysis["valid"] is True
    assert analysis["algorithm"] == "AES-256-GCM"
    assert "salt_hex" in analysis
    assert "nonce_hex" in analysis
    assert "auth_tag_hex" in analysis


def test_steganography_roundtrip(tmp_path):
    # Create test carrier image (100x100 RGB)
    cover_path = str(tmp_path / "test_carrier.png")
    stego_path = str(tmp_path / "test_stego.png")

    img_data = (np.random.rand(100, 100, 3) * 255).astype(np.uint8)
    Image.fromarray(img_data).save(cover_path)

    # Check capacity
    capacity = calculate_image_capacity(cover_path)
    assert capacity["width"] == 100
    assert capacity["height"] == 100
    assert capacity["total_available_bits"] == 30000

    # Secret message and encryption
    secret = "StegoVault Zero-Knowledge Concealment!"
    passphrase = "UltraVaultKey2026!"
    encrypted_data = encrypt_message(secret, passphrase)

    # Encode into image
    encode_res = encode_image(cover_path, encrypted_data, stego_path)
    assert encode_res["success"] is True
    assert os.path.exists(stego_path)

    # Verify carrier detection
    carrier_check = verify_carrier(stego_path)
    assert carrier_check["has_payload"] is True
    assert carrier_check["payload_bytes"] == len(encrypted_data)

    # Decode payload
    extracted_bytes = decode_image(stego_path)
    assert extracted_bytes == encrypted_data

    # Decrypt extracted payload
    recovered_text = decrypt_message(extracted_bytes, passphrase)
    assert recovered_text == secret


def test_steganography_capacity_limit(tmp_path):
    # Small 10x10 carrier = 300 bits total (max ~37 bytes)
    cover_path = str(tmp_path / "tiny.png")
    stego_path = str(tmp_path / "tiny_stego.png")

    img_data = np.zeros((10, 10, 3), dtype=np.uint8)
    Image.fromarray(img_data).save(cover_path)

    # Create large payload that exceeds capacity
    large_payload = b"A" * 200

    with pytest.raises(CapacityError):
        encode_image(cover_path, large_payload, stego_path)
