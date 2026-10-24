"""
Unit and integration tests for Multi-Format Steganography:
- Phase 4: Audio Waveform Steganography
- Phase 5: PDF Concealment & Extraction
- Phase 6: QR Code Security & Computer Vision Scanning
- Phase 7: Cryptographic Validation & Dispatcher
"""

import os
import pytest
import numpy as np
import soundfile as sf
import pypdf

from security.encryption import encrypt_message, decrypt_message
from steganography.audio_stego import (
    encode_audio,
    decode_audio,
    calculate_audio_capacity,
    AudioCapacityError,
    AudioStegoError,
)
from steganography.pdf_stego import (
    encode_pdf,
    decode_pdf,
    calculate_pdf_capacity,
    PdfStegoError,
)
from steganography.qr_stego import encode_qr, decode_qr, QrStegoError
from steganography import encode_carrier, decode_carrier


def test_audio_steganography_roundtrip(tmp_path):
    # 1. Create a dummy 1-second stereo WAV file at 44.1kHz (88,200 total samples = ~11KB capacity)
    cover_audio = str(tmp_path / "test_carrier.wav")
    stego_audio = str(tmp_path / "test_stego.wav")

    sample_rate = 44100
    duration = 1.0
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    # Generate 440 Hz sine tone in 16-bit integer range
    sine_wave = (np.sin(2 * np.pi * 440 * t) * 15000).astype(np.int16)
    stereo_data = np.column_stack((sine_wave, sine_wave))
    sf.write(cover_audio, stereo_data, sample_rate, subtype="PCM_16")

    # Check capacity
    cap = calculate_audio_capacity(cover_audio)
    assert cap["total_samples"] == len(stereo_data) * 2
    assert cap["max_payload_bytes"] > 5000

    # 2. Encrypt secret payload
    secret = "Audio Waveform Classified Intelligence: Frequencies Locked 🛰️"
    passphrase = "SonicKey#2026"
    encrypted_payload = encrypt_message(secret, passphrase)

    # 3. Embed into audio
    res = encode_audio(cover_audio, encrypted_payload, stego_audio)
    assert res["success"] is True
    assert os.path.exists(stego_audio)

    # 4. Extract and Decrypt
    extracted_bytes = decode_audio(stego_audio)
    assert extracted_bytes == encrypted_payload

    recovered_text = decrypt_message(extracted_bytes, passphrase)
    assert recovered_text == secret


def test_audio_capacity_exceeded(tmp_path):
    cover_audio = str(tmp_path / "short.wav")
    stego_audio = str(tmp_path / "short_stego.wav")

    # Very short audio (100 samples = ~12 bytes capacity)
    short_data = np.zeros((100, 1), dtype=np.int16)
    sf.write(cover_audio, short_data, 44100, subtype="PCM_16")

    large_payload = b"X" * 100
    with pytest.raises(AudioCapacityError):
        encode_audio(cover_audio, large_payload, stego_audio)


def test_pdf_steganography_roundtrip(tmp_path):
    stego_pdf = str(tmp_path / "confidential_dossier.pdf")

    secret = "Operation StegoVault: PDF Document Infiltration Approved 📄🔐"
    passphrase = "ExecutiveClearance99"
    encrypted_payload = encrypt_message(secret, passphrase)

    # Encode with automatic clean carrier generation
    res = encode_pdf(None, encrypted_payload, stego_pdf)
    assert res["success"] is True
    assert os.path.exists(stego_pdf)

    # Inspect PDF capacity / pages
    cap = calculate_pdf_capacity(stego_pdf)
    assert cap["page_count"] >= 1

    # Extract and Decrypt
    extracted_bytes = decode_pdf(stego_pdf)
    assert extracted_bytes == encrypted_payload

    recovered_text = decrypt_message(extracted_bytes, passphrase)
    assert recovered_text == secret


def test_pdf_steganography_with_existing_cover(tmp_path):
    cover_pdf = str(tmp_path / "existing_cover.pdf")
    stego_pdf = str(tmp_path / "existing_stego.pdf")

    # Create a 2-page existing PDF
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=600, height=800)
    writer.add_blank_page(width=600, height=800)
    with open(cover_pdf, "wb") as f:
        writer.write(f)

    secret = "Dual-layer PDF attachment and catalog stream payload"
    password = "CustomCoverPassword"
    encrypted_payload = encrypt_message(secret, password)

    encode_pdf(cover_pdf, encrypted_payload, stego_pdf)
    extracted = decode_pdf(stego_pdf)
    assert decrypt_message(extracted, password) == secret


def test_qr_steganography_roundtrip(tmp_path):
    qr_path = str(tmp_path / "secure_qr.png")

    secret = "QR-Scan-Auth-Token: 9948-2831-VAULT-2026"
    passphrase = "QRPassphrase2026!"
    encrypted_payload = encrypt_message(secret, passphrase)

    # Generate QR Carrier
    res = encode_qr(encrypted_payload, qr_path)
    assert res["success"] is True
    assert os.path.exists(qr_path)

    # Decode QR using Computer Vision (OpenCV)
    extracted_bytes = decode_qr(qr_path)
    assert extracted_bytes == encrypted_payload

    recovered_text = decrypt_message(extracted_bytes, passphrase)
    assert recovered_text == secret


def test_universal_dispatcher(tmp_path):
    # Test unified encode_carrier and decode_carrier
    qr_out = str(tmp_path / "dispatch_qr.png")
    pdf_out = str(tmp_path / "dispatch_pdf.pdf")

    secret = "Universal Multi-Format Dispatcher Test"
    pwd = "DispatcherSecret"
    enc = encrypt_message(secret, pwd)

    # Dispatch QR
    encode_carrier("qr", None, enc, qr_out)
    assert decode_carrier(qr_out, "qr") == enc

    # Dispatch PDF with auto-detection
    encode_carrier("pdf", None, enc, pdf_out)
    assert decode_carrier(pdf_out, "auto") == enc
