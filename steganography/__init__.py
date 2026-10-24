"""
StegoVault Steganography Subsystem
Exposes unified multi-format steganography engines for Images, Audio, PDF Documents, and QR Codes.
"""

import os
from typing import Dict, Any, Optional

from .encoder import encode_image, calculate_image_capacity, StegoError, CapacityError
from .decoder import decode_image, verify_carrier
from .audio_stego import encode_audio, decode_audio, calculate_audio_capacity, AudioStegoError, AudioCapacityError
from .pdf_stego import encode_pdf, decode_pdf, calculate_pdf_capacity, PdfStegoError
from .qr_stego import encode_qr, decode_qr, QrStegoError

__all__ = [
    # Image
    "encode_image",
    "decode_image",
    "calculate_image_capacity",
    "verify_carrier",
    "StegoError",
    "CapacityError",
    # Audio
    "encode_audio",
    "decode_audio",
    "calculate_audio_capacity",
    "AudioStegoError",
    "AudioCapacityError",
    # PDF
    "encode_pdf",
    "decode_pdf",
    "calculate_pdf_capacity",
    "PdfStegoError",
    # QR
    "encode_qr",
    "decode_qr",
    "QrStegoError",
    # Unified dispatcher
    "encode_carrier",
    "decode_carrier",
    "detect_carrier_type",
]


def detect_carrier_type(file_path: str) -> str:
    """
    Infer carrier format based on file extension and inspection.
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".wav", ".flac"):
        return "audio"
    if ext == ".pdf":
        return "pdf"
    if ext in (".png", ".jpg", ".jpeg", ".bmp"):
        # Could be image or QR code; caller can specify or try image then QR
        return "image"
    return "unknown"


def encode_carrier(
    carrier_type: str,
    cover_path: Optional[str],
    payload: bytes,
    output_path: str,
) -> Dict[str, Any]:
    """
    Universal multi-format carrier encoder dispatcher.
    """
    carrier_type = carrier_type.lower()
    if carrier_type == "image":
        return encode_image(cover_path, payload, output_path)
    elif carrier_type == "audio":
        return encode_audio(cover_path, payload, output_path)
    elif carrier_type == "pdf":
        return encode_pdf(cover_path, payload, output_path)
    elif carrier_type == "qr":
        return encode_qr(payload, output_path)
    else:
        raise ValueError(f"Unsupported carrier type: '{carrier_type}'. Choose from image, audio, pdf, qr.")


def decode_carrier(carrier_path: str, carrier_type: Optional[str] = None) -> bytes:
    """
    Universal multi-format carrier decoder dispatcher with auto-fallback.
    """
    if not carrier_type or carrier_type == "auto":
        inferred = detect_carrier_type(carrier_path)
        if inferred == "audio":
            return decode_audio(carrier_path)
        elif inferred == "pdf":
            return decode_pdf(carrier_path)
        else:
            # First try image LSB stego; if header fails, try QR scan!
            try:
                return decode_image(carrier_path)
            except Exception as img_err:
                try:
                    return decode_qr(carrier_path)
                except Exception:
                    raise img_err

    carrier_type = carrier_type.lower()
    if carrier_type == "image":
        return decode_image(carrier_path)
    elif carrier_type == "audio":
        return decode_audio(carrier_path)
    elif carrier_type == "pdf":
        return decode_pdf(carrier_path)
    elif carrier_type == "qr":
        return decode_qr(carrier_path)
    else:
        raise ValueError(f"Unknown carrier type: '{carrier_type}'")
