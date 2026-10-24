"""
StegoVault - Image Steganography Decoder
Extracts embedded binary payloads from digital image carriers using Least Significant Bit (LSB) extraction.
"""

import os
from typing import Dict, Any
import numpy as np
from PIL import Image

MAGIC_HEADER = b"STEGO1"
HEADER_LEN = 10  # 6 bytes magic + 4 bytes payload length


class StegoError(Exception):
    """Base exception for steganography errors."""
    pass


def verify_carrier(stego_image_path: str) -> Dict[str, Any]:
    """
    Inspect an image file to determine if it contains an authentic StegoVault payload.
    
    Parameters:
        stego_image_path: Path to steganographic image.
        
    Returns:
        Dictionary indicating validity, embedded payload size, and carrier dimensions.
    """
    if not os.path.exists(stego_image_path):
        return {"has_payload": False, "error": "File does not exist"}

    try:
        with Image.open(stego_image_path) as img:
            width, height = img.size
            total_bits = width * height * 3
            if total_bits < HEADER_LEN * 8:
                return {"has_payload": False, "error": "Image too small to contain header"}

            img_array = np.array(img.convert("RGB"), dtype=np.uint8)
            channels = img_array[:, :, :3].reshape(-1)

            # Extract header bits
            header_bits = channels[: HEADER_LEN * 8] & 1
            header_bytes = np.packbits(header_bits).tobytes()

            if header_bytes[:6] != MAGIC_HEADER:
                return {
                    "has_payload": False,
                    "reason": "Magic header mismatch (no StegoVault signature found)"
                }

            payload_len = int.from_bytes(header_bytes[6:10], byteorder="big")
            total_required_bits = (HEADER_LEN + payload_len) * 8

            if total_required_bits > total_bits:
                return {
                    "has_payload": False,
                    "reason": "Corrupted header: Payload length exceeds carrier capacity"
                }

            return {
                "has_payload": True,
                "payload_bytes": payload_len,
                "width": width,
                "height": height,
                "total_available_bytes": total_bits // 8,
            }
    except Exception as e:
        return {"has_payload": False, "error": str(e)}


def decode_image(stego_image_path: str) -> bytes:
    """
    Extract embedded binary payload from a steganographic cover image.
    
    Parameters:
        stego_image_path: Path to the image file containing hidden data.
        
    Returns:
        Extracted raw bytes payload (ready for cryptographic decryption).
        
    Raises:
        StegoError: If the image is invalid, lacks a StegoVault signature, or is corrupted.
    """
    if not os.path.exists(stego_image_path):
        raise StegoError(f"Image not found at: {stego_image_path}")

    try:
        with Image.open(stego_image_path) as img:
            width, height = img.size
            total_available_bits = width * height * 3

            if total_available_bits < HEADER_LEN * 8:
                raise StegoError("Carrier image is too small to contain a StegoVault header.")

            img_array = np.array(img.convert("RGB"), dtype=np.uint8)
            channels = img_array[:, :, :3].reshape(-1)
    except Exception as e:
        if isinstance(e, StegoError):
            raise
        raise StegoError(f"Failed to read image carrier: {str(e)}")

    # Extract first 80 bits (10 bytes) for header validation
    header_bits = channels[: HEADER_LEN * 8] & 1
    header_bytes = np.packbits(header_bits).tobytes()

    magic = header_bytes[:6]
    if magic != MAGIC_HEADER:
        raise StegoError(
            "No valid StegoVault payload detected in image. "
            "The carrier either has no concealed data or was recompressed (e.g. converted to lossy JPEG)."
        )

    # Read payload length
    payload_len = int.from_bytes(header_bytes[6:10], byteorder="big")
    total_required_bits = (HEADER_LEN + payload_len) * 8

    if total_required_bits > total_available_bits:
        raise StegoError(
            f"Corrupted stego header: Header reports {payload_len} bytes, "
            f"which exceeds the carrier's capacity of {total_available_bits // 8} bytes."
        )

    # Extract payload bits
    payload_bits = channels[HEADER_LEN * 8 : total_required_bits] & 1
    payload_bytes = np.packbits(payload_bits).tobytes()

    return payload_bytes[:payload_len]
