"""
StegoVault - Image Steganography Encoder
Embeds binary payloads inside digital image carriers using Least Significant Bit (LSB) manipulation.

Framing Protocol:
- Magic Marker: b"STEGO1" (6 bytes)
- Payload Length: 4 bytes unsigned int (big-endian)
- Total Header: 10 bytes (80 bits)
- Payload: Encrypted binary data
"""

import os
from typing import Dict, Any, Tuple
import numpy as np
from PIL import Image

MAGIC_HEADER = b"STEGO1"
HEADER_LEN = 10  # 6 bytes magic + 4 bytes length


class StegoError(Exception):
    """Base exception for steganography errors."""
    pass


class CapacityError(StegoError):
    """Raised when the payload exceeds the carrier's bit capacity."""
    pass


def calculate_image_capacity(image_or_path: Any) -> Dict[str, Any]:
    """
    Calculate maximum embeddable capacity of an image in bits, bytes, and characters.
    
    Parameters:
        image_or_path: Path to image or PIL Image object.
        
    Returns:
        Dictionary with dimensions, total bits, capacity in bytes, and max payload bytes.
    """
    if isinstance(image_or_path, str):
        if not os.path.exists(image_or_path):
            raise FileNotFoundError(f"Image not found at {image_or_path}")
        img = Image.open(image_or_path)
    else:
        img = image_or_path

    width, height = img.size
    # 3 channels (R, G, B) - 1 bit per channel
    total_bits = width * height * 3
    total_bytes = total_bits // 8
    max_payload_bytes = max(0, total_bytes - HEADER_LEN)

    return {
        "width": width,
        "height": height,
        "total_pixels": width * height,
        "total_available_bits": total_bits,
        "total_carrier_bytes": total_bytes,
        "max_payload_bytes": max_payload_bytes,
        "recommended_max_chars": max_payload_bytes - 44,  # Accounting for AES-256-GCM overhead
    }


def encode_image(carrier_image_path: str, payload: bytes, output_path: str) -> Dict[str, Any]:
    """
    Embed a binary payload into a carrier image using RGB LSB substitution.
    
    Parameters:
        carrier_image_path: Path to the input cover image.
        payload: Binary data to conceal.
        output_path: Filepath where the steganographic PNG should be saved.
        
    Returns:
        Dictionary containing encoding statistics and metrics.
        
    Raises:
        CapacityError: If payload exceeds carrier limits.
        StegoError: For invalid inputs or image processing failures.
    """
    if not os.path.exists(carrier_image_path):
        raise StegoError(f"Carrier image does not exist: {carrier_image_path}")
    if not isinstance(payload, bytes) or len(payload) == 0:
        raise StegoError("Payload must be non-empty bytes.")

    try:
        with Image.open(carrier_image_path) as img:
            # Normalize to RGB (or RGBA preserving Alpha)
            has_alpha = img.mode == "RGBA"
            if img.mode not in ("RGB", "RGBA"):
                img = img.convert("RGB")
                has_alpha = False

            width, height = img.size
            img_array = np.array(img, dtype=np.uint8)
    except Exception as e:
        raise StegoError(f"Failed to load carrier image: {str(e)}")

    # Frame the payload: [MAGIC (6B) | LENGTH (4B) | PAYLOAD]
    header = MAGIC_HEADER + len(payload).to_bytes(4, byteorder="big")
    stream = header + payload
    stream_bits = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))
    total_bits_needed = len(stream_bits)

    total_available_bits = width * height * 3
    if total_bits_needed > total_available_bits:
        raise CapacityError(
            f"Payload requires {total_bits_needed // 8} bytes ({total_bits_needed} bits), "
            f"but carrier only supports {total_available_bits // 8} bytes ({total_available_bits} bits)."
        )

    # Work directly on RGB channels
    rgb_channels = img_array[:, :, :3].reshape(-1)

    # Embed bitstream into LSBs
    rgb_channels[:total_bits_needed] = (rgb_channels[:total_bits_needed] & 0xFE) | stream_bits

    # Write back modified RGB channels
    img_array[:, :, :3] = rgb_channels.reshape(height, width, 3)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Save as lossless PNG to protect LSBs against compression distortion
    if not output_path.lower().endswith(".png"):
        output_path = os.path.splitext(output_path)[0] + ".png"

    output_img = Image.fromarray(img_array)
    output_img.save(output_path, format="PNG", optimize=False)

    capacity_used_pct = round((total_bits_needed / total_available_bits) * 100, 3)

    return {
        "success": True,
        "output_path": output_path,
        "carrier_width": width,
        "carrier_height": height,
        "total_pixels": width * height,
        "total_bits_embedded": int(total_bits_needed),
        "payload_bytes": len(payload),
        "total_stream_bytes": len(stream),
        "capacity_used_percent": capacity_used_pct,
        "available_capacity_bytes": total_available_bits // 8,
    }
