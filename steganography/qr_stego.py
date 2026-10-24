"""
StegoVault - QR Code Security Module
Generates encrypted high-density QR code carriers and recovers hidden data using computer vision scanning.
"""

import os
import base64
from typing import Dict, Any
import qrcode
try:
    import cv2
except ImportError:
    cv2 = None
import numpy as np

QR_PREFIX = "STEGOQR:"


class QrStegoError(Exception):
    """Raised when QR code encoding or scanning fails."""
    pass


def encode_qr(payload: bytes, output_path: str, box_size: int = 10, border: int = 4) -> Dict[str, Any]:
    """
    Generate a QR code carrier concealing an encrypted binary payload.
    
    Parameters:
        payload: Binary data to conceal.
        output_path: Filepath where the QR image (.png) should be saved.
        box_size: Pixel size of each QR box.
        border: Border margin in boxes.
        
    Returns:
        Dictionary with QR generation statistics.
    """
    if not isinstance(payload, bytes) or len(payload) == 0:
        raise QrStegoError("Payload must be non-empty bytes.")

    # Encode payload to base64 with signature prefix
    b64_payload = base64.b64encode(payload).decode("ascii")
    qr_payload_string = f"{QR_PREFIX}{b64_payload}"

    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=box_size,
            border=border,
        )
        qr.add_data(qr_payload_string)
        qr.make(fit=True)

        # Standard high-contrast rendering for maximum computer vision readability
        img = qr.make_image(fill_color="black", back_color="white")

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        if not output_path.lower().endswith(".png"):
            output_path = os.path.splitext(output_path)[0] + ".png"

        with open(output_path, "wb") as f_out:
            img.save(f_out, format="PNG")

        width, height = img.size

        return {
            "success": True,
            "output_path": output_path,
            "qr_version": qr.version,
            "dimensions": f"{width}x{height} px",
            "payload_bytes": len(payload),
            "encoded_string_length": len(qr_payload_string),
        }
    except Exception as e:
        raise QrStegoError(f"Failed to generate secure QR code: {str(e)}")


def decode_qr(qr_image_path: str) -> bytes:
    """
    Scan a QR code image and extract the concealed encrypted binary payload.
    
    Parameters:
        qr_image_path: Path to QR code image file.
        
    Returns:
        Extracted raw payload bytes.
    """
    if not os.path.exists(qr_image_path):
        raise QrStegoError(f"QR code image not found: {qr_image_path}")

    data = ""
    try:
        from PIL import Image

        # Strategy 1: High-precision ZBar decoder
        try:
            from pyzbar.pyzbar import decode as zbar_decode
            with Image.open(qr_image_path) as pil_img:
                zbar_results = zbar_decode(pil_img)
                if zbar_results:
                    data = zbar_results[0].data.decode("utf-8")
        except Exception:
            data = ""

        # Strategy 2: OpenCV Computer Vision fallback
        if not data:
            if cv2 is not None:
                with Image.open(qr_image_path) as pil_img:
                    img = cv2.cvtColor(np.array(pil_img.convert("RGB")), cv2.COLOR_RGB2BGR)

                detector = cv2.QRCodeDetector()
                data, _, _ = detector.detectAndDecode(img)

                if not data:
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    _, thresh = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
                    data, _, _ = detector.detectAndDecode(thresh)
            else:
                raise QrStegoError("QR decoding engine unavailable (requires opencv-python-headless or pyzbar).")

        if not data:
            raise QrStegoError("No valid QR code symbol detected in image.")

        if not data.startswith(QR_PREFIX):
            raise QrStegoError(
                "Standard QR code detected, but it does not contain a StegoVault encrypted signature."
            )

        b64_payload = data[len(QR_PREFIX) :]
        return base64.b64decode(b64_payload)

    except Exception as e:
        if isinstance(e, QrStegoError):
            raise
        raise QrStegoError(f"QR decoding error: {str(e)}")
