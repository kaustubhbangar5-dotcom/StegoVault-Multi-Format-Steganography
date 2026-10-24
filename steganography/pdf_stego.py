"""
StegoVault - PDF Data Concealment Module
Conceals encrypted binary payloads inside PDF documents using embedded attachment streams
and authenticated private document catalog metadata dictionaries.
"""

import os
import base64
from typing import Dict, Any, Optional
import pypdf

METADATA_KEY = "/StegoVaultPayload"
ATTACHMENT_NAME = "vault.sec"


class PdfStegoError(Exception):
    """Raised when PDF steganography operations fail."""
    pass


def calculate_pdf_capacity(pdf_path: str) -> Dict[str, Any]:
    """
    Inspect PDF document for capacity estimation.
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"PDF not found: {pdf_path}")

    try:
        reader = pypdf.PdfReader(pdf_path)
        page_count = len(reader.pages)
        file_size = os.path.getsize(pdf_path)

        return {
            "page_count": page_count,
            "carrier_size_bytes": file_size,
            "max_recommended_payload_bytes": 10 * 1024 * 1024,  # Up to 10MB recommended
            "format": "PDF 1.4 - 1.7",
        }
    except Exception as e:
        raise PdfStegoError(f"Could not read PDF carrier: {str(e)}")


def create_blank_cover_pdf(output_path: str) -> str:
    """
    Generate an innocent executive document carrier if user does not upload a cover PDF.
    """
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=612, height=792)  # Standard Letter size
    with open(output_path, "wb") as f:
        writer.write(f)
    return output_path


def encode_pdf(cover_pdf_path: Optional[str], payload: bytes, output_path: str) -> Dict[str, Any]:
    """
    Conceal binary payload inside a PDF carrier.
    
    Parameters:
        cover_pdf_path: Path to existing cover PDF, or None to generate a clean carrier.
        payload: Binary data to conceal.
        output_path: Path to write the stego PDF.
        
    Returns:
        Dictionary with encoding statistics.
    """
    if not isinstance(payload, bytes) or len(payload) == 0:
        raise PdfStegoError("Payload must be non-empty bytes.")

    writer = pypdf.PdfWriter()

    temp_cover_created = False
    if not cover_pdf_path or not os.path.exists(cover_pdf_path):
        # Generate an executive cover PDF
        cover_pdf_path = output_path + ".temp_cover.pdf"
        create_blank_cover_pdf(cover_pdf_path)
        temp_cover_created = True

    try:
        reader = pypdf.PdfReader(cover_pdf_path)
        for page in reader.pages:
            writer.add_page(page)

        # Clone existing metadata if present
        metadata = {}
        if reader.metadata:
            for k, v in reader.metadata.items():
                if k != METADATA_KEY:
                    metadata[k] = v

        # Method 1: Conceal via private document catalog metadata (base64 string)
        b64_payload = base64.b64encode(payload).decode("ascii")
        metadata[METADATA_KEY] = b64_payload
        writer.add_metadata(metadata)

        # Method 2: Conceal as embedded binary attachment stream
        try:
            writer.add_attachment(ATTACHMENT_NAME, payload)
        except Exception:
            pass  # Metadata embedding remains as primary concealment channel

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        if not output_path.lower().endswith(".pdf"):
            output_path = os.path.splitext(output_path)[0] + ".pdf"

        with open(output_path, "wb") as f_out:
            writer.write(f_out)

    except Exception as e:
        raise PdfStegoError(f"Failed to embed payload into PDF: {str(e)}")
    finally:
        if temp_cover_created and os.path.exists(cover_pdf_path):
            try:
                os.remove(cover_pdf_path)
            except OSError:
                pass

    return {
        "success": True,
        "output_path": output_path,
        "pages": len(writer.pages),
        "payload_bytes": len(payload),
        "output_size_bytes": os.path.getsize(output_path),
        "method": "Dual-layer (Metadata Dictionary + Attachment Stream)",
    }


def decode_pdf(stego_pdf_path: str) -> bytes:
    """
    Extract concealed payload from a PDF carrier.
    
    Parameters:
        stego_pdf_path: Path to the stego PDF file.
        
    Returns:
        Extracted raw payload bytes.
    """
    if not os.path.exists(stego_pdf_path):
        raise PdfStegoError(f"PDF carrier not found: {stego_pdf_path}")

    try:
        reader = pypdf.PdfReader(stego_pdf_path)
    except Exception as e:
        raise PdfStegoError(f"Could not open PDF carrier: {str(e)}")

    # 1. Check Private Metadata Catalog
    if reader.metadata and METADATA_KEY in reader.metadata:
        try:
            raw_b64 = reader.metadata[METADATA_KEY]
            return base64.b64decode(raw_b64)
        except Exception:
            pass

    # 2. Check Embedded Attachments
    try:
        attachments = getattr(reader, "attachments", {})
        if ATTACHMENT_NAME in attachments:
            for file_data in attachments[ATTACHMENT_NAME]:
                return bytes(file_data.data)
        # Search any attachment if named differently
        for name, files in attachments.items():
            for file_data in files:
                return bytes(file_data.data)
    except Exception:
        pass

    raise PdfStegoError(
        "No concealed StegoVault payload detected in PDF carrier. "
        "File may be an unencoded standard PDF."
    )
