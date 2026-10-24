"""
StegoVault - Multi-Format Web Application Backend
Flask server providing encryption, multi-format steganographic concealment, and payload extraction.
Supported Carriers: Images (LSB), Audio Waveforms (PCM LSB), PDF Documents, and Secure QR Codes.
"""

import os
import uuid
import time
import base64
from typing import Optional
from flask import Flask, render_template, request, send_from_directory, jsonify
from werkzeug.utils import secure_filename

from security.encryption import (
    encrypt_message,
    decrypt_message,
    analyze_security_envelope,
    SecurityError,
)
from steganography import (
    encode_carrier,
    decode_carrier,
    detect_carrier_type,
    calculate_image_capacity,
    calculate_audio_capacity,
    calculate_pdf_capacity,
    StegoError,
    CapacityError,
    AudioStegoError,
    AudioCapacityError,
    PdfStegoError,
    QrStegoError,
)

app = Flask(__name__)
app.secret_key = os.urandom(24)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# On serverless platforms (Vercel, AWS Lambda), write to ephemeral /tmp directory
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    OUTPUT_DIR = "/tmp/outputs"
else:
    OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

ALLOWED_IMAGE_EXTS = {"png", "jpg", "jpeg", "bmp"}
ALLOWED_AUDIO_EXTS = {"wav", "flac"}
ALLOWED_PDF_EXTS = {"pdf"}
ALLOWED_ALL_EXTS = ALLOWED_IMAGE_EXTS | ALLOWED_AUDIO_EXTS | ALLOWED_PDF_EXTS

app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB limit


def allowed_file(filename: str, allowed_extensions: set) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


@app.route("/favicon.ico")
def favicon():
    """Returns 204 No Content for favicon requests."""
    return "", 204


@app.route("/")
def index():
    """StegoVault landing dashboard."""
    return render_template("index.html")


@app.route("/encode", methods=["GET", "POST"])
def encode_route():
    """Handles multi-format concealment (Image, Audio, PDF, QR Code)."""
    if request.method == "GET":
        return render_template("encode.html")

    carrier_type = request.form.get("carrier_type", "image").lower().strip()
    secret_message = request.form.get("secret_message", "").strip()
    password = request.form.get("password", "").strip()

    if not secret_message:
        return render_template("encode.html", error="Secret message payload cannot be empty.")
    if not password:
        return render_template("encode.html", error="Encryption passphrase is required.")

    file = request.files.get("carrier_file")
    temp_input_path: Optional[str] = None
    output_filename = ""

    try:
        # Step 1: Authenticated Encryption (AES-256-GCM + Scrypt KDF)
        encrypted_payload = encrypt_message(secret_message, password)

        # Step 2: Handle Carrier-Specific Logic
        if carrier_type == "image":
            if not file or file.filename == "":
                return render_template("encode.html", error="Please upload a cover image (PNG, JPG, BMP).")
            if not allowed_file(file.filename, ALLOWED_IMAGE_EXTS):
                return render_template(
                    "encode.html",
                    error=f"Unsupported image format. Allowed: {', '.join(ALLOWED_IMAGE_EXTS)}",
                )
            temp_input_filename = f"temp_cover_{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            temp_input_path = os.path.join(OUTPUT_DIR, temp_input_filename)
            file.save(temp_input_path)

            output_filename = f"stego_img_{int(time.time())}_{uuid.uuid4().hex[:8]}.png"
            output_path = os.path.join(OUTPUT_DIR, output_filename)
            encode_stats = encode_carrier("image", temp_input_path, encrypted_payload, output_path)

        elif carrier_type == "audio":
            if not file or file.filename == "":
                return render_template("encode.html", error="Please upload a cover audio file (WAV, FLAC).")
            if not allowed_file(file.filename, ALLOWED_AUDIO_EXTS):
                return render_template(
                    "encode.html",
                    error=f"Unsupported audio format. Allowed: {', '.join(ALLOWED_AUDIO_EXTS)}",
                )
            temp_input_filename = f"temp_cover_{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            temp_input_path = os.path.join(OUTPUT_DIR, temp_input_filename)
            file.save(temp_input_path)

            output_filename = f"stego_audio_{int(time.time())}_{uuid.uuid4().hex[:8]}.wav"
            output_path = os.path.join(OUTPUT_DIR, output_filename)
            encode_stats = encode_carrier("audio", temp_input_path, encrypted_payload, output_path)

        elif carrier_type == "pdf":
            # Cover PDF is optional; if omitted, StegoVault generates a clean carrier
            if file and file.filename != "":
                if not allowed_file(file.filename, ALLOWED_PDF_EXTS):
                    return render_template("encode.html", error="Unsupported format. Only PDF files are accepted.")
                temp_input_filename = f"temp_cover_{uuid.uuid4().hex}_{secure_filename(file.filename)}"
                temp_input_path = os.path.join(OUTPUT_DIR, temp_input_filename)
                file.save(temp_input_path)

            output_filename = f"stego_doc_{int(time.time())}_{uuid.uuid4().hex[:8]}.pdf"
            output_path = os.path.join(OUTPUT_DIR, output_filename)
            encode_stats = encode_carrier("pdf", temp_input_path, encrypted_payload, output_path)

        elif carrier_type == "qr":
            output_filename = f"stego_qr_{int(time.time())}_{uuid.uuid4().hex[:8]}.png"
            output_path = os.path.join(OUTPUT_DIR, output_filename)
            encode_stats = encode_carrier("qr", None, encrypted_payload, output_path)

        else:
            return render_template("encode.html", error=f"Unknown carrier type '{carrier_type}'.")

        # Step 3: Cryptographic Audit Envelope
        security_audit = analyze_security_envelope(encrypted_payload)

        # Read generated stego file bytes for stateless client-side download & preview
        b64_file_data = ""
        mime_type = "application/octet-stream"
        if os.path.exists(output_path):
            with open(output_path, "rb") as f_out:
                b64_file_data = base64.b64encode(f_out.read()).decode("ascii")

            mime_map = {
                "png": "image/png",
                "jpg": "image/jpeg",
                "jpeg": "image/jpeg",
                "bmp": "image/bmp",
                "wav": "audio/wav",
                "flac": "audio/flac",
                "pdf": "application/pdf",
            }
            ext = output_filename.rsplit(".", 1)[-1].lower() if "." in output_filename else "bin"
            mime_type = mime_map.get(ext, "application/octet-stream")

        result_payload = {
            "carrier_type": carrier_type,
            "download_filename": output_filename,
            "payload_bytes": len(encrypted_payload),
            "stats": encode_stats,
            "security_audit": security_audit,
            "b64_data": b64_file_data,
            "mime_type": mime_type,
        }

        return render_template("encode.html", success=True, result=result_payload)

    except (CapacityError, AudioCapacityError) as ce:
        return render_template("encode.html", error=f"Carrier Capacity Exceeded: {str(ce)}")
    except (SecurityError, StegoError, AudioStegoError, PdfStegoError, QrStegoError) as se:
        return render_template("encode.html", error=str(se))
    except Exception as e:
        return render_template("encode.html", error=f"An unexpected error occurred: {str(e)}")
    finally:
        if temp_input_path and os.path.exists(temp_input_path):
            try:
                os.remove(temp_input_path)
            except OSError:
                pass


@app.route("/decode", methods=["GET", "POST"])
def decode_route():
    """Universal carrier extraction & decryption (Image, Audio, PDF, QR Code)."""
    if request.method == "GET":
        return render_template("decode.html")

    file = request.files.get("stego_file") or request.files.get("stego_image")
    password = request.form.get("password", "").strip()
    forced_type = request.form.get("carrier_type", "auto").strip().lower()

    if not file or file.filename == "":
        return render_template("decode.html", error="Please upload a steganographic carrier file.")

    if not password:
        return render_template("decode.html", error="Decryption passphrase is required.")

    filename = secure_filename(file.filename)
    temp_stego_path = os.path.join(OUTPUT_DIR, f"temp_decode_{uuid.uuid4().hex}_{filename}")

    try:
        file.save(temp_stego_path)

        # Step 1: Universal payload extraction with automatic format detection
        extracted_payload = decode_carrier(temp_stego_path, forced_type)

        # Step 2: Authenticated AES-256-GCM decryption
        decrypted_secret = decrypt_message(extracted_payload, password)

        # Step 3: Security audit metadata
        audit = analyze_security_envelope(extracted_payload)

        inferred_format = detect_carrier_type(temp_stego_path)
        if inferred_format == "image" and forced_type == "qr":
            inferred_format = "qr"

        result_payload = {
            "secret_message": decrypted_secret,
            "secret_length": len(decrypted_secret),
            "payload_bytes": len(extracted_payload),
            "carrier_format": inferred_format.upper(),
            "audit": audit,
        }

        return render_template("decode.html", success=True, result=result_payload)

    except (SecurityError, StegoError, AudioStegoError, PdfStegoError, QrStegoError) as se:
        return render_template("decode.html", error=str(se))
    except Exception as e:
        return render_template("decode.html", error=f"Extraction failure: {str(e)}")
    finally:
        if os.path.exists(temp_stego_path):
            try:
                os.remove(temp_stego_path)
            except OSError:
                pass


@app.route("/download/<path:filename>")
def download_file(filename: str):
    """Safely serves processed stego files for download."""
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


@app.route("/api/capacity", methods=["POST"])
def api_capacity():
    """REST endpoint to calculate carrier capacity from an uploaded carrier."""
    file = request.files.get("file") or request.files.get("image")
    carrier_type = request.form.get("carrier_type", "image").lower()

    if not file or file.filename == "":
        return jsonify({"error": "Empty filename or no file provided"}), 400

    temp_path = os.path.join(OUTPUT_DIR, f"temp_cap_{uuid.uuid4().hex}.tmp")
    try:
        file.save(temp_path)
        if carrier_type == "audio":
            cap = calculate_audio_capacity(temp_path)
        elif carrier_type == "pdf":
            cap = calculate_pdf_capacity(temp_path)
        else:
            cap = calculate_image_capacity(temp_path)

        return jsonify({"success": True, "capacity": cap})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@app.route("/api/health")
def api_health():
    """Health check endpoint confirming cryptographic and multi-format subsystems."""
    return jsonify({
        "status": "operational",
        "system": "StegoVault",
        "version": "2.0.0",
        "supported_carriers": ["image", "audio", "pdf", "qr"],
        "security": {
            "cipher": "AES-256-GCM",
            "kdf": "Scrypt (N=16384, r=8, p=1)",
            "auth_tag_bits": 128,
            "salt_bits": 128,
            "nonce_bits": 96,
        },
        "protocols": {
            "image": "LSB (RGB Channels, STEGO1 framing)",
            "audio": "16-bit PCM LSB (STEGA1 framing)",
            "pdf": "Dual-Layer (Private Catalog Metadata + Embedded Stream)",
            "qr": "Computer Vision Scanning + Base64 Envelope",
        },
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
