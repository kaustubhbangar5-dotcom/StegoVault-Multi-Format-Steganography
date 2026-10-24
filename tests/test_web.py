"""
Web endpoint and multi-carrier integration tests for StegoVault Flask application.
"""

import io
import re
import pytest
import numpy as np
import soundfile as sf
import pypdf
from PIL import Image

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def create_dummy_image_bytes(width=100, height=100):
    img = Image.fromarray((np.random.rand(height, width, 3) * 255).astype(np.uint8))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def create_dummy_audio_bytes(duration=1.0, sample_rate=44100):
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    sine = (np.sin(2 * np.pi * 440 * t) * 15000).astype(np.int16)
    stereo = np.column_stack((sine, sine))
    buf = io.BytesIO()
    sf.write(buf, stereo, sample_rate, format="WAV", subtype="PCM_16")
    buf.seek(0)
    return buf


def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"StegoVault" in response.data
    assert b"Hide the Signal. Protect the Secret." in response.data


def test_encode_page_get(client):
    response = client.get("/encode")
    assert response.status_code == 200
    assert b"Conceal Secret Payload" in response.data
    assert b"Select Carrier Architecture" in response.data


def test_decode_page_get(client):
    response = client.get("/decode")
    assert response.status_code == 200
    assert b"Universal Extraction Terminal" in response.data


def test_api_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "operational"
    assert "audio" in data["supported_carriers"]
    assert "pdf" in data["supported_carriers"]
    assert "qr" in data["supported_carriers"]


def test_web_image_encode_and_decode(client):
    img_bytes = create_dummy_image_bytes(120, 120)
    secret = "Top-Secret-Coordinates: 40.7128N, 74.0060W"
    password = "SuperSecretKey99!"

    # 1. Encode Image
    data = {
        "carrier_type": "image",
        "carrier_file": (img_bytes, "test_carrier.png"),
        "secret_message": secret,
        "password": password,
    }
    encode_resp = client.post("/encode", data=data, content_type="multipart/form-data")
    assert encode_resp.status_code == 200
    assert b"Payload Concealed Successfully" in encode_resp.data

    match = re.search(r'/download/(stego_img_\w+\.png)', encode_resp.data.decode("utf-8"))
    assert match is not None
    download_filename = match.group(1)

    # 2. Download stego image
    download_resp = client.get(f"/download/{download_filename}")
    assert download_resp.status_code == 200

    # 3. Decode with correct password
    decode_data = {
        "carrier_type": "image",
        "stego_file": (io.BytesIO(download_resp.data), "downloaded_stego.png"),
        "password": password,
    }
    decode_resp = client.post("/decode", data=decode_data, content_type="multipart/form-data")
    assert decode_resp.status_code == 200
    assert secret.encode("utf-8") in decode_resp.data
    assert b"Payload Recovered" in decode_resp.data

    # 4. Decode with wrong password
    wrong_decode_data = {
        "carrier_type": "image",
        "stego_file": (io.BytesIO(download_resp.data), "downloaded_stego.png"),
        "password": "WrongPassword123!",
    }
    fail_resp = client.post("/decode", data=wrong_decode_data, content_type="multipart/form-data")
    assert fail_resp.status_code == 200
    assert b"Extraction / Decryption Failed" in fail_resp.data


def test_web_audio_encode_and_decode(client):
    audio_bytes = create_dummy_audio_bytes(1.0)
    secret = "Audio Wave Secret Transmission #44"
    password = "AudioKey2026!"

    # 1. Encode Audio
    data = {
        "carrier_type": "audio",
        "carrier_file": (audio_bytes, "sound_cover.wav"),
        "secret_message": secret,
        "password": password,
    }
    encode_resp = client.post("/encode", data=data, content_type="multipart/form-data")
    assert encode_resp.status_code == 200
    assert b"Payload Concealed Successfully" in encode_resp.data

    match = re.search(r'/download/(stego_audio_\w+\.wav)', encode_resp.data.decode("utf-8"))
    assert match is not None
    download_filename = match.group(1)

    download_resp = client.get(f"/download/{download_filename}")
    assert download_resp.status_code == 200

    # 2. Decode Audio
    decode_data = {
        "carrier_type": "audio",
        "stego_file": (io.BytesIO(download_resp.data), "stego_audio.wav"),
        "password": password,
    }
    decode_resp = client.post("/decode", data=decode_data, content_type="multipart/form-data")
    assert decode_resp.status_code == 200
    assert secret.encode("utf-8") in decode_resp.data


def test_web_pdf_encode_and_decode(client):
    secret = "Classified PDF Document Payload Directive 007"
    password = "ExecutivePdfPassphrase"

    # 1. Encode PDF (auto-generated cover)
    data = {
        "carrier_type": "pdf",
        "secret_message": secret,
        "password": password,
    }
    encode_resp = client.post("/encode", data=data, content_type="multipart/form-data")
    assert encode_resp.status_code == 200
    assert b"Payload Concealed Successfully" in encode_resp.data

    match = re.search(r'/download/(stego_doc_\w+\.pdf)', encode_resp.data.decode("utf-8"))
    assert match is not None
    download_filename = match.group(1)

    download_resp = client.get(f"/download/{download_filename}")
    assert download_resp.status_code == 200

    # 2. Decode PDF
    decode_data = {
        "carrier_type": "pdf",
        "stego_file": (io.BytesIO(download_resp.data), "stego_doc.pdf"),
        "password": password,
    }
    decode_resp = client.post("/decode", data=decode_data, content_type="multipart/form-data")
    assert decode_resp.status_code == 200
    assert secret.encode("utf-8") in decode_resp.data


def test_web_qr_encode_and_decode(client):
    secret = "QR-AirGapped-Payload-2026"
    password = "QrPassphrase99"

    # 1. Encode QR
    data = {
        "carrier_type": "qr",
        "secret_message": secret,
        "password": password,
    }
    encode_resp = client.post("/encode", data=data, content_type="multipart/form-data")
    assert encode_resp.status_code == 200
    assert b"Payload Concealed Successfully" in encode_resp.data

    match = re.search(r'/download/(stego_qr_\w+\.png)', encode_resp.data.decode("utf-8"))
    assert match is not None
    download_filename = match.group(1)

    download_resp = client.get(f"/download/{download_filename}")
    assert download_resp.status_code == 200

    # 2. Decode QR
    decode_data = {
        "carrier_type": "qr",
        "stego_file": (io.BytesIO(download_resp.data), "stego_qr.png"),
        "password": password,
    }
    decode_resp = client.post("/decode", data=decode_data, content_type="multipart/form-data")
    assert decode_resp.status_code == 200
    assert secret.encode("utf-8") in decode_resp.data
