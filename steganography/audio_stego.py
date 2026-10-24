"""
StegoVault - Audio Waveform Steganography Module
Embeds encrypted binary payloads into audio carriers using 16-bit PCM Least Significant Bit (LSB) substitution.

Framing Protocol:
- Magic Marker: b"STEGA1" (6 bytes)
- Payload Length: 4 bytes unsigned int (big-endian)
- Total Header: 10 bytes (80 bits)
- Payload: Encrypted binary data
"""

import os
from typing import Dict, Any
import numpy as np
import soundfile as sf

MAGIC_AUDIO_HEADER = b"STEGA1"
HEADER_LEN = 10  # 6 bytes magic + 4 bytes length


class AudioStegoError(Exception):
    """Raised when audio steganography operations fail."""
    pass


class AudioCapacityError(AudioStegoError):
    """Raised when the payload exceeds audio carrier sample capacity."""
    pass


def calculate_audio_capacity(audio_path: str) -> Dict[str, Any]:
    """
    Calculate maximum concealable capacity in an audio file.
    """
    if not os.path.exists(audio_path):
        raise FileNotFoundError(f"Audio file not found: {audio_path}")

    try:
        info = sf.info(audio_path)
        total_samples = info.frames * info.channels
        total_carrier_bytes = total_samples // 8
        max_payload_bytes = max(0, total_carrier_bytes - HEADER_LEN)

        return {
            "duration_seconds": round(info.duration, 2),
            "samplerate": info.samplerate,
            "channels": info.channels,
            "total_frames": info.frames,
            "total_samples": total_samples,
            "total_carrier_bytes": total_carrier_bytes,
            "max_payload_bytes": max_payload_bytes,
            "recommended_max_chars": max(0, max_payload_bytes - 44),
        }
    except Exception as e:
        raise AudioStegoError(f"Failed to inspect audio file: {str(e)}")


def encode_audio(cover_audio_path: str, payload: bytes, output_path: str) -> Dict[str, Any]:
    """
    Embed binary payload into audio carrier using sample LSB replacement.
    
    Parameters:
        cover_audio_path: Path to cover audio (.wav, .flac).
        payload: Binary data to conceal.
        output_path: Path to write the stego audio (.wav).
        
    Returns:
        Dictionary with encoding statistics.
    """
    if not os.path.exists(cover_audio_path):
        raise AudioStegoError(f"Cover audio does not exist: {cover_audio_path}")
    if not isinstance(payload, bytes) or len(payload) == 0:
        raise AudioStegoError("Payload must be non-empty bytes.")

    try:
        # Read as 16-bit signed PCM integers
        audio_data, samplerate = sf.read(cover_audio_path, dtype="int16", always_2d=True)
    except Exception as e:
        raise AudioStegoError(f"Could not load audio file: {str(e)}")

    original_shape = audio_data.shape
    total_samples = audio_data.size
    total_available_bits = total_samples

    # Build binary stream: Header (10B) + Payload
    header = MAGIC_AUDIO_HEADER + len(payload).to_bytes(4, byteorder="big")
    stream = header + payload
    stream_bits = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))
    total_bits_needed = len(stream_bits)

    if total_bits_needed > total_available_bits:
        raise AudioCapacityError(
            f"Payload requires {total_bits_needed // 8} bytes ({total_bits_needed} bits), "
            f"but audio carrier only provides {total_available_bits // 8} bytes ({total_available_bits} samples)."
        )

    # Flatten samples for LSB embedding
    samples_flat = audio_data.reshape(-1).copy()

    # Apply LSB bit substitution on 16-bit integer samples
    # Clear bit 0 and bitwise-OR with message bit
    samples_flat[:total_bits_needed] = (samples_flat[:total_bits_needed] & ~1) | stream_bits

    # Restore 2D channel structure
    modified_audio = samples_flat.reshape(original_shape)

    # Ensure output directory exists and format is lossless WAV
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    if not output_path.lower().endswith(".wav"):
        output_path = os.path.splitext(output_path)[0] + ".wav"

    try:
        sf.write(output_path, modified_audio, samplerate, subtype="PCM_16")
    except Exception as e:
        raise AudioStegoError(f"Failed to write encoded audio file: {str(e)}")

    capacity_used_pct = round((total_bits_needed / total_available_bits) * 100, 3)

    return {
        "success": True,
        "output_path": output_path,
        "samplerate": samplerate,
        "channels": original_shape[1],
        "total_samples": total_samples,
        "payload_bytes": len(payload),
        "total_stream_bytes": len(stream),
        "capacity_used_percent": capacity_used_pct,
        "available_capacity_bytes": total_available_bits // 8,
    }


def decode_audio(stego_audio_path: str) -> bytes:
    """
    Extract embedded binary payload from steganographic audio carrier.
    
    Parameters:
        stego_audio_path: Path to stego audio file (.wav).
        
    Returns:
        Extracted binary payload.
    """
    if not os.path.exists(stego_audio_path):
        raise AudioStegoError(f"Audio file not found: {stego_audio_path}")

    try:
        audio_data, _ = sf.read(stego_audio_path, dtype="int16", always_2d=True)
    except Exception as e:
        raise AudioStegoError(f"Could not read audio carrier: {str(e)}")

    samples_flat = audio_data.reshape(-1)
    total_samples = samples_flat.size

    if total_samples < HEADER_LEN * 8:
        raise AudioStegoError("Audio file is too short to contain a StegoVault header.")

    # Extract first 80 bits (10 bytes header)
    header_bits = samples_flat[: HEADER_LEN * 8] & 1
    header_bytes = np.packbits(header_bits).tobytes()

    magic = header_bytes[:6]
    if magic != MAGIC_AUDIO_HEADER:
        raise AudioStegoError(
            "No valid StegoVault audio signature found (magic mismatch). "
            "File may not contain concealed data or was re-encoded with lossy compression."
        )

    # Read payload length
    payload_len = int.from_bytes(header_bytes[6:10], byteorder="big")
    total_required_bits = (HEADER_LEN + payload_len) * 8

    if total_required_bits > total_samples:
        raise AudioStegoError("Corrupted audio header: Payload length exceeds sample capacity.")

    # Extract payload bits
    payload_bits = samples_flat[HEADER_LEN * 8 : total_required_bits] & 1
    payload_bytes = np.packbits(payload_bits).tobytes()

    return payload_bytes[:payload_len]
