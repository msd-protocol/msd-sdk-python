"""Compact key format encoding and decoding.

Format: msd-key-{uid_hex_20}-{base64url(pub_32 + priv_32 + sha256_checksum_3)}

The compact key packs a full Ed25519 key pair (public key, private key, UID)
into a single 119-character ASCII string suitable for environment variables.
"""

from __future__ import annotations

import base64
import hashlib
import re

from msd_sdk._types import Ed25519KeyPair

_COMPACT_RE = re.compile(r'^msd-key-([0-9a-f]{20})-([A-Za-z0-9_-]+)$')


def encode_compact_key(key: Ed25519KeyPair) -> str:
    """Encode a full MSD key dict to compact string form.

    >>> key = {'__type': 'ET.Ed25519KeyPair', '__uid': '🍃-8d1dc8766070c87a4bb1', ...}
    >>> encode_compact_key(key)
    'msd-key-8d1dc8766070c87a4bb1-hhTRALPNtf9sN8hGdg3R...'
    """
    uid_hex = key['__uid'].split('-', 1)[1]
    priv_hex = key['private_key'].split('-', 1)[1]
    pub_hex = key['public_key'].split('-', 1)[1]

    uid_bytes = bytes.fromhex(uid_hex)
    priv_bytes = bytes.fromhex(priv_hex)
    pub_bytes = bytes.fromhex(pub_hex)

    checksum = _compute_checksum(uid_bytes, priv_bytes, pub_bytes)

    payload = pub_bytes + priv_bytes + checksum
    b64 = base64.urlsafe_b64encode(payload).rstrip(b'=').decode('ascii')

    return f'msd-key-{uid_hex}-{b64}'


def decode_compact_key(compact: str) -> Ed25519KeyPair:
    """Decode a compact key string back to a full MSD key dict.

    Raises ValueError on invalid format, bad length, or checksum mismatch.
    """
    compact = compact.strip()
    match = _COMPACT_RE.match(compact)
    if not match:
        raise ValueError(
            f"Invalid compact key format. Expected 'msd-key-<20 hex chars>-<base64url>'"
        )

    uid_hex = match.group(1)
    payload_b64 = match.group(2)

    padding = 4 - len(payload_b64) % 4
    if padding < 4:
        payload_b64 += '=' * padding
    payload = base64.urlsafe_b64decode(payload_b64)

    if len(payload) != 67:
        raise ValueError(f"Expected 67-byte payload, got {len(payload)}")

    pub_bytes = payload[0:32]
    priv_bytes = payload[32:64]
    checksum = payload[64:67]

    uid_bytes = bytes.fromhex(uid_hex)
    expected = _compute_checksum(uid_bytes, priv_bytes, pub_bytes)

    if checksum != expected:
        raise ValueError(
            f"Checksum mismatch (got {checksum.hex()}, expected {expected.hex()}). "
            "The key string may be corrupted or truncated."
        )

    return {
        '__type': 'ET.Ed25519KeyPair',
        '__uid': f'🍃-{uid_hex}',
        'private_key': f'🗝️-{priv_bytes.hex()}',
        'public_key': f'🔑-{pub_bytes.hex()}',
    }


def _compute_checksum(uid_bytes: bytes, priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    """SHA-256(uid + priv + pub), truncated to 3 bytes."""
    return hashlib.sha256(uid_bytes + priv_bytes + pub_bytes).digest()[:3]
