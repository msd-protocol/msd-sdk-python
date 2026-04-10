"""Type definitions for MSD SDK.

TypedDicts describing the shape of dicts returned by and passed to
the SDK's public functions. Enable IDE autocomplete, mypy/pyright
type checking, and serve as structural documentation.

Import types directly::

    from msd_sdk import VerifyResult, SignedData, Ed25519KeyPair
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict


# ---------------------------------------------------------------------------
# Leaf types
# ---------------------------------------------------------------------------

MsdHash = TypedDict('MsdHash', {
    '__type': Literal['MsdHash'],
    'hash': str,
})

Time = TypedDict('Time', {
    '__type': Literal['Time'],
    'zef_unix_time': str,
})

Ed25519Signature = TypedDict('Ed25519Signature', {
    '__type': Literal['ET.Ed25519Signature'],
    'signature': str,
})


# ---------------------------------------------------------------------------
# Key types
# ---------------------------------------------------------------------------

Ed25519PublicKey = TypedDict('Ed25519PublicKey', {
    '__type': Literal['ET.Ed25519KeyPair'],
    '__uid': str,
    'public_key': str,
})
"""Public-only key as seen in verify results and signed data."""

Ed25519KeyPair = TypedDict('Ed25519KeyPair', {
    '__type': Literal['ET.Ed25519KeyPair'],
    '__uid': str,
    'public_key': str,
    'private_key': str,
})
"""Full key pair with private key — required for signing."""


# ---------------------------------------------------------------------------
# Composite types (functional syntax: contain __type)
# ---------------------------------------------------------------------------

SignedData = TypedDict('SignedData', {
    '__type': Literal['ET.SignedData'],
    'data': Any,
    'metadata': dict[str, Any],
    'signature': Ed25519Signature,
    'signature_time': Time,
    'key': Ed25519PublicKey,
})
"""Signed data structure returned by ``sign()``."""

TypedFileDict = TypedDict('TypedFileDict', {
    '__type': str,
    'data': str,
})
"""Typed file dict (PngImage, PDF, etc.) with base64-encoded data."""


# ---------------------------------------------------------------------------
# Result types (class syntax: no dunder keys)
# ---------------------------------------------------------------------------

class VerifyResult(TypedDict):
    """Result of ``verify()`` — signature validity and trust information."""
    is_verified_and_trusted: str
    signature_is_valid: bool
    signature_is_trusted: bool
    data_hash: MsdHash
    metadata_hash: MsdHash
    signature_timestamp: Time
    signing_key: Ed25519PublicKey
    signing_key_trust_chain: list[Any]
    trust_chain_breaches: list[Any]


class SignatureInfo(TypedDict):
    """Extracted signature information from ``extract_signature()``."""
    signature: Ed25519Signature
    signature_time: Time
    key: Ed25519PublicKey
