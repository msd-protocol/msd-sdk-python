"""Type definitions for MSD SDK.

These are TypedDicts — plain Python dicts with documented key structure.
They enable IDE autocomplete on dict keys and type checker validation,
but at runtime every value is just a regular ``dict``.

Import types for your own annotations::

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
"""A plain dict — BLAKE3 content hash.

Keys::

    '__type': 'MsdHash'
    'hash':   str  — 64-character hex string
"""

Time = TypedDict('Time', {
    '__type': Literal['Time'],
    'zef_unix_time': str,
})
"""A plain dict — timestamp.

Keys::

    '__type':        'Time'
    'zef_unix_time': str  — unix seconds as string
"""

Ed25519Signature = TypedDict('Ed25519Signature', {
    '__type': Literal['ET.Ed25519Signature'],
    'signature': str,
})
"""A plain dict — Ed25519 cryptographic signature.

Keys::

    '__type':    'ET.Ed25519Signature'
    'signature': str  — emoji-prefixed hex, e.g. '🔏-ab36b3dd...'
"""


# ---------------------------------------------------------------------------
# Key types
# ---------------------------------------------------------------------------

Ed25519PublicKey = TypedDict('Ed25519PublicKey', {
    '__type': Literal['ET.Ed25519KeyPair'],
    '__uid': str,
    'public_key': str,
})
"""A plain dict — public key only (as seen in verify results and signed data).

Keys::

    '__type':     'ET.Ed25519KeyPair'
    '__uid':      str  — key identifier, e.g. '🍃-ab3a3648...'
    'public_key': str  — e.g. '🔑-c824bfc5...'
"""

Ed25519KeyPair = TypedDict('Ed25519KeyPair', {
    '__type': Literal['ET.Ed25519KeyPair'],
    '__uid': str,
    'public_key': str,
    'private_key': str,
})
"""A plain dict — full key pair with private key (required for signing).

Keys::

    '__type':      'ET.Ed25519KeyPair'
    '__uid':       str  — key identifier, e.g. '🍃-ab3a3648...'
    'public_key':  str  — e.g. '🔑-c824bfc5...'
    'private_key': str  — e.g. '🗝️-...'
"""


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
"""A plain dict — signed data returned by ``sign()``.

Keys::

    '__type':         'ET.SignedData'
    'data':           Any  — the signed payload
    'metadata':       dict — metadata attached during signing
    'signature':      Ed25519Signature dict
    'signature_time': Time dict
    'key':            Ed25519PublicKey dict (public key only)
"""

TypedFileDict = TypedDict('TypedFileDict', {
    '__type': str,
    'data': str,
})
"""A plain dict — typed file (PngImage, PDF, etc.) with base64-encoded data.

Keys::

    '__type': str  — e.g. 'PngImage', 'PDF', 'JpgImage'
    'data':   str  — base64-encoded file content (or text for SvgImage)
"""


# ---------------------------------------------------------------------------
# Result types (class syntax: no dunder keys — full hover in Pylance)
# ---------------------------------------------------------------------------

class VerifyResult(TypedDict):
    """A plain dict — result of ``verify()``.

    Pylance/pyright will autocomplete all keys below.
    """
    is_verified_and_trusted: str
    """'✅' when signature is valid AND trusted, '❌' otherwise."""
    signature_is_valid: bool
    """True if the cryptographic signature is valid."""
    signature_is_trusted: bool
    """True if the signing key has a valid trust chain (not yet implemented)."""
    data_hash: MsdHash
    """BLAKE3 hash of the signed data."""
    metadata_hash: MsdHash
    """BLAKE3 hash of the metadata."""
    signature_timestamp: Time
    """When the signature was created."""
    signing_key: Ed25519PublicKey
    """The public key used to create the signature."""
    signing_key_trust_chain: list[Any]
    """Endorsement chain from root to signing key."""
    trust_chain_breaches: list[Any]
    """Any broken links in the trust chain."""


class SignatureInfo(TypedDict):
    """A plain dict — extracted signature information from ``extract_signature()``.

    Pylance/pyright will autocomplete all keys below.
    """
    signature: Ed25519Signature
    """The Ed25519 signature."""
    signature_time: Time
    """When the signature was created."""
    key: Ed25519PublicKey
    """The public key that created the signature."""


# ---------------------------------------------------------------------------
# Trust network entity types
# ---------------------------------------------------------------------------

GoogleAccount = TypedDict('GoogleAccount', {
    '__type': Literal['ET.GoogleAccount'],
    'email': str,
})
"""A plain dict — a Google account trusted in the trust network.

Keys::

    '__type': 'ET.GoogleAccount'
    'email':  str  — e.g. 'alice@gmail.com'
"""

Organization = TypedDict('Organization', {
    '__type': Literal['ET.Organization'],
    'url': str,
})
"""A plain dict — an organization trusted in the trust network.

Keys::

    '__type': 'ET.Organization'
    'url':    str  — e.g. 'https://acme.com'
"""

# Union of all trust network entity types
TrustNetworkEntity = GoogleAccount | Organization
"""A trusted entity — either a Google account or an organization."""
