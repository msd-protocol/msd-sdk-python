"""
MSD SDK — Sign and verify data with Ed25519 signatures.

Every function is pure: data in, data out. You connect sources
and sinks — MSD handles the cryptography.

Quick Start
-----------
    import msd_sdk as msd

    key = msd.key_from_env()  # reads MSD_SIGNING_KEY
    signed = msd.sign({"msg": "hello"}, {"author": "alice"}, key)
    result = msd.verify(signed)
    result['signature_is_valid']   # cryptographic validity
    result['signature_is_trusted'] # identity trust (requires endorsed key)

Keys & Trust
------------
    A valid signature from an unknown key tells verifiers nothing about who
    signed the data. For trusted signatures, generate keys in MSD Explorer
    (https://network.msd-protocol.org/dashboard) — they're endorsed and linked
    to your identity. generate_key_pair(unendorsed=True) is for testing only.

Signing & Verification
----------------------
    sign               — Sign data with metadata
    embed              — Fold signature into the data
    verify             — Verify and inspect a signature
    content_hash       — BLAKE3 Merkle hash of any data

Inspection
----------
    extract_metadata   — Read metadata from signed data
    extract_signature  — Read signature details from signed data
    strip_metadata_and_signature — Remove signature, recover original data

Key Management
--------------
    generate_key_pair  — Create a key pair for testing
    save_key           — Save key to disk (JSON)
    load_key           — Load key from disk
    key_from_env       — Load key from environment variable
    key_to_compact     — Convert key to compact string for env vars
    get_key_directory  — OS-appropriate key storage path

Trust Network
-------------
    add_to_trust_network    — Add a trusted entity (idempotent)
    remove_from_trust_network — Remove a trusted entity
    clear_trust_network     — Remove all trusted entities
    get_trust_network       — List all trusted entities
    is_trusted              — Check if an entity is trusted

Documentation: See docs/overview.md and docs/key-management.md
"""

__version__ = "0.2.3"


def _verify_zef_installation():
    """
    Verify that the correct zef (rust-based) is installed.
    
    This is called at import time to fail fast if the required
    zef-core package is not available.
    """
    try:
        import zef
    except ImportError:
        raise ImportError(
            "msd-sdk requires 'zef' — a compiled runtime library.\n\n"
            "Install it:\n"
            "  pip install zef\n\n"
            "Or install everything at once:\n"
            "  pip install msd-sdk\n"
        )
    
    # Check for msd_hash which is only available in rust-based zef
    if not hasattr(zef, 'msd_hash'):
        raise ImportError(
            "msd-sdk requires zef with msd_hash support (>= 0.1.29).\n\n"
            "Update with:\n"
            "  pip install --upgrade zef\n"
        )
    
    return zef


# Verify zef installation at import time (fail fast)
_zef = _verify_zef_installation()


# Re-export core API functions from the core module.
# This provides a flat API: users write `msd.sign()` instead of
# `msd.core.sign()`. The actual implementations live in core.py
# for better code organization.
from msd_sdk.core import (
    key_from_env,
    sign,
    embed,
    content_hash,
    verify,
    extract_metadata,
    extract_signature,
    strip_metadata_and_signature,
)

# Re-export key management functions
from msd_sdk.key_management import (
    generate_key_pair,
    save_key,
    load_key,
    key_to_compact,
    get_key_directory,
    is_endorsed,
    get_endorsement_chain,
)

# Re-export trust network functions
from msd_sdk.trust_network import (
    add_to_trust_network,
    remove_from_trust_network,
    get_trust_network,
    clear_trust_network,
    is_trusted,
)

# Re-export types for user annotations
from msd_sdk._types import (
    MsdHash,
    Time,
    Ed25519Signature,
    Ed25519PublicKey,
    Ed25519KeyPair,
    SignedData,
    TypedFileDict,
    VerifyResult,
    SignatureInfo,
    GoogleAccount,
    Organization,
    TrustNetworkEntity,
)

# __all__ explicitly declares the public API of this package.
# When users write `from msd_sdk import *`, only these names are imported.
# Internal helpers like _verify_zef_installation and _zef are excluded.
__all__ = [
    "__version__",
    # Core API
    "key_from_env",
    "sign",
    "embed",
    "content_hash",
    "verify",
    "extract_metadata",
    "extract_signature",
    "strip_metadata_and_signature",
    # Key Management
    "generate_key_pair",
    "save_key",
    "load_key",
    "key_to_compact",
    "get_key_directory",
    "is_endorsed",
    "get_endorsement_chain",
    # Trust Network
    "add_to_trust_network",
    "remove_from_trust_network",
    "get_trust_network",
    "clear_trust_network",
    "is_trusted",
    # Types (for user annotations)
    "MsdHash",
    "Time",
    "Ed25519Signature",
    "Ed25519PublicKey",
    "Ed25519KeyPair",
    "SignedData",
    "TypedFileDict",
    "VerifyResult",
    "SignatureInfo",
    "GoogleAccount",
    "Organization",
    "TrustNetworkEntity",
]



