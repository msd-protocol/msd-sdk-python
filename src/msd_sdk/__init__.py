"""
MSD SDK - Sign and verify structured data with Ed25519 signatures.

Quick Start
-----------
    import msd_sdk as msd
    
    key = msd.key_from_env("MSD_PRIVATE_KEY")  # or generate in MSD Explorer
    signed = msd.sign({"msg": "hello"}, {"author": "alice"}, key)
    result = msd.verify(signed)
    result['signature_is_valid']   # cryptographic validity
    result['signature_is_trusted'] # identity trust (requires endorsed key)

Keys & Trust
------------
    A valid signature from an unknown key tells verifiers nothing about who
    signed the data. For trusted signatures, generate keys in MSD Explorer
    (https://network.msd-protocol.org/dashboard) — they're endorsed and linked to
    your identity. generate_key_pair(unendorsed=True) is for testing only.

Core Functions
--------------
    sign               - Sign data with metadata, returns ET.SignedData
    embed              - Embed signature into file or dict
    verify             - Verify signature, returns rich dict
    content_hash       - Get BLAKE3 Merkle hash of any data

Key Management
--------------
    generate_key_pair  - Create identity or working keys
    save_key           - Save key to file (JSON format)
    load_key           - Load key from file
    key_from_env       - Load key from environment variable
    get_key_directory  - Get OS-appropriate key storage path
    is_endorsed        - Check if key has valid endorsement chain
    get_endorsement_chain - Get full chain from root to key

File Operations
--------------
    extract_metadata   - Read embedded metadata from signed data
    extract_signature  - Read embedded signature from signed data
    strip_metadata_and_signature - Remove embedded data, get original

Documentation: See docs/overview.md and docs/key-management.md
"""

__version__ = "0.2.0"


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
            "msd-sdk requires the 'zef' package.\n\n"
            "Install with:\n"
            "  pip install msd-sdk --extra-index-url https://msd-protocol.org/simple/\n\n"
            "Or install zef directly:\n"
            "  pip install https://msd-protocol.org/wheels/zef-0.1.29-cp310-abi3-manylinux_2_28_x86_64.whl  # Linux\n"
            "  pip install https://msd-protocol.org/wheels/zef-0.1.29-cp310-abi3-macosx_11_0_arm64.whl      # macOS ARM\n"
        )
    
    # Check for msd_hash which is only available in rust-based zef
    if not hasattr(zef, 'msd_hash'):
        raise ImportError(
            "msd-sdk requires zef with msd_hash support (>= 0.1.29).\n\n"
            "Update with:\n"
            "  pip install --upgrade msd-sdk --extra-index-url https://msd-protocol.org/simple/\n"
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
    get_key_directory,
    is_endorsed,
    get_endorsement_chain,
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
    "get_key_directory",
    "is_endorsed",
    "get_endorsement_chain",
]



