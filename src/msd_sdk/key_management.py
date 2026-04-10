"""
Key Management for MSD SDK

Generate, store, and manage Ed25519 key pairs with endorsement chains.
Keys are plain data (dicts) - you control naming and storage.
"""

from __future__ import annotations
import json
import os
import sys
from typing import Any

from msd_sdk._types import Ed25519KeyPair, Ed25519PublicKey


def key_to_compact(key: Ed25519KeyPair) -> str:
    """Convert a key dict to compact string form for environment variables.

    ```python
    compact = msd.key_to_compact(key)
    # 'msd-key-8d1dc8766070c87a4bb1-hhTRALPN...'
    ```

    The compact string is a single 119-character ASCII string that packs the
    full key (UID, public key, private key) with a SHA-256 checksum.
    Decode it back with ``key_from_env()`` or ``decode_compact_key()``.
    """
    from msd_sdk._compact_key import encode_compact_key
    return encode_compact_key(key)


def generate_key_pair(
    endorsed_by: Ed25519KeyPair | None = None,
    expires_in: str | None = None,
    *,
    unendorsed: bool = False,
) -> Ed25519KeyPair:
    """Generate a new Ed25519 key pair for testing.

    ```python
    key = msd.generate_key_pair(unendorsed=True)
    ```

    For production, generate keys in
    [MSD Explorer](https://network.msd-protocol.org/dashboard) —
    keys generated there are endorsed and linked to your identity.

    Returns a plain dict with `__type`, `__uid`, `public_key`, and `private_key`.
    """
    if not unendorsed and endorsed_by is None:
        # Default case: should be platform-endorsed, but not implemented yet
        raise NotImplementedError(
            "Platform endorsement is not yet implemented. "
            "For testing, use generate_key_pair(unendorsed=True) to create "
            "a local-only key pair without endorsement."
        )
    
    if endorsed_by is not None or expires_in is not None:
        raise NotImplementedError(
            "Delegated key generation (endorsed_by) is not yet implemented. "
            "For testing, use generate_key_pair(unendorsed=True)."
        )
    
    # unendorsed=True: generate a raw key pair
    import zef
    from msd_sdk.core import _to_native_python_hard
    
    zef_key = zef.generate_ed25519_key_pair()
    json_like = zef.to_json_like(zef_key)
    return _to_native_python_hard(json_like)


def _resolve_key_path(name_or_path: str) -> str:
    """Resolve simple name to full path, or return full path as-is."""
    # If it has any path separators, treat as a path
    if os.sep in name_or_path or '/' in name_or_path:
        return os.path.expanduser(name_or_path)
    # Simple name → use default directory
    return os.path.join(get_key_directory(), name_or_path)


def save_key(name_or_path: str, key: Ed25519KeyPair) -> str:
    """Save a key to disk as JSON.

    ```python
    path = msd.save_key("alice.json", key)
    # ~/.config/msd/keys/alice.json (macOS/Linux)
    ```

    Simple names save to the OS default key directory.
    Full paths (with `/`) save there directly.
    Returns the full path where the key was saved.
    """
    path = _resolve_key_path(name_or_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(key, f, ensure_ascii=False, indent=2)
    return path


def load_key(name_or_path: str) -> Ed25519KeyPair:
    """Load a key from disk.

    ```python
    key = msd.load_key("alice.json")
    ```

    Mirrors `save_key` — simple names use the default key directory,
    full paths are used directly.
    """
    path = _resolve_key_path(name_or_path)
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_key_directory() -> str:
    """Get the default key storage directory for the current OS.

    ```python
    msd.get_key_directory()
    # ~/.config/msd/keys (macOS/Linux)
    # %APPDATA%\\msd\\keys (Windows)
    ```
    """
    if sys.platform == "win32":
        # Windows: use APPDATA, fall back to home if not set
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "msd", "keys")
    else:
        # macOS/Linux: XDG-style config directory
        return os.path.join(os.path.expanduser("~"), ".config", "msd", "keys")


def is_endorsed(key: Ed25519PublicKey) -> bool:
    """Check if a key is endorsed by a trusted root.

    ```python
    if msd.is_endorsed(key):
        print("Key is part of a valid endorsement chain")
    ```

    Traces the endorsement chain from the key up to a trust anchor.

    *Not yet implemented.*
    """
    raise NotImplementedError("is_endorsed is not yet implemented")


def get_endorsement_chain(key: Ed25519PublicKey) -> list[dict[str, Any]]:
    """Get the full endorsement chain for a key.

    ```python
    chain = msd.get_endorsement_chain(working_key)
    # [
    #     {'type': 'MSD Platform Root', 'uid': '🍃-...'},
    #     {'type': 'Identity Key', 'uid': '🍃-...'},
    #     {'type': 'Working Key', 'uid': '🍃-...'},
    # ]
    ```

    Returns a list from root to key, showing who endorsed whom.

    *Not yet implemented.*
    """
    raise NotImplementedError("get_endorsement_chain is not yet implemented")

