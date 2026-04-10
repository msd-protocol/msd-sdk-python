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


def generate_key_pair(
    endorsed_by: dict | None = None,
    expires_in: str | None = None,
    *,
    unendorsed: bool = False,
) -> Ed25519KeyPair:
    """
    Generate a new Ed25519 key pair.
    
    By default, creates an identity key endorsed by the MSD platform.
    Use `endorsed_by` to create a working key endorsed by another key.
    
        # Identity key (platform-endorsed, never expires)
        identity = msd.generate_key_pair()
        
        # Working key (endorsed by identity, expires in 30 days)
        working = msd.generate_key_pair(endorsed_by=identity, expires_in="30d")
    
    Duration units: "1h" (hours), "7d" (days), "3m" (months)
    
    For testing or offline use, explicitly request an unendorsed key:
    
        # Unendorsed key (not recommended for production)
        test_key = msd.generate_key_pair(unendorsed=True)
    
    Returns a key dict with __type, __uid, public_key, private_key,
    and endorsement info (unless unendorsed=True).
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
    """
    Save a key to disk as JSON.
    
    If `name_or_path` is a simple name (no slashes), saves to the
    OS-appropriate default directory:
    
        msd.save_key("alice.json", key)
        # → ~/.config/msd/keys/alice.json (macOS/Linux)
        # → %APPDATA%\\msd\\keys\\alice.json (Windows)
    
    If `name_or_path` is a full path, saves there directly:
    
        msd.save_key("/secure/keys/alice.json", key)
    
    Returns the full path where the key was saved.
    """
    path = _resolve_key_path(name_or_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(key, f, ensure_ascii=False, indent=2)
    return path


def load_key(name_or_path: str) -> Ed25519KeyPair:
    """
    Load a key from disk.
    
    Mirrors `save_key` - simple names use the default directory,
    full paths are used directly.
    
        key = msd.load_key("alice.json")
        key = msd.load_key("/secure/keys/alice.json")
    
    Returns the key dict.
    """
    path = _resolve_key_path(name_or_path)
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_key_directory() -> str:
    """
    Get the default key storage directory for the current OS.
    
        msd.get_key_directory()
        # → "~/.config/msd/keys/" (macOS/Linux)
        # → "%APPDATA%\\msd\\keys\\" (Windows)
    
    Returns the expanded absolute path.
    """
    if sys.platform == "win32":
        # Windows: use APPDATA, fall back to home if not set
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "msd", "keys")
    else:
        # macOS/Linux: XDG-style config directory
        return os.path.join(os.path.expanduser("~"), ".config", "msd", "keys")


def is_endorsed(key: Ed25519PublicKey) -> bool:
    """
    Check if a key is endorsed by a trusted root.
    
    Traces the endorsement chain from the key up to a trust anchor.
    Returns True if the chain is valid and ends at a trusted root.
    
        if msd.is_endorsed(key):
            print("Key is part of a valid endorsement chain")
    """
    raise NotImplementedError("is_endorsed is not yet implemented")


def get_endorsement_chain(key: Ed25519PublicKey) -> list[dict[str, Any]]:
    """
    Get the full endorsement chain for a key.
    
    Returns a list from root to key, showing who endorsed whom:
    
        chain = msd.get_endorsement_chain(working_key)
        # [
        #     {'type': 'MSD Platform Root', 'uid': '🍃-...', 'status': 'trusted'},
        #     {'type': 'Identity Key', 'uid': '🍃-...', 'endorsed_by': '🍃-...'},
        #     {'type': 'Working Key', 'uid': '🍃-...', 'endorsed_by': '🍃-...'}
        # ]
    """
    raise NotImplementedError("get_endorsement_chain is not yet implemented")

