"""
Trust Network Store — local state for identity trust decisions.

Architecture: pure functions for logic, thin IO shell at the edges.
The trust network is a JSON array of entity dicts stored at
~/.config/msd/trust-network.json (or $MSD_TRUST_NETWORK).
"""

from __future__ import annotations
import json
import os
from typing import Any

from msd_sdk._config import get_msd_config_root
from msd_sdk._types import TrustNetworkEntity


# ─── Entity Type Registry ─────────────────────────────────────────────────────

_IDENTITY_FIELDS: dict[str, str] = {
    'ET.GoogleAccount': 'email',
    'ET.Organization': 'url',
}


# ─── Pure Functions ───────────────────────────────────────────────────────────

def _validate_entity(entity: Any) -> None:
    """Validate entity shape. Raises ValueError if malformed."""
    if not isinstance(entity, dict):
        raise ValueError(
            f"Entity must be a dict, got {type(entity).__name__}: {entity!r}"
        )

    if '__type' not in entity:
        raise ValueError(
            f"Entity missing '__type' field: {entity!r}"
        )

    etype = entity['__type']
    if not isinstance(etype, str):
        raise ValueError(
            f"'__type' must be a string, got {type(etype).__name__}"
        )

    if etype not in _IDENTITY_FIELDS:
        supported = ', '.join(sorted(_IDENTITY_FIELDS))
        raise ValueError(
            f"Unknown entity type '{etype}'. Supported types: {supported}"
        )

    id_field = _IDENTITY_FIELDS[etype]
    if id_field not in entity:
        raise ValueError(
            f"Entity of type '{etype}' missing required field '{id_field}': {entity!r}"
        )

    id_value = entity[id_field]
    if not isinstance(id_value, str) or not id_value.strip():
        raise ValueError(
            f"'{id_field}' must be a non-empty string, got {id_value!r}"
        )


def _normalize_entity(entity: dict) -> dict:
    """Return a normalized copy. Preserves extra fields."""
    etype = entity['__type']
    id_field = _IDENTITY_FIELDS[etype]
    result = dict(entity)

    if etype == 'ET.GoogleAccount':
        result[id_field] = result[id_field].strip().lower()
    elif etype == 'ET.Organization':
        result[id_field] = result[id_field].strip().rstrip('/')

    return result


def _entity_matches(a: dict, b: dict) -> bool:
    """Check if two entities refer to the same identity."""
    if a.get('__type') != b.get('__type'):
        return False
    id_field = _IDENTITY_FIELDS.get(a['__type'])
    if id_field is None:
        return False
    return a.get(id_field) == b.get(id_field)


def _add_entity(entries: list[dict], entity: dict) -> list[dict]:
    """Return entries with entity added. Same object if already present."""
    for e in entries:
        if _entity_matches(e, entity):
            return entries
    return entries + [entity]


def _remove_entity(entries: list[dict], entity: dict) -> list[dict]:
    """Return entries without entity."""
    return [e for e in entries if not _entity_matches(e, entity)]


def _has_entity(entries: list[dict], entity: dict) -> bool:
    """Check if entity is in the list."""
    return any(_entity_matches(e, entity) for e in entries)


# ─── IO Shell ─────────────────────────────────────────────────────────────────

def _get_trust_network_path() -> str:
    """Resolve trust network file path. Checks MSD_TRUST_NETWORK env var first."""
    override = os.environ.get("MSD_TRUST_NETWORK")
    if override:
        return os.path.expanduser(override)
    return os.path.join(get_msd_config_root(), "trust-network.json")


def _read_trust_network(path: str) -> list[dict]:
    """Read entries from disk. Returns [] if file doesn't exist."""
    if not os.path.exists(path):
        return []

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Trust network file is not valid JSON: {path}\n{exc}"
        ) from exc

    if not isinstance(data, list):
        raise ValueError(
            f"Trust network file must contain a JSON array, "
            f"got {type(data).__name__}: {path}"
        )

    return data


def _write_trust_network(path: str, entries: list[dict]) -> None:
    """Atomic write: write to .tmp then rename."""
    os.makedirs(os.path.dirname(path), exist_ok=True)

    tmp_path = path + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write('\n')

    os.replace(tmp_path, path)


# ─── Public API ───────────────────────────────────────────────────────────────

def add_to_trust_network(entity: TrustNetworkEntity) -> None:
    """Add a trusted entity. Idempotent — adding twice is a no-op.

    Entities are normalized before storage: emails are lowercased,
    URLs have trailing slashes stripped. Matching uses the normalized
    form, so ``'ALICE@Gmail.COM'`` and ``'alice@gmail.com'`` are the
    same entity.

    Raises ``ValueError`` if the entity dict is malformed (missing
    ``__type``, unknown type, or missing identity field).

    ```python
    msd.add_to_trust_network({'__type': 'ET.GoogleAccount', 'email': 'alice@gmail.com'})
    msd.add_to_trust_network({'__type': 'ET.Organization', 'url': 'https://acme.com'})
    ```

    The trust network file is created on the first call. Directory
    structure is created automatically.
    """
    _validate_entity(entity)
    entity = _normalize_entity(entity)
    path = _get_trust_network_path()
    entries = _read_trust_network(path)
    new_entries = _add_entity(entries, entity)
    if new_entries is not entries:
        _write_trust_network(path, new_entries)


def remove_from_trust_network(entity: TrustNetworkEntity) -> None:
    """Remove a trusted entity. No-op if not present.

    Matching uses the same normalization rules as ``add_to_trust_network``.

    ```python
    msd.remove_from_trust_network({'__type': 'ET.GoogleAccount', 'email': 'alice@gmail.com'})
    ```
    """
    _validate_entity(entity)
    entity = _normalize_entity(entity)
    path = _get_trust_network_path()
    entries = _read_trust_network(path)
    new_entries = _remove_entity(entries, entity)
    if len(new_entries) != len(entries):
        _write_trust_network(path, new_entries)


def get_trust_network() -> list[TrustNetworkEntity]:
    """Return all trusted entities. Empty list if no file exists.

    Entities are stored in their normalized form: emails lowercased,
    URLs without trailing slashes.

    ```python
    trusted = msd.get_trust_network()
    # [{'__type': 'ET.Organization', 'url': 'https://acme.com'}]
    ```

    Raises ``ValueError`` if the trust network file exists but
    contains invalid JSON or is not a JSON array.
    """
    return _read_trust_network(_get_trust_network_path())


def clear_trust_network() -> None:
    """Remove all trusted entities.

    Deletes the trust network file. After calling this,
    ``get_trust_network()`` returns ``[]`` and ``is_trusted()``
    returns ``False`` for all entities.

    ```python
    msd.clear_trust_network()
    ```
    """
    path = _get_trust_network_path()
    if os.path.exists(path):
        os.remove(path)


def is_trusted(entity: TrustNetworkEntity) -> bool:
    """Check if an entity is in the trust network.

    Uses normalized matching — ``'ALICE@Gmail.COM'`` matches
    ``'alice@gmail.com'``.

    Returns ``False`` if no trust network file exists.

    ```python
    msd.is_trusted({'__type': 'ET.GoogleAccount', 'email': 'alice@gmail.com'})
    # True
    ```
    """
    _validate_entity(entity)
    entity = _normalize_entity(entity)
    return _has_entity(_read_trust_network(_get_trust_network_path()), entity)
