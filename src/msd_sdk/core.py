"""Core API functions for MSD SDK."""

import json
import time
import base64


def _to_native_python_hard(data):
    """
    Recursively convert zef data types to native Python types.
    
    Handles: Dict2_, String_, List2_, etc. -> dict, str, list, etc.
    """
    import zef
    ptype = zef.primary_type(data)
    
    # String types
    if ptype == zef.String:
        return str(data)
    
    # Int types (Int, Int32, Int64, etc.)
    if ptype in (zef.Int, getattr(zef, 'Int32', None), getattr(zef, 'Int64', None)):
        return int(data)
    
    # Float types (Float, Float32, Float64, etc.)
    if ptype in (zef.Float, getattr(zef, 'Float32', None), getattr(zef, 'Float64', None)):
        return float(data)
    
    # Bool
    if ptype == zef.Bool:
        return bool(data)
    
    # Nil
    if ptype == zef.Nil:
        return None
    
    # Dict
    if ptype == zef.Dict:
        return {_to_native_python_hard(k): _to_native_python_hard(v) for k, v in data.items()}
    
    # Array/List
    if ptype == zef.Array:
        return [_to_native_python_hard(item) for item in data]
    
    raise ValueError(f"Unsupported type in _to_native_python_hard: {ptype}")


# =============================================================================
# Typed data: dicts with '__type' represent specific Zef types, not plain dicts
# =============================================================================

import re

# All known valid __type names (Zef types expressible as typed dicts)
TYPED_DATA_TYPES = frozenset({
    'PngImage', 'JpgImage', 'WebpImage', 'SvgImage',
    'PDF', 'WordDocument', 'ExcelDocument', 'PowerpointDocument',
    'Set', 'Bytes', 'Time', 'MsdHash',
})

# Pattern for valid entity type names: ET.<valid_python_identifier>
_ENTITY_TYPE_RE = re.compile(r'^ET\.[A-Za-z_][A-Za-z0-9_]*$')

# Types that support file embedding (embed)
_FILE_EMBEDDABLE_TYPES = frozenset({
    'PngImage', 'JpgImage', 'WebpImage', 'SvgImage',
    'PDF', 'WordDocument', 'ExcelDocument', 'PowerpointDocument',
})


def _is_valid_type_name(name: str) -> bool:
    """Check if a __type value is valid (known type or valid ET.* entity type)."""
    if name in TYPED_DATA_TYPES:
        return True
    if _ENTITY_TYPE_RE.match(name):
        return True
    return False


def _validate_typed_values(data):
    """
    Recursively walk data and validate all __type fields.
    
    Raises ValueError with a clear message if any __type is invalid.
    """
    if isinstance(data, dict):
        if '__type' in data:
            t = data['__type']
            if not isinstance(t, str):
                raise ValueError(
                    f"'__type' must be a string, got {type(t).__name__}: {t!r}"
                )
            if not _is_valid_type_name(t):
                raise ValueError(
                    f"Invalid '__type': '{t}'. "
                    f"Allowed types: {sorted(TYPED_DATA_TYPES)} "
                    f"or entity types matching 'ET.<ValidPythonIdentifier>' "
                    f"(e.g. 'ET.Person', 'ET.Invoice')."
                )
        for v in data.values():
            _validate_typed_values(v)
    elif isinstance(data, (list, tuple)):
        for item in data:
            _validate_typed_values(item)


def _is_typed_data(data) -> bool:
    """Check if data is a typed file dict that supports file embedding."""
    return isinstance(data, dict) and data.get('__type') in _FILE_EMBEDDABLE_TYPES


def _typed_dict_to_zef(data: dict):
    """
    Convert a typed dict to the corresponding Zef type.
    
    Input format: {'__type': 'PngImage', 'data': '<base64 or text>'}
    """
    import zef
    t = data['__type']
    raw = data['data']
    match t:
        case 'PngImage':            return zef.PngImage(base64.b64decode(raw))
        case 'JpgImage':            return zef.JpgImage(base64.b64decode(raw))
        case 'WebpImage':           return zef.WebpImage(base64.b64decode(raw))
        case 'SvgImage':            return zef.SvgImage(raw)  # text, not base64
        case 'PDF':                 return zef.PDF(base64.b64decode(raw))
        case 'WordDocument':        return zef.ET.WordDocument(content=base64.b64decode(raw))
        case 'ExcelDocument':       return zef.ET.ExcelDocument(content=base64.b64decode(raw))
        case 'PowerpointDocument':  return zef.ET.PowerpointDocument(content=base64.b64decode(raw))
        case _:
            raise ValueError(f"Unknown typed data type: '{t}'")


def _zef_to_typed_dict(zef_obj) -> dict:
    """
    Convert a Zef file type back to a typed dict.
    
    Output format: {'__type': 'PngImage', 'data': '<base64 or text>'}
    """
    import zef
    pt = zef.primary_type(zef_obj)
    
    # Binary image types
    if pt == zef.PngImage:
        return {'__type': 'PngImage', 'data': base64.b64encode(bytes(zef_obj.data_as_bytes())).decode()}
    if pt == zef.JpgImage:
        return {'__type': 'JpgImage', 'data': base64.b64encode(bytes(zef_obj.data_as_bytes())).decode()}
    if pt == zef.WebpImage:
        return {'__type': 'WebpImage', 'data': base64.b64encode(bytes(zef_obj.data_as_bytes())).decode()}
    if pt == zef.PDF:
        return {'__type': 'PDF', 'data': base64.b64encode(bytes(zef_obj.data_as_bytes())).decode()}
    
    # Text-based types
    if pt == zef.SvgImage:
        return {'__type': 'SvgImage', 'data': str(zef_obj)}
    
    # Entity types (content attribute)
    type_name = str(pt)
    if type_name.startswith('ET.'):
        type_name = type_name[3:]
    return {'__type': type_name, 'data': base64.b64encode(bytes(zef_obj.content)).decode()}


def key_from_env(env_var_name: str = "MSD_PRIVATE_KEY") -> dict:
    """
    Load an Ed25519 key pair from an environment variable.
    
    The environment variable should contain a JSON-encoded key pair.
    
    Args:
        env_var_name: Name of the environment variable containing the key.
                      Defaults to "MSD_PRIVATE_KEY".
    
    Returns:
        A dictionary representing the key pair with structure:
        {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-...',
          'private_key': '🗝️-...',
          'public_key': '🔑-...'
        }
    
    Raises:
        KeyError: If the environment variable is not set.
        json.JSONDecodeError: If the environment variable doesn't contain valid JSON.
    """
    import zef
    
    # Use Zef's managed effect system to get the environment variable
    env_value = zef.FX.GetEnvVar(name=env_var_name) | zef.run
    
    if env_value is None:
        raise KeyError(f"Environment variable '{env_var_name}' is not set")
    
    # Convert Zef String to Python string and parse as JSON
    key_json = str(env_value)
    return json.loads(key_json)


def sign(data, metadata: dict, key: dict) -> dict:
    """
    Sign data with metadata. Returns an ET.SignedData dict.
    
    This is the primary signing function. It produces a signed data structure
    that can be:
    - Verified directly with verify()
    - Embedded into a file or dict with embed()
    
    For typed file dicts (PngImage, PDF, etc.), any existing embedded data
    is stripped before signing to ensure correct hash computation.
    
    Args:
        data: The data to sign (any JSON-serializable value, or a typed file dict).
        metadata: A dictionary of metadata about the data.
        key: The Ed25519 key pair to sign with.
    
    Returns:
        A dictionary with __type='ET.SignedData' containing the signed data,
        metadata, timestamp, signature, and public key.
    """
    import zef
    
    # Strip existing embedded data from typed file dicts before signing.
    # Without this, re-signing an already-signed file would hash the 
    # content+old-signature, making verify fail after embed().
    if _is_typed_data(data):
        data_zef = _typed_dict_to_zef(data)
        data_zef = zef.strip_embedded_data(data_zef)
        data = _zef_to_typed_dict(data_zef)
    
    _validate_typed_values(data)
    _validate_typed_values(metadata)
    # If typed data, convert to Zef type first
    if _is_typed_data(data):
        data = _typed_dict_to_zef(data)
    timestamp = zef.now()
    key_internal = zef.from_json_like(key)
    granule_internal = zef.create_signed_granule(data, metadata, timestamp, key_internal)
    result = granule_internal | zef.to_json_like | zef.collect
    result = _to_native_python_hard(result)
    result['__type'] = 'ET.SignedData'
    return result


def content_hash(data) -> dict:
    """
    Compute the MSD content hash (BLAKE3-based) of data.
    
    Uses MSD hashing for all supported types. MSD hashing enables:
    - Structural sharing: Reused sub-structures have the same hash
    - Interoperability with signatures: Shared data can be verified independently
    - Specifying aggregates by constituent hashes: A dict's hash depends on 
      the hashes of its keys and values, not just raw bytes
    - Type-aware hashing: Different types with the same value produce different hashes
    
    Args:
        data: The data to hash. Can be:
              - Primitives: str, int, float, bool, None
              - Aggregates: dict, list (uses Merkle hashing of elements)
              - Typed data: dicts with '__type' (e.g. PngImage, PDF)
    
    Returns:
        A dict with structure:
        {
            '__type': 'MsdHash',
            'hash': '<64-character hex string>'
        }
    """
    import zef
    _validate_typed_values(data)
    # If typed data, convert to Zef type first
    if _is_typed_data(data):
        data = _typed_dict_to_zef(data)
    return {
        '__type': 'MsdHash',
        'hash': bytes(zef.msd_hash(data)).hex(),
    }


def _verify_signed_data(data: dict) -> dict:
    """
    Verify the signature of an MSD SignedData dict.
    
    Internal function - use verify() for the public API.
    
    Args:
        data: A signed data dictionary with __type='ET.SignedData'.
    
    Returns:
        A rich dict with signature_is_valid and extracted metadata.
    """
    import zef
    
    # Convert to ET.SignedGranule for Zef compatibility
    d = dict(data)
    d['__type'] = 'ET.SignedGranule'
    granule_internal = zef.from_json_like(d)
    is_valid = bool(granule_internal | zef.verify_granite_signature | zef.collect)
    is_trusted = False  # trust chains not yet implemented
    
    return {
        'is_verified_and_trusted': '✅' if (is_valid and is_trusted) else '❌',
        'signature_is_valid': is_valid,
        'signature_is_trusted': is_trusted,
        'data_hash': content_hash(data['data']),
        'metadata_hash': content_hash(data['metadata']),
        'signature_timestamp': data['signature_time'],
        'signing_key': data['key'],
        'signing_key_trust_chain': [],
        'trust_chain_breaches': [],
    }


def _verify_dict(signed_dict_data: dict) -> dict:
    """
    Verify the embedded signature in a dict signed with embed().
    
    Internal function - use verify() for the public API.
    
    Reconstructs the full SignedGranule by:
    1. Extracting sig_and_metadata from the __msd Unicode steganography payload
    2. Recovering the original data (dict minus __msd key)
    3. Building a complete SignedGranule with data + sig_and_metadata
    4. Verifying the signature
    
    Args:
        signed_dict_data: A dict with an '__msd' key from embed().
    
    Returns:
        A rich dict with signature_is_valid and extracted metadata.
    
    Raises:
        ValueError: If no '__msd' key is found.
    """
    import zef
    
    if '__msd' not in signed_dict_data:
        raise ValueError("No '__msd' key found in dict — this dict was not signed with embed()")
    
    emoji_str = signed_dict_data['__msd']
    
    # 1. Decode the steganographic payload from __msd
    sig_and_metadata_zef = (
        emoji_str 
        | zef.decode_secret_string_in_emoji
        | zef.base64_to_bytes
        | zef.insert_into(zef.ET.ZstdCompressed(), 'compressed_bytes')
        | zef.zstd_decompress
        | zef.bytes_to_zef_value
        | zef.to_json_like
        | zef.collect
    )
    sig_and_metadata_py = _to_native_python_hard(sig_and_metadata_zef)
    
    # 2. Recover original data (everything except __msd)
    original_data = {k: v for k, v in signed_dict_data.items() if k != '__msd'}
    
    # 3. Build a complete SignedGranule dict and convert to Entity via from_json_like
    granule_dict = {
        '__type': 'ET.SignedGranule',
        'data': original_data,
        **sig_and_metadata_py,
    }
    granule_entity = zef.from_json_like(granule_dict)
    
    # 4. Verify
    is_valid = bool(granule_entity | zef.verify_granite_signature | zef.collect)
    is_trusted = False  # trust chains not yet implemented
    
    return {
        'is_verified_and_trusted': '✅' if (is_valid and is_trusted) else '❌',
        'signature_is_valid': is_valid,
        'signature_is_trusted': is_trusted,
        'data_hash': content_hash(original_data),
        'metadata_hash': content_hash(sig_and_metadata_py.get('metadata', {})),
        'signature_timestamp': sig_and_metadata_py.get('signature_time'),
        'signing_key': sig_and_metadata_py.get('key'),
        'signing_key_trust_chain': [],
        'trust_chain_breaches': [],
    }


def _verify_file(signed_data: dict) -> dict:
    """
    Verify the embedded signature in a signed file (typed dict).
    
    Internal function - use verify() for the public API.
    """
    import zef
    
    # 1. Convert typed dict to Zef type
    typed_file = _typed_dict_to_zef(signed_data)
    
    # 2. Extract embedded granule data (without 'data' field)
    embedded_bytes = typed_file | zef.extract_embedded_data | zef.collect
    
    if embedded_bytes is None or embedded_bytes == zef.Nil:
        raise ValueError("No embedded MSD signature found in this file")
    
    granule_without_data = zef.bytes_to_zef_value(embedded_bytes)
    
    # Extract metadata from embedded data for the result
    embedded_dict = granule_without_data | zef.to_json_like | zef.collect
    embedded_py = _to_native_python_hard(embedded_dict)
    
    # 3. Strip embedded data to get clean content
    clean_file = zef.strip_embedded_data(typed_file)
    clean_typed_dict = _zef_to_typed_dict(clean_file)
    
    # 4. Insert clean data into granule to create complete structure
    complete_granule = zef.insert(granule_without_data, 'data', clean_file)
    
    # 5. Verify signature
    is_valid = bool(complete_granule | zef.verify_granite_signature | zef.collect)
    is_trusted = False  # trust chains not yet implemented
    
    return {
        'is_verified_and_trusted': '✅' if (is_valid and is_trusted) else '❌',
        'signature_is_valid': is_valid,
        'signature_is_trusted': is_trusted,
        'data_hash': content_hash(clean_typed_dict),
        'metadata_hash': content_hash(embedded_py.get('metadata', {})),
        'signature_timestamp': embedded_py.get('signature_time'),
        'signing_key': embedded_py.get('key'),
        'signing_key_trust_chain': [],
        'trust_chain_breaches': [],
    }


def verify(data: dict) -> dict:
    """
    Verify the signature of signed data, an embedded dict, or a signed file.
    
    Supports three input types:
    
    1. SignedData dict (from sign()):
       {'__type': 'ET.SignedData', 'data': ..., 'signature': ..., ...}
    
    2. Dict with Unicode steganography signature (from embed()):
       {'x': 42, '__msd': '🔏...'}
    
    3. File dict with embedded signature (from embed()):
       {'__type': 'PngImage', 'data': '<base64>'}
    
    Args:
        data: An ET.SignedData dict, a dict with __msd key, or a file dict
              with embedded signature.
    
    Returns:
        A dict with verification results:
        {
            'is_verified_and_trusted': '✅' or '❌',
            'signature_is_valid': bool,
            'signature_is_trusted': False,
            'data_hash': {'__type': 'MsdHash', 'hash': '...'},
            'metadata_hash': {'__type': 'MsdHash', 'hash': '...'},
            'signature_timestamp': {'__type': 'Time', ...},
            'signing_key': {'__type': 'ET.Ed25519KeyPair', ...},
            'signing_key_trust_chain': [],
            'trust_chain_breaches': [],
        }
    
    Raises:
        ValueError: If the input format is not recognized, the file type is
                    unsupported, or no embedded signature is found.
    
    Examples:
        signed = msd.sign(data, metadata, key)
        result = msd.verify(signed)
        assert result['signature_is_valid'] == True
        
        embedded = msd.embed(signed)
        result = msd.verify(embedded)
        assert result['signature_is_valid'] == True
    """
    # Handle both native Python dicts and Zef dict types
    # Zef dicts may not have .get() and hasattr may fail
    
    # Try to get __type field
    type_field = None
    try:
        type_field = data['__type']
        # Convert Zef String to Python str if needed
        type_field = str(type_field)
    except (KeyError, TypeError):
        pass
    
    # Case 1: ET.SignedData dict (new API)
    if type_field == 'ET.SignedData':
        return _verify_signed_data(data)
    
    # Reject old ET.SignedGranule — fail hard
    if type_field == 'ET.SignedGranule':
        raise ValueError(
            "ET.SignedGranule is no longer supported. "
            "Use msd.sign() which returns ET.SignedData."
        )
    
    # Case 2: Typed data with embedded signature (PngImage, PDF, etc.)
    if type_field in TYPED_DATA_TYPES:
        return _verify_file(data)
    
    # Case 3: Dict signed with embed() (has __msd key)
    has_msd = False
    try:
        _ = data['__msd']
        has_msd = True
    except (KeyError, TypeError):
        pass
    
    if has_msd:
        return _verify_dict(data)
    
    raise ValueError(
        "verify() expects an ET.SignedData dict (from msd.sign()), "
        "a typed data dict (with '__type' in " + str(sorted(TYPED_DATA_TYPES)) + "), "
        "or a dict with embedded signature (with '__msd' key). "
        "Got keys: " + str(list(data.keys()))
    )




def _embed_in_file(granule_dict: dict) -> dict:
    """
    Embed signature data into a typed file (PngImage, PDF, etc.).
    
    Internal function - use embed() for the public API.
    """
    import zef
    
    granule_entity = zef.from_json_like(granule_dict)
    
    # Get the file data as a Zef type
    data_field = granule_entity['data']
    
    # Build the "everything except data" payload and convert to bytes
    binary_data_to_embed = (
        granule_entity
        | zef.remove('data')
        | zef.to_bytes
        | zef.collect
    )
    
    # Embed into the file data
    signed = zef.embed_data(data_field, binary_data_to_embed)
    return _zef_to_typed_dict(signed)


def _embed_in_dict(granule_dict: dict) -> dict:
    """
    Embed signature data into a plain dict using Unicode steganography.
    
    Internal function - use embed() for the public API.
    """
    import zef
    
    granule_entity = zef.from_json_like(granule_dict)
    
    sig_and_metadata = {
        'metadata': granule_entity['metadata'],
        'signature_time': granule_entity['signature_time'],
        'signature': granule_entity['signature'],
        'key': granule_entity['key']
    }
    
    sig_and_metadata_bytes = zef.collect(sig_and_metadata).to_bytes()
    sig_and_metadata_bytes_compressed = zef.zstd_compress(sig_and_metadata_bytes)
    sig_and_metadata_bytes_compressed_b64 = zef.to_base64(sig_and_metadata_bytes_compressed.compressed_bytes)
    encoded = zef.encode_secret_string_in_emoji(sig_and_metadata_bytes_compressed_b64, '🔏')
    
    original_data = granule_dict['data']
    return {
        **original_data,
        '__msd': str(encoded)
    }


def embed(signed_data: dict) -> dict:
    """
    Embed the signature from an ET.SignedData dict into its data.
    
    Auto-detects format:
    - Typed file dict (PngImage, PDF, etc.) → binary embedding in file bytes
    - Plain dict → Unicode steganography (__msd key)
    
    Args:
        signed_data: An ET.SignedData dict from sign().
    
    Returns:
        For file data: a typed dict (same __type) with embedded signature.
        For dict data: the original dict plus an __msd key.
    
    Raises:
        ValueError: If input is not an ET.SignedData dict, or if the data
                    type cannot be embedded (e.g. string, int).
    """
    type_field = signed_data.get('__type') if isinstance(signed_data, dict) else None
    
    if type_field not in ('ET.SignedData', 'ET.SignedGranule'):
        raise ValueError(
            "embed() expects an ET.SignedData dict (from msd.sign()). "
            f"Got __type={type_field!r}"
        )
    
    # Convert to ET.SignedGranule for Zef compatibility
    sd = dict(signed_data)
    sd['__type'] = 'ET.SignedGranule'
    
    data = sd['data']
    if _is_typed_data(data):
        return _embed_in_file(sd)
    elif isinstance(data, dict):
        if '__msd' in data:
            raise ValueError(
                "Data dict already contains an '__msd' key. "
                "Cannot embed without overwriting existing key."
            )
        return _embed_in_dict(sd)
    else:
        raise ValueError(
            f"Cannot embed signature into {type(data).__name__} data. "
            f"embed() supports typed file dicts (PngImage, PDF, etc.) and plain dicts. "
            f"For other data types, use the ET.SignedData dict directly."
        )




def _extract_msd_from_dict(signed_dict_data: dict) -> dict:
    """
    Extract the full sig_and_metadata structure from a dict that was signed
    with embed(). Reverses the Unicode steganography encoding chain:
    emoji → decode → base64 → decompress → bytes → data.
    
    Returns:
        The decoded sig_and_metadata dict with keys:
        'metadata', 'signature_time', 'signature', 'key'.
    
    Raises:
        ValueError: If no '__msd' key is found.
    """
    import zef
    
    if '__msd' not in signed_dict_data:
        raise ValueError("No '__msd' key found in dict — this dict was not signed with embed()")
    
    emoji_str = signed_dict_data['__msd']
    
    # Reverse the Unicode steganography encoding chain from embed():
    # 1. Decode steganographic payload from emoji → base64 string
    # 2. Base64 → raw compressed bytes
    # 3. Wrap in ET.ZstdCompressed entity → decompress → original bytes
    # 4. Bytes → Zef value → json-like Python dict
    result = (
        emoji_str 
        | zef.decode_secret_string_in_emoji
        | zef.base64_to_bytes
        | zef.insert_into(zef.ET.ZstdCompressed(), 'compressed_bytes')
        | zef.zstd_decompress
        | zef.bytes_to_zef_value
        | zef.to_json_like
        | zef.collect
    )
    
    return _to_native_python_hard(result)


def extract_metadata(signed_data: dict) -> dict:
    """
    Extract metadata from signed data.
    
    Args:
        signed_data: One of:
            - An ET.SignedData dict (from sign()),
            - A dict with an '__msd' key (from embed() on dicts), or
            - A typed data dict with '__type' (from embed() on files).
    
    Returns:
        The metadata dictionary that was attached during signing.
    
    Raises:
        ValueError: If no embedded signature data is found.
    """
    import zef
    
    # Case 0: Raw ET.SignedData from sign()
    if signed_data.get('__type') == 'ET.SignedData':
        return signed_data.get('metadata', {})
    
    # Case 1: Dict signed with embed()
    if '__msd' in signed_data:
        msd_data = _extract_msd_from_dict(signed_data)
        return msd_data.get('metadata', {})
    
    # Case 2: Typed data with embedded signature
    data_ = _typed_dict_to_zef(signed_data)
    
    embedded_bytes = data_ | zef.extract_embedded_data | zef.collect
    
    if embedded_bytes is None or (hasattr(zef, 'Nil') and embedded_bytes == zef.Nil):
        raise ValueError("No embedded signature data found in this file")
    
    granule = zef.bytes_to_zef_value(embedded_bytes)
    granule_dict = granule | zef.to_json_like | zef.collect
    
    # Convert zef types to native Python types recursively
    py_dict = _to_native_python_hard(granule_dict)
    return py_dict.get('metadata', {})




def extract_signature(signed_data: dict) -> dict:
    """
    Extract signature information from signed data.
    
    Args:
        signed_data: One of:
            - An ET.SignedData dict (from sign()),
            - A dict with an '__msd' key (from embed() on dicts), or
            - A typed data dict with '__type' (from embed() on files).
    
    Returns:
        A dictionary with signature information including:
        'signature', 'signature_time', and 'key'.
    
    Raises:
        ValueError: If no embedded signature data is found.
    """
    import zef
    
    # Case 0: Raw ET.SignedData from sign()
    if signed_data.get('__type') == 'ET.SignedData':
        return {
            'signature': signed_data.get('signature'),
            'signature_time': signed_data.get('signature_time'),
            'key': signed_data.get('key'),
        }
    
    # Case 1: Dict signed with embed()
    if '__msd' in signed_data:
        msd_data = _extract_msd_from_dict(signed_data)
        return {
            'signature': msd_data.get('signature'),
            'signature_time': msd_data.get('signature_time'),
            'key': msd_data.get('key'),
        }
    
    # Case 2: Typed data with embedded signature
    data_ = _typed_dict_to_zef(signed_data)
    
    embedded_bytes = data_ | zef.extract_embedded_data | zef.collect
    
    if embedded_bytes is None or (hasattr(zef, 'Nil') and embedded_bytes == zef.Nil):
        raise ValueError("No embedded signature data found in this file")
    
    granule = zef.bytes_to_zef_value(embedded_bytes)
    granule_dict = granule | zef.to_json_like | zef.collect
    py_dict = _to_native_python_hard(granule_dict)
    
    return {
        'signature': py_dict.get('signature'),
        'signature_time': py_dict.get('signature_time'),
        'key': py_dict.get('key'),
    }




def strip_metadata_and_signature(signed_data: dict) -> dict:
    """
    Strip the embedded metadata and signature from a signed file,
    returning the original content as a typed dict.
    
    Args:
        signed_data: A typed data dict with '__type' (from embed()).
    
    Returns:
        A typed data dict with the same '__type' but clean content
        (all embedded MSD data removed).
    """
    import zef
    
    data_ = _typed_dict_to_zef(signed_data)
    stripped = zef.strip_embedded_data(data_)
    return _zef_to_typed_dict(stripped)

