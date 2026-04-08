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

# Types that support file embedding (sign_and_embed)
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


def create_granule(data, metadata: dict, key: dict) -> dict:
    """
    Create a signed MSD Granule.
    
    A Granule is the fundamental unit in MSD: a piece of data combined with
    its metadata, timestamp, and cryptographic signature.
    
    Args:
        data: The data to sign (can be any JSON-serializable value).
        metadata: A dictionary of metadata about the data.
        key: The Ed25519 key pair to sign with (from key_from_env or similar).
             Must be a dict with '__type': 'ET.Ed25519KeyPair' and 'private_key'.
    
    Returns:
        A dictionary representing the signed granule with structure:
        {
          '__type': 'ET.SignedGranule',
          'data': ...,
          'metadata': {...},
          'signature_time': {...},
          'signature': {...},
          'key': {...}
        }
    """
    import zef
    _validate_typed_values(data)
    _validate_typed_values(metadata)
    # If typed data, convert to Zef type first
    if _is_typed_data(data):
        data = _typed_dict_to_zef(data)
    timestamp = zef.now()
    key_internal = zef.from_json_like(key)
    granule_internal = zef.create_signed_granule(data, metadata, timestamp, key_internal)
    result = granule_internal | zef.to_json_like | zef.collect
    return _to_native_python_hard(result)


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


def _verify_granule(granule: dict) -> bool:
    """
    Verify the signature of an MSD SignedGranule dict.
    
    Internal function - use verify() for the public API.
    
    Args:
        granule: A signed granule dictionary with __type='ET.SignedGranule'.
    
    Returns:
        True if the signature is valid, False otherwise.
    """
    import zef
    
    granule_internal = zef.from_json_like(granule)
    result = granule_internal | zef.verify_granite_signature | zef.collect
    return bool(result)


def _verify_dict(signed_dict_data: dict) -> bool:
    """
    Verify the embedded signature in a dict signed with sign_and_embed_dict.
    
    Internal function - use verify() for the public API.
    
    Reconstructs the full SignedGranule by:
    1. Extracting sig_and_metadata from the __msd Unicode steganography payload
    2. Recovering the original data (dict minus __msd key)
    3. Building a complete SignedGranule with data + sig_and_metadata
    4. Verifying the signature
    
    Args:
        signed_dict_data: A dict with an '__msd' key from sign_and_embed_dict.
    
    Returns:
        True if the signature is valid, False otherwise.
    
    Raises:
        ValueError: If no '__msd' key is found.
    """
    import zef
    
    if '__msd' not in signed_dict_data:
        raise ValueError("No '__msd' key found in dict — this dict was not signed with sign_and_embed_dict")
    
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
    result = granule_entity | zef.verify_granite_signature | zef.collect
    return bool(result)


def _verify_file(signed_data: dict) -> bool:
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
    
    # 3. Strip embedded data to get clean content
    clean_file = zef.strip_embedded_data(typed_file)
    
    # 4. Insert clean data into granule to create complete structure
    complete_granule = zef.insert(granule_without_data, 'data', clean_file)
    
    # 5. Verify signature
    result = complete_granule | zef.verify_granite_signature | zef.collect
    return bool(result)


def verify(data: dict) -> bool:
    """
    Verify the signature of a granule, signed dict, or signed file.
    
    Supports three input types:
    
    1. SignedGranule dict (from create_granule):
       {'__type': 'ET.SignedGranule', 'data': ..., 'signature': ..., ...}
    
    2. Dict with Unicode steganography signature (from sign_and_embed_dict):
       {'x': 42, '__msd': '🔏...'}
    
    3. File dict with embedded signature (from sign_and_embed):
       {'type': 'png'|'jpg'|'pdf'|..., 'content': bytes}
    
    Args:
        data: A SignedGranule dict, a dict with __msd key, or a file dict
              with embedded signature.
    
    Returns:
        True if the signature is valid, False otherwise.
    
    Raises:
        ValueError: If the input format is not recognized, the file type is
                    unsupported, or no embedded signature is found.
    
    Examples:
        # Verify a granule
        granule = msd.create_granule(data, metadata, key)
        assert msd.verify(granule) == True
        
        # Verify a signed dict
        signed_dict = msd.sign_and_embed_dict(data, metadata, key)
        assert msd.verify(signed_dict) == True
        
        # Verify a signed file
        signed_png = msd.sign_and_embed({'__type': 'PngImage', 'data': base64_str}, metadata, key)
        assert msd.verify(signed_png) == True
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
    
    # Case 1: SignedGranule dict
    if type_field == 'ET.SignedGranule':
        return _verify_granule(data)
    
    # Case 2: Typed data with embedded signature (PngImage, PDF, etc.)
    if type_field in TYPED_DATA_TYPES:
        return _verify_file(data)
    
    # Case 3: Dict signed with sign_and_embed_dict (has __msd key)
    has_msd = False
    try:
        _ = data['__msd']
        has_msd = True
    except (KeyError, TypeError):
        pass
    
    if has_msd:
        return _verify_dict(data)
    
    raise ValueError(
        "verify() expects a SignedGranule dict (with '__type': 'ET.SignedGranule'), "
        "a typed data dict (with '__type' in " + str(sorted(TYPED_DATA_TYPES)) + "), "
        "or a dict with embedded signature (with '__msd' key). "
        "Got keys: " + str(list(data.keys()))
    )




def sign_and_embed(data: dict, metadata: dict, key: dict) -> dict:
    """
    Sign data and embed the signature into it.
    
    Accepts a typed dict with '__type' and 'data' keys:
        {'__type': 'PngImage', 'data': '<base64>'}
    
    Returns the same typed dict format with the signature embedded in the content.
    
    Supported types: PngImage, JpgImage, WebpImage, SvgImage, PDF,
    WordDocument, ExcelDocument, PowerpointDocument.
    """
    import zef
    
    _validate_typed_values(data)
    _validate_typed_values(metadata)
    if not _is_typed_data(data):
        raise ValueError(
            f"sign_and_embed expects a typed file dict with '__type' in {sorted(_FILE_EMBEDDABLE_TYPES)}. "
            f"Got: {data.get('__type', '<missing>')}"
        )
    
    data_ = _typed_dict_to_zef(data)
    
    # Strip any existing embedded data to ensure idempotent behavior
    data_ = zef.strip_embedded_data(data_)
    
    timestamp = zef.now()
    key_internal = zef.from_json_like(key)

    # Embed signature data (without the actual file content)
    binary_data_to_embed = (zef.create_signed_granule(data_, metadata, timestamp, key_internal) 
        | zef.remove('data') 
        | zef.to_bytes
        | zef.collect
    )    
    signed = zef.embed_data(data_, binary_data_to_embed)
    return _zef_to_typed_dict(signed)




def sign_and_embed_dict(data: dict, metadata: dict, key: dict) -> dict:
    """
    Sign a plain Python dict and embed the metadata + signature using Unicode steganography.
    
    The cryptographic payload (metadata, timestamp, signature, public key) is compressed,
    base64-encoded, and hidden inside invisible Unicode variation selectors attached to a
    single emoji character (🔏). This keeps the dict clean and human-readable — the
    signature never clutters the output.
    
    The returned dict contains all original key-value pairs plus an `__msd` key whose
    value looks like a single emoji but carries the full steganographic payload.
    Survives JSON round-trips.
    
    See sign_and_embed() for signing binary file formats (PNG, JPG, PDF, etc.).
    """
    import zef
    
    if not isinstance(data, dict):
        raise ValueError("sign_and_embed_dict expects a dictionary as input")

    if '__msd' in data:
        raise ValueError("Input data already contains an '__msd' key, cannot embed MSD data without overwriting existing key")
    
    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be a dictionary")
    
    _validate_typed_values(data)
    _validate_typed_values(metadata)

    timestamp = zef.now()
    key_internal = zef.from_json_like(key)
    granule = zef.create_signed_granule(data, metadata, timestamp, key_internal)
    
    sig_and_metadata = {
        'metadata': granule['metadata'],
        'signature_time': granule['signature_time'],
        'signature': granule['signature'],
        'key': granule['key']
    }

    sig_and_metadata_bytes = zef.collect(sig_and_metadata).to_bytes()
    sig_and_metadata_bytes_compressed = zef.zstd_compress(sig_and_metadata_bytes)
    sig_and_metadata_bytes_compressed_b64 = zef.to_base64(sig_and_metadata_bytes_compressed.compressed_bytes)
    encoded = zef.encode_secret_string_in_emoji(sig_and_metadata_bytes_compressed_b64, '🔏')

    return {
        **data,
        '__msd': str(encoded)
    }

    




def _extract_msd_from_dict(signed_dict_data: dict) -> dict:
    """
    Extract the full sig_and_metadata structure from a dict that was signed
    with sign_and_embed_dict. Reverses the Unicode steganography encoding chain:
    emoji → decode → base64 → decompress → bytes → data.
    
    Returns:
        The decoded sig_and_metadata dict with keys:
        'metadata', 'signature_time', 'signature', 'key'.
    
    Raises:
        ValueError: If no '__msd' key is found.
    """
    import zef
    
    if '__msd' not in signed_dict_data:
        raise ValueError("No '__msd' key found in dict — this dict was not signed with sign_and_embed_dict")
    
    emoji_str = signed_dict_data['__msd']
    
    # Reverse the Unicode steganography encoding chain from sign_and_embed_dict:
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
    Extract metadata from a signed dict (Unicode steganography) or a signed
    typed data dict (PngImage, PDF, etc.).
    
    Args:
        signed_data: Either:
            - A dict with an '__msd' key (from sign_and_embed_dict), or
            - A typed data dict with '__type' (from sign_and_embed).
    
    Returns:
        The metadata dictionary that was attached during signing.
    
    Raises:
        ValueError: If no embedded signature data is found.
    """
    import zef
    
    # Case 1: Dict signed with sign_and_embed_dict
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
    Extract signature information from a signed dict (Unicode steganography)
    or a signed typed data dict (PngImage, PDF, etc.).
    
    Args:
        signed_data: Either:
            - A dict with an '__msd' key (from sign_and_embed_dict), or
            - A typed data dict with '__type' (from sign_and_embed).
    
    Returns:
        A dictionary with signature information including:
        'signature', 'signature_time', and 'key'.
    
    Raises:
        ValueError: If no embedded signature data is found.
    """
    import zef
    
    # Case 1: Dict signed with sign_and_embed_dict
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
        signed_data: A typed data dict with '__type' (from sign_and_embed).
    
    Returns:
        A typed data dict with the same '__type' but clean content
        (all embedded MSD data removed).
    """
    import zef
    
    data_ = _typed_dict_to_zef(signed_data)
    stripped = zef.strip_embedded_data(data_)
    return _zef_to_typed_dict(stripped)

