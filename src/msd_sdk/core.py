"""Core API functions for MSD SDK."""

import json
import time


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
              - Entity types: ET.* wrapped dicts
    
    Returns:
        A dict with structure:
        {
            '__type': 'MsdHash',
            'hash': '<64-character hex string>'
        }
    """
    import zef
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


def _parse_to_zef_type(data: dict):
    """
    Parse a file dict to its corresponding Zef type.
    
    Args:
        data: A dict with 'type' and 'content' keys.
    
    Returns:
        The corresponding Zef type (PngImage, JpgImage, PDF, etc.)
    
    Raises:
        ValueError: If the type is not supported.
    """
    import zef
    
    match data['type']:
        case 'png': return zef.PngImage(data['content'])
        case 'jpg': return zef.JpgImage(data['content'])
        case 'pdf': return zef.PDF(data['content'])
        case 'word_document': return zef.ET.WordDocument(content=data['content'])
        case 'excel_document': return zef.ET.ExcelDocument(content=data['content'])
        case 'powerpoint_document': return zef.ET.PowerpointDocument(content=data['content'])
        case _: raise ValueError(
            f"Unsupported file type: '{data['type']}'. "
            f"Supported types: png, jpg, pdf, word_document, excel_document, powerpoint_document"
        )


def _verify_file(signed_data: dict) -> bool:
    """
    Verify the embedded signature in a signed file.
    
    Internal function - use verify() for the public API.
    
    Args:
        signed_data: A dict with 'type' and 'content' keys containing a signed file.
    
    Returns:
        True if the signature is valid, False otherwise.
    
    Raises:
        ValueError: If no embedded signature is found or file type is unsupported.
    """
    import zef
    
    # 1. Parse to Zef type
    typed_file = _parse_to_zef_type(signed_data)
    
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
        signed_png = msd.sign_and_embed({'type': 'png', 'content': bytes}, metadata, key)
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
    
    # Case 2: Dict signed with sign_and_embed_dict (has __msd key)
    has_msd = False
    try:
        _ = data['__msd']
        has_msd = True
    except (KeyError, TypeError):
        pass
    
    if has_msd:
        return _verify_dict(data)
    
    # Case 3: File dict with 'type' and 'content'
    has_type = False
    has_content = False
    try:
        _ = data['type']
        has_type = True
    except (KeyError, TypeError):
        pass
    try:
        _ = data['content']
        has_content = True
    except (KeyError, TypeError):
        pass
    
    if has_type and has_content:
        return _verify_file(data)
    
    raise ValueError(
        "verify() expects a SignedGranule dict (with '__type': 'ET.SignedGranule'), "
        "a dict with embedded signature (with '__msd' key), "
        "or a file dict (with 'type' and 'content' keys). "
        "Got keys: " + str(list(data.keys()))
    )




def sign_and_embed(data: dict, metadata: dict, key: dict) -> dict:
    import zef
    match data['type']:
        case 'png': data_ = zef.PngImage(data['content'])
        case 'jpg': data_ = zef.JpgImage(data['content'])
        case 'pdf': data_ = zef.PDF(data['content'])
        case 'word_document': data_ = zef.ET.WordDocument(content=data['content'])
        case 'excel_document': data_ = zef.ET.ExcelDocument(content=data['content'])
        case 'powerpoint_document': data_ = zef.ET.PowerpointDocument(content=data['content'])
        case _: raise ValueError(f"Unsupported type in msd_sdk.sign_and_embed: {data['type']}")
    
    # First strip any existing embedded data to ensure idempotent behavior
    data_ = zef.strip_embedded_data(data_)
    
    timestamp = zef.now()
    key_internal = zef.from_json_like(key)

    # this should NOT contain the actual image data
    binary_data_to_embed = (zef.create_signed_granule(data_, metadata, timestamp, key_internal) 
        | zef.remove('data') 
        | zef.to_bytes
        | zef.collect
    )    
    signed = zef.embed_data(data_, binary_data_to_embed)
    match data['type']:
        case 'png': return {'type': 'png', 'content': bytes(signed.data_as_bytes())}
        case 'jpg': return {'type': 'jpg', 'content': bytes(signed.data_as_bytes())}
        case 'pdf': return {'type': 'pdf', 'content': bytes(signed.data_as_bytes())}
        case 'word_document': return {'type': 'word_document', 'content': bytes(signed.content)}
        case 'excel_document': return {'type': 'excel_document', 'content': bytes(signed.content)}
        case 'powerpoint_document': return {'type': 'powerpoint_document', 'content': bytes(signed.content)}
        case _: raise ValueError(f"Unsupported image type: {data['type']}")




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
    binary file (PNG, JPG, PDF, etc.).
    
    Args:
        signed_data: Either:
            - A dict with an '__msd' key (from sign_and_embed_dict), or
            - A dict with 'type' and 'content' keys (binary file).
    
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
    
    # Case 2: Binary file with embedded signature
    match signed_data['type']:
        case 'png': data_ = zef.PngImage(signed_data['content'])
        case 'jpg': data_ = zef.JpgImage(signed_data['content'])
        case 'pdf': data_ = zef.PDF(signed_data['content'])
        case 'word_document': data_ = zef.ET.WordDocument(content=signed_data['content'])
        case 'excel_document': data_ = zef.ET.ExcelDocument(content=signed_data['content'])
        case 'powerpoint_document': data_ = zef.ET.PowerpointDocument(content=signed_data['content'])
        case _: raise ValueError(f"Unsupported type: {signed_data['type']}")
    
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
    or a signed binary file (PNG, JPG, PDF, etc.).
    
    Args:
        signed_data: Either:
            - A dict with an '__msd' key (from sign_and_embed_dict), or
            - A dict with 'type' and 'content' keys (binary file).
    
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
    
    # Case 2: Binary file with embedded signature
    match signed_data['type']:
        case 'png': data_ = zef.PngImage(signed_data['content'])
        case 'jpg': data_ = zef.JpgImage(signed_data['content'])
        case 'pdf': data_ = zef.PDF(signed_data['content'])
        case 'word_document': data_ = zef.ET.WordDocument(content=signed_data['content'])
        case 'excel_document': data_ = zef.ET.ExcelDocument(content=signed_data['content'])
        case 'powerpoint_document': data_ = zef.ET.PowerpointDocument(content=signed_data['content'])
        case _: raise ValueError(f"Unsupported type: {signed_data['type']}")
    
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
    Strip the embedded metadata and signature from a signed media file,
    returning the original file content.
    
    Args:
        signed_data: A dict with 'type' and 'content' keys, where content
                     is the binary data of the signed file.
    
    Returns:
        A dict with 'type' and 'content' keys, where content is the
        original file data with all embedded MSD data removed.
    """
    import zef
    
    match signed_data['type']:
        case 'png': data_ = zef.PngImage(signed_data['content'])
        case 'jpg': data_ = zef.JpgImage(signed_data['content'])
        case 'pdf': data_ = zef.PDF(signed_data['content'])
        case 'word_document': data_ = zef.ET.WordDocument(content=signed_data['content'])
        case 'excel_document': data_ = zef.ET.ExcelDocument(content=signed_data['content'])
        case 'powerpoint_document': data_ = zef.ET.PowerpointDocument(content=signed_data['content'])
        case _: raise ValueError(f"Unsupported type: {signed_data['type']}")
    
    # Call strip_embedded_data as function, not through pipe
    stripped = zef.strip_embedded_data(data_)
    
    match signed_data['type']:
        case 'png': return {'type': 'png', 'content': bytes(stripped.data_as_bytes())}
        case 'jpg': return {'type': 'jpg', 'content': bytes(stripped.data_as_bytes())}
        case 'pdf': return {'type': 'pdf', 'content': bytes(stripped.data_as_bytes())}
        case 'word_document': return {'type': 'word_document', 'content': bytes(stripped.content)}
        case 'excel_document': return {'type': 'excel_document', 'content': bytes(stripped.content)}
        case 'powerpoint_document': return {'type': 'powerpoint_document', 'content': bytes(stripped.content)}
        case _: raise ValueError(f"Unsupported type: {signed_data['type']}")

