#%%
"""
Test file for sign() function.

sign() is the new primary signing function that returns ET.SignedData dicts.
It strips embedded data from typed files before signing and delegates to
the same Zef signing pipeline.
"""

from zef import *
import msd_sdk as msd
import base64


# Sample key from README.md for testing
sample_key = {
  '__type': 'ET.Ed25519KeyPair',
  '__uid': '🍃-8d1dc8766070c87a4bb1',
  'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
  'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284'
}


# ============================================================================
# Test 1: sign() returns correct structure
# ============================================================================

test_cases_structure = [
  ('🍃-a1b2c3d4e5f6a7b8c9d0', 'sign string data returns ET.SignedData',
   'Hello, Meta Structured Data!', {'creator': 'Alice'}),
  ('🍃-b2c3d4e5f6a7b8c9d0a1', 'sign dict data returns ET.SignedData',
   {'message': 'hello', 'count': 42}, {'creator': 'Bob'}),
  ('🍃-c3d4e5f6a7b8c9d0a1b2', 'sign integer data returns ET.SignedData',
   42, {'type': 'number'}),
  ('🍃-d4e5f6a7b8c9d0a1b2c3', 'sign with empty metadata',
   'data', {}),
  ('🍃-e5f6a7b8c9d0a1b2c3d4', 'sign None data',
   nil, {'type': 'null'}),
  ('🍃-f6a7b8c9d0a1b2c3d4e5', 'sign nested dict data',
   {'outer': {'inner': {'deep': True}}, 'list': [1, 2, 3]}, {'schema': 'v2'}),
]


def run_structure_tests(test_cases):
    """Test that sign() returns correct structure with ET.SignedData."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        try:
            signed = msd.sign(data, metadata, sample_key)
        except Exception as e:
            failed.append({'description': desc, 'error': f'sign() raised: {e}'})
            continue
        
        # Must be a dict
        if not isinstance(signed, dict):
            failed.append({'description': desc, 'error': f'Expected dict, got {type(signed)}'})
            continue
        
        # Must have __type = 'ET.SignedData'
        if signed.get('__type') != 'ET.SignedData':
            failed.append({'description': desc, 'error': f'Wrong __type: {signed.get("__type")}'})
            continue
        
        # Must have required keys
        required_keys = {'__type', 'data', 'metadata', 'signature_time', 'signature', 'key'}
        actual_keys = set(signed.keys())
        if not required_keys.issubset(actual_keys):
            failed.append({'description': desc, 'error': f'Missing keys: {required_keys - actual_keys}'})
            continue
        
        # Metadata must match input
        if signed['metadata'] != metadata:
            failed.append({'description': desc, 'error': f'Metadata mismatch'})
            continue
        
        # Data must match input (normalize nil → None)
        expected_data = None if data == nil else data
        if signed['data'] != expected_data:
            failed.append({'description': desc, 'error': f'Data mismatch: expected {expected_data}, got {signed["data"]}'})
            continue
        
        # Key's public key must match
        if signed['key'].get('public_key') != sample_key['public_key']:
            failed.append({'description': desc, 'error': f'Public key mismatch in result'})
            continue
    
    return failed


# ============================================================================
# Test 2: sign() output verifies with verify()
# ============================================================================

test_cases_verify = [
  ('🍃-1a2b3c4d5e6f7a8b9c0d', 'sign string verifies',
   'Hello world', {'creator': 'Alice'}),
  ('🍃-2b3c4d5e6f7a8b9c0d1a', 'sign dict verifies',
   {'key': 'value', 'nested': {'a': 1}}, {'schema': 'v1'}),
  ('🍃-3c4d5e6f7a8b9c0d1a2b', 'sign list verifies',
   [1, 'two', 3.0, True, None], {'type': 'mixed'}),
]


def run_verify_tests(test_cases):
    """Test that sign() output can be verified with verify()."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        signed = msd.sign(data, metadata, sample_key)
        
        try:
            result = msd.verify(signed)
        except Exception as e:
            failed.append({'description': desc, 'error': f'verify() raised: {e}'})
            continue
        
        if not result['signature_is_valid']:
            failed.append({'description': desc, 'error': 'verify returned signature_is_valid=False for freshly signed data'})
    
    return failed


# ============================================================================
# Test 3: sign() with typed file data (PngImage)
# ============================================================================

test_cases_typed = [
  ('🍃-4d5e6f7a8b9c0d1a2b3c', 'sign PngImage typed data'),
]


def _create_minimal_png():
    """Create a minimal valid 1x1 pixel PNG for testing."""
    import struct
    import zlib
    
    signature = b'\x89PNG\r\n\x1a\n'
    
    def chunk(chunk_type, data):
        c = chunk_type + data
        crc = struct.pack('>I', zlib.crc32(c) & 0xffffffff)
        return struct.pack('>I', len(data)) + c + crc
    
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    raw_data = b'\x00\xff\x00\x00'
    compressed = zlib.compress(raw_data)
    
    return signature + chunk(b'IHDR', ihdr_data) + chunk(b'IDAT', compressed) + chunk(b'IEND', b'')


def run_typed_tests(test_cases):
    """Test sign() with typed file data."""
    failed = []
    
    png_bytes = _create_minimal_png()
    png_b64 = base64.b64encode(png_bytes).decode()
    file_data = {'__type': 'PngImage', 'data': png_b64}
    metadata = {'creator': 'test', 'format': 'png'}
    
    try:
        signed = msd.sign(file_data, metadata, sample_key)
    except Exception as e:
        failed.append({'description': 'sign PngImage typed data', 'error': f'sign() raised: {e}'})
        return failed
    
    # __type must be ET.SignedData
    if signed.get('__type') != 'ET.SignedData':
        failed.append({'description': 'sign PngImage typed data', 'error': f'Wrong __type: {signed.get("__type")}'})
        return failed
    
    # data field must be a typed dict (PngImage)
    if not isinstance(signed['data'], dict) or signed['data'].get('__type') != 'PngImage':
        failed.append({'description': 'sign PngImage typed data', 'error': f'Data not a PngImage typed dict'})
        return failed
    
    # Must verify
    try:
        result = msd.verify(signed)
    except Exception as e:
        failed.append({'description': 'sign PngImage typed data', 'error': f'verify raised: {e}'})
        return failed
    
    if not result['signature_is_valid']:
        failed.append({'description': 'sign PngImage typed data', 'error': 'Verification failed'})
    
    return failed


# ============================================================================
# Test 4: sign() validates __type fields
# ============================================================================

test_cases_validation = [
  ('🍃-5e6f7a8b9c0d1a2b3c4d', 'sign rejects invalid __type in data'),
  ('🍃-6f7a8b9c0d1a2b3c4d5e', 'sign rejects invalid __type in metadata'),
]


def run_validation_tests(test_cases):
    """Test that sign() validates __type fields."""
    failed = []
    
    # Invalid __type in data
    try:
        msd.sign({'__type': 'FakeType', 'data': 'whatever'}, {}, sample_key)
        failed.append({'description': 'Rejects invalid __type in data', 'error': 'Should have raised ValueError'})
    except ValueError:
        pass
    except Exception as e:
        failed.append({'description': 'Rejects invalid __type in data', 'error': f'Wrong exception: {type(e).__name__}: {e}'})
    
    # Invalid __type in metadata
    try:
        msd.sign('data', {'__type': 'BogusEntity'}, sample_key)
        failed.append({'description': 'Rejects invalid __type in metadata', 'error': 'Should have raised ValueError'})
    except ValueError:
        pass
    except Exception as e:
        failed.append({'description': 'Rejects invalid __type in metadata', 'error': f'Wrong exception: {type(e).__name__}: {e}'})
    
    return failed


# ============================================================================
# Test 5: extract_metadata() on raw ET.SignedData
# ============================================================================

test_cases_extract_meta = [
  ('🍃-7a8b9c0d1a2b3c4d5e6f', 'extract_metadata from signed string',
   'Hello world', {'creator': 'Alice', 'version': '1.0'}),
  ('🍃-8b9c0d1a2b3c4d5e6f7a', 'extract_metadata from signed dict',
   {'message': 'test', 'count': 42}, {'schema': 'v2', 'author': 'Bob'}),
  ('🍃-9c0d1a2b3c4d5e6f7a8b', 'extract_metadata with empty metadata',
   'data', {}),
]


def run_extract_meta_tests(test_cases):
    """Test that extract_metadata() works on raw ET.SignedData output from sign()."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        signed = msd.sign(data, metadata, sample_key)
        
        try:
            extracted = msd.extract_metadata(signed)
        except Exception as e:
            failed.append({'description': desc, 'error': f'extract_metadata() raised: {e}'})
            continue
        
        if extracted != metadata:
            failed.append({'description': desc, 'error': f'Metadata mismatch: expected {metadata}, got {extracted}'})
    
    return failed


# ============================================================================
# Test 6: extract_signature() on raw ET.SignedData
# ============================================================================

test_cases_extract_sig = [
  ('🍃-0d1a2b3c4d5e6f7a8b9c', 'extract_signature from signed string',
   'Hello world', {'creator': 'Alice'}),
  ('🍃-1a2b3c4d5e6f7a8b9c0e', 'extract_signature from signed dict',
   {'key': 'value'}, {'schema': 'v1'}),
]


def run_extract_sig_tests(test_cases):
    """Test that extract_signature() works on raw ET.SignedData output from sign()."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        signed = msd.sign(data, metadata, sample_key)
        
        try:
            sig_info = msd.extract_signature(signed)
        except Exception as e:
            failed.append({'description': desc, 'error': f'extract_signature() raised: {e}'})
            continue
        
        # Must have signature, signature_time, and key
        for required in ('signature', 'signature_time', 'key'):
            if required not in sig_info:
                failed.append({'description': desc, 'error': f'Missing key: {required}'})
                break
        else:
            # Key's public key must match the signing key
            if sig_info['key'].get('public_key') != sample_key['public_key']:
                failed.append({'description': desc, 'error': 'Public key mismatch in extracted signature'})
    
    return failed


# ============================================================================
# Run all test groups
# ============================================================================

all_groups = [
    ("Structure", run_structure_tests, test_cases_structure),
    ("Verify round-trip", run_verify_tests, test_cases_verify),
    ("Typed file data", run_typed_tests, test_cases_typed),
    ("Validation", run_validation_tests, test_cases_validation),
    ("Extract metadata from ET.SignedData", run_extract_meta_tests, test_cases_extract_meta),
    ("Extract signature from ET.SignedData", run_extract_sig_tests, test_cases_extract_sig),
]

total_passed = 0
total_failed = 0

for group_name, runner, cases in all_groups:
    failed = runner(cases)
    passed = len(cases) - len(failed)
    total_passed += passed
    total_failed += len(failed)
    
    if failed:
        print(f"❌ {group_name}: {len(failed)}/{len(cases)} failed")
        for f in failed:
            print(f"   - {f['description']}: {f['error']}")
    else:
        print(f"✅ {group_name}: {len(cases)}/{len(cases)} passed")

total = total_passed + total_failed
print(f"\n{'✅' if total_failed == 0 else '❌'} All {total} tests: {total_passed} passed, {total_failed} failed")
