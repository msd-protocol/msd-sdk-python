#%%
"""
Test file for sign_and_embed (file signing) and generate_key_pair.

Tests binary file signing/verification pipeline for supported formats
and key pair generation.

NOTE: Test data (dicts, file bytes) must be plain Python types, not stored 
in ET.UnitTest args, because SDK functions check isinstance(data, dict).
"""

from zef import *
import msd_sdk as msd
import os

# Sample key from README.md for testing
sample_key = {
  '__type': 'ET.Ed25519KeyPair',
  '__uid': '🍃-8d1dc8766070c87a4bb1',
  'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
  'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284'
}

# Locate test fixtures
test_dir = os.path.dirname(os.path.abspath(__file__))
fixtures_dir = os.path.join(test_dir, '..', 'tests', 'fixtures')
if not os.path.isdir(fixtures_dir):
    fixtures_dir = os.path.join(test_dir, 'fixtures')


def load_fixture(filename):
    """Load a test fixture file as bytes."""
    path = os.path.join(fixtures_dir, filename)
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read()
    return None


# ============================================================================
# Test 1: generate_key_pair
# ============================================================================
# UIDs: 🍃-905157fb968bdb0ec48c, 🍃-22d151736e1f667890d4

test_cases_keygen = [
  ('🍃-905157fb968bdb0ec48c', 'Generate unendorsed key pair'),
  ('🍃-22d151736e1f667890d4', 'Generated keys have correct structure'),
]


def run_keygen_tests(test_cases):
    """Test key pair generation."""
    failed = []
    
    # Test: generate_key_pair(unendorsed=True) returns valid key
    try:
        key = msd.generate_key_pair(unendorsed=True)
    except Exception as e:
        failed.append({'description': 'Generate unendorsed key pair', 'error': f'Raised: {e}'})
        return failed
    
    if not isinstance(key, dict):
        failed.append({'description': 'Generate unendorsed key pair', 'error': f'Expected dict, got {type(key)}'})
        return failed
    
    # Check required fields
    required_fields = ['__type', '__uid', 'private_key', 'public_key']
    for field in required_fields:
        if field not in key:
            failed.append({'description': 'Generated keys have correct structure', 'error': f'Missing field: {field}'})
            return failed
    
    if key['__type'] != 'ET.Ed25519KeyPair':
        failed.append({'description': 'Generated keys have correct structure', 'error': f'Wrong __type: {key["__type"]}'})
        return failed
    
    # public_key should start with 🔑-, private_key with 🗝️-
    if not isinstance(key['public_key'], str) or not key['public_key'].startswith('🔑-'):
        failed.append({'description': 'Generated keys have correct structure', 'error': f'Invalid public_key format'})
        return failed
    
    if not isinstance(key['private_key'], str) or not key['private_key'].startswith('🗝️-'):
        failed.append({'description': 'Generated keys have correct structure', 'error': f'Invalid private_key format'})
        return failed
    
    # Test: key can be used to sign and verify
    try:
        granule = msd.create_granule('test data', {'test': True}, key)
        if not msd.verify(granule):
            failed.append({'description': 'Generate unendorsed key pair', 'error': 'Generated key cannot sign/verify'})
    except Exception as e:
        failed.append({'description': 'Generate unendorsed key pair', 'error': f'Sign/verify with generated key failed: {e}'})
    
    return failed


# ============================================================================
# Test 2: sign_and_embed for file types (only run if fixtures exist)
# ============================================================================
# UIDs: 🍃-68fdcc0e873b394ead26, 🍃-d6bf5c02c7d2f77875ae, 🍃-b6c1099d690acc4979ea

# Build file test cases dynamically based on available fixtures
file_fixtures = {
    'png': 'sample.png',
    'jpg': 'sample.jpg',
    'pdf': 'sample.pdf',
    'word_document': 'sample.docx',
    'excel_document': 'sample.xlsx',
    'powerpoint_document': 'sample.pptx',
}

test_cases_files = [
  ('🍃-68fdcc0e873b394ead26', 'Sign and verify file round-trip'),
  ('🍃-d6bf5c02c7d2f77875ae', 'Extract metadata from signed file'),
  ('🍃-b6c1099d690acc4979ea', 'Strip signature returns usable content'),
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


def run_file_tests(test_cases):
    """Test sign_and_embed for file types."""
    failed = []
    
    # Use a minimal PNG we can always generate
    png_bytes = _create_minimal_png()
    
    # Test: sign_and_embed + verify round-trip
    file_data = {'type': 'png', 'content': png_bytes}
    metadata = {'creator': 'test', 'format': 'png'}
    
    try:
        signed = msd.sign_and_embed(file_data, metadata, sample_key)
    except Exception as e:
        failed.append({'description': 'Sign and verify file round-trip', 'error': f'sign_and_embed raised: {e}'})
        return failed
    
    if not isinstance(signed, dict) or 'type' not in signed or 'content' not in signed:
        failed.append({'description': 'Sign and verify file round-trip', 'error': f'Invalid return structure'})
        return failed
    
    if signed['type'] != 'png':
        failed.append({'description': 'Sign and verify file round-trip', 'error': f'Type changed: {signed["type"]}'})
        return failed
    
    if not isinstance(signed['content'], bytes):
        failed.append({'description': 'Sign and verify file round-trip', 'error': f'Content not bytes: {type(signed["content"])}'})
        return failed
    
    # Signed content should be larger (has embedded data)
    if len(signed['content']) <= len(png_bytes):
        failed.append({'description': 'Sign and verify file round-trip', 'error': 'Signed content not larger than original'})
        return failed
    
    # Verify the signed file
    try:
        is_valid = msd.verify(signed)
    except Exception as e:
        failed.append({'description': 'Sign and verify file round-trip', 'error': f'verify raised: {e}'})
        return failed
    
    if not is_valid:
        failed.append({'description': 'Sign and verify file round-trip', 'error': 'Verification failed'})
        return failed
    
    # Test: extract_metadata from signed file
    try:
        extracted_meta = msd.extract_metadata(signed)
    except Exception as e:
        failed.append({'description': 'Extract metadata from signed file', 'error': f'extract_metadata raised: {e}'})
        return failed
    
    if not isinstance(extracted_meta, dict):
        failed.append({'description': 'Extract metadata from signed file', 'error': f'Expected dict, got {type(extracted_meta)}'})
        return failed
    
    if extracted_meta != metadata:
        failed.append({'description': 'Extract metadata from signed file', 'error': f'Mismatch: expected {metadata}, got {extracted_meta}'})
        return failed
    
    # Test: strip_metadata_and_signature
    try:
        stripped = msd.strip_metadata_and_signature(signed)
    except Exception as e:
        failed.append({'description': 'Strip signature returns usable content', 'error': f'strip raised: {e}'})
        return failed
    
    if stripped['type'] != 'png':
        failed.append({'description': 'Strip signature returns usable content', 'error': f'Type changed after strip: {stripped["type"]}'})
        return failed
    
    if not isinstance(stripped['content'], bytes):
        failed.append({'description': 'Strip signature returns usable content', 'error': f'Content not bytes after strip'})
        return failed
    
    # Stripped should be smaller than signed
    if len(stripped['content']) >= len(signed['content']):
        failed.append({'description': 'Strip signature returns usable content', 'error': 'Stripped not smaller than signed'})
        return failed
    
    return failed


# ============================================================================
# Run all test groups
# ============================================================================

all_groups = [
    ("Key generation", run_keygen_tests, test_cases_keygen),
    ("File sign/verify/extract/strip", run_file_tests, test_cases_files),
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
