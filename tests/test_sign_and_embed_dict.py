#%%
"""
Test file for sign_and_embed_dict, extract_metadata, extract_signature, and verify on dicts.

Tests the Unicode steganography signing pipeline:
  sign_and_embed_dict → verify → extract_metadata → extract_signature

sign_and_embed_dict is NON-DETERMINISTIC (uses zef.now()), so we test
behavior rather than exact values.

NOTE: Test data must be plain Python dicts (not stored in ET.UnitTest args)
because sign_and_embed_dict checks isinstance(data, dict), and Zef Dict2_
types stored inside ET.UnitTest args would fail that check.
"""

from zef import *
import msd_sdk as msd
import json


# Sample key from README.md for testing
sample_key = {
  '__type': 'ET.Ed25519KeyPair',
  '__uid': '🍃-8d1dc8766070c87a4bb1',
  'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
  'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284'
}


# ============================================================================
# Test 1: Basic sign and verify round-trip
# ============================================================================
# UIDs for tracking: 🍃-b3cfc01fdde0cf2bd884 through 🍃-ddaec642f513422800b6
test_cases_sign_verify = [
  ('🍃-b3cfc01fdde0cf2bd884', 'Sign and verify simple dict',
   {'message': 'hello', 'count': 42}, {'creator': 'Alice'}),
  ('🍃-21e755af972aff951c6d', 'Sign and verify empty data dict',
   {}, {'creator': 'Test'}),
  ('🍃-59b28554944e0e5edfe8', 'Sign and verify nested dict',
   {'outer': {'inner': {'deep': True}}, 'list': [1, 2, 3]}, {'schema': 'v2'}),
  ('🍃-db06facdbb581533bb21', 'Sign and verify dict with various value types',
   {'str': 'text', 'int': 99, 'float': 2.718, 'bool': False, 'null': None}, {'type': 'mixed'}),
  ('🍃-ddaec642f513422800b6', 'Sign and verify dict with empty metadata',
   {'data': 'value'}, {}),
]


def run_sign_verify_tests(test_cases):
    """Test that sign_and_embed_dict produces verifiable dicts."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        
        try:
            signed = msd.sign_and_embed_dict(data, metadata, sample_key)
        except Exception as e:
            failed.append({'description': desc, 'error': f'sign_and_embed_dict raised: {e}'})
            continue
        
        # Must be a dict
        if not isinstance(signed, dict):
            failed.append({'description': desc, 'error': f'Expected dict, got {type(signed)}'})
            continue
        
        # Must contain __msd key
        if '__msd' not in signed:
            failed.append({'description': desc, 'error': 'Missing __msd key in signed dict'})
            continue
        
        # __msd must start with 🔏
        msd_val = signed['__msd']
        if not isinstance(msd_val, str) or not msd_val.startswith('🔏'):
            failed.append({'description': desc, 'error': f'__msd should start with 🔏, got: {repr(msd_val[:20])}'})
            continue
        
        # Original data must be preserved
        for k, v in data.items():
            if k not in signed or signed[k] != v:
                failed.append({'description': desc, 'error': f'Original key {k} not preserved'})
                break
        else:
            # Verify must return True
            try:
                is_valid = msd.verify(signed)
            except Exception as e:
                failed.append({'description': desc, 'error': f'verify raised: {e}'})
                continue
            
            if not is_valid:
                failed.append({'description': desc, 'error': 'verify returned False for freshly signed dict'})
    
    return failed


# ============================================================================
# Test 2: Tamper detection on signed dicts
# ============================================================================
# UIDs: 🍃-716ea33d9151542d3408, 🍃-5933615d1855cf5c3064, 🍃-e961fcc3942b7ae9e5d9
test_cases_tamper = [
  ('🍃-716ea33d9151542d3408', 'Tamper: modify existing value',
   {'amount': 100, 'currency': 'USD'}, {'source': 'bank'}),
  ('🍃-5933615d1855cf5c3064', 'Tamper: add new key',
   {'status': 'approved'}, {'reviewer': 'Bob'}),
  ('🍃-e961fcc3942b7ae9e5d9', 'Tamper: remove a key',
   {'secret': 'data', 'public': 'info'}, {'level': 'mixed'}),
]


def run_tamper_tests(test_cases):
    """Test that tampering with signed dicts is detected."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        
        signed = msd.sign_and_embed_dict(data, metadata, sample_key)
        
        # First verify the untampered version works
        if not msd.verify(signed):
            failed.append({'description': desc, 'error': 'Untampered dict failed verification'})
            continue
        
        # Now tamper based on the test description
        tampered = dict(signed)  # shallow copy
        if 'modify existing' in desc.lower():
            first_key = [k for k in data.keys()][0]
            tampered[first_key] = 'TAMPERED'
        elif 'add new' in desc.lower():
            tampered['backdoor'] = True
        elif 'remove a key' in desc.lower():
            first_key = [k for k in data.keys()][0]
            del tampered[first_key]
        
        # Tampered dict should fail verification
        try:
            is_valid = msd.verify(tampered)
            if is_valid:
                failed.append({'description': desc, 'error': 'Tampered dict passed verification (should fail)'})
        except Exception:
            # An exception during verify of tampered data is acceptable
            pass
    
    return failed


# ============================================================================
# Test 3: extract_metadata from signed dicts
# ============================================================================
# UIDs: 🍃-2aac3f28736ceb6829a1, 🍃-66984824b7733f65772d
test_cases_extract_meta = [
  ('🍃-2aac3f28736ceb6829a1', 'Extract metadata from signed dict',
   {'payload': 'test'}, {'creator': 'Alice', 'version': '1.0', 'tags': ['important']}),
  ('🍃-66984824b7733f65772d', 'Extract empty metadata from signed dict',
   {'payload': 'test'}, {}),
]


def run_extract_metadata_tests(test_cases):
    """Test that extract_metadata recovers the metadata from signed dicts."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        
        signed = msd.sign_and_embed_dict(data, metadata, sample_key)
        
        try:
            extracted = msd.extract_metadata(signed)
        except Exception as e:
            failed.append({'description': desc, 'error': f'extract_metadata raised: {e}'})
            continue
        
        if not isinstance(extracted, dict):
            failed.append({'description': desc, 'error': f'Expected dict, got {type(extracted)}'})
            continue
        
        if extracted != metadata:
            failed.append({'description': desc, 'error': f'Metadata mismatch: expected {metadata}, got {extracted}'})
    
    return failed


# ============================================================================
# Test 4: extract_signature from signed dicts
# ============================================================================
# UID: 🍃-2931395fffeb9695e7e5
test_cases_extract_sig = [
  ('🍃-2931395fffeb9695e7e5', 'Extract signature info from signed dict',
   {'payload': 'test'}, {'creator': 'Alice'}),
]


def run_extract_signature_tests(test_cases):
    """Test that extract_signature returns signature info with expected keys."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        
        signed = msd.sign_and_embed_dict(data, metadata, sample_key)
        
        try:
            sig_info = msd.extract_signature(signed)
        except Exception as e:
            failed.append({'description': desc, 'error': f'extract_signature raised: {e}'})
            continue
        
        if not isinstance(sig_info, dict):
            failed.append({'description': desc, 'error': f'Expected dict, got {type(sig_info)}'})
            continue
        
        # Must have the three expected keys
        for required_key in ['signature', 'signature_time', 'key']:
            if required_key not in sig_info:
                failed.append({'description': desc, 'error': f'Missing key: {required_key}'})
                break
        else:
            # Key should contain the public key we signed with
            key_info = sig_info['key']
            if not isinstance(key_info, dict):
                failed.append({'description': desc, 'error': f'key should be dict, got {type(key_info)}'})
                continue
            if key_info.get('public_key') != sample_key['public_key']:
                failed.append({'description': desc, 'error': f'Public key mismatch'})
    
    return failed


# ============================================================================
# Test 5: JSON round-trip survival
# ============================================================================
# UID: 🍃-27f9df2925043078bcc8
test_cases_json = [
  ('🍃-27f9df2925043078bcc8', 'Signed dict survives JSON round-trip',
   {'document': 'contract', 'value': 1000}, {'signer': 'legal'}),
]


def run_json_roundtrip_tests(test_cases):
    """Test that signed dicts survive JSON serialization/deserialization."""
    failed = []
    
    for uid, desc, data, metadata in test_cases:
        
        signed = msd.sign_and_embed_dict(data, metadata, sample_key)
        
        # Round-trip through JSON
        json_str = json.dumps(signed, ensure_ascii=False)
        restored = json.loads(json_str)
        
        # Verify the restored dict
        try:
            is_valid = msd.verify(restored)
        except Exception as e:
            failed.append({'description': desc, 'error': f'verify after JSON round-trip raised: {e}'})
            continue
        
        if not is_valid:
            failed.append({'description': desc, 'error': 'Verification failed after JSON round-trip'})
            continue
        
        # Metadata should still be extractable
        extracted_meta = msd.extract_metadata(restored)
        if extracted_meta != metadata:
            failed.append({'description': desc, 'error': f'Metadata lost after JSON round-trip'})
    
    return failed


# ============================================================================
# Test 6: Error cases
# ============================================================================
# UIDs: 🍃-a2ebf6f39353a7c4a048, 🍃-a4cdf1e486048283be56, 🍃-9fbe8c073929ba7b7852
test_cases_errors = [
  ('🍃-a2ebf6f39353a7c4a048', 'sign_and_embed_dict rejects non-dict data'),
  ('🍃-a4cdf1e486048283be56', 'sign_and_embed_dict rejects dict with existing __msd key'),
  ('🍃-9fbe8c073929ba7b7852', 'verify raises ValueError on unrecognized input'),
]


def run_error_tests(test_cases):
    """Test error handling for invalid inputs."""
    failed = []
    
    # Test: non-dict data
    try:
        msd.sign_and_embed_dict("not a dict", {}, sample_key)
        failed.append({'description': 'Rejects non-dict data', 'error': 'Should have raised ValueError'})
    except ValueError:
        pass  # expected
    except Exception as e:
        failed.append({'description': 'Rejects non-dict data', 'error': f'Wrong exception type: {type(e).__name__}: {e}'})
    
    # Test: dict with existing __msd key
    try:
        msd.sign_and_embed_dict({'__msd': 'already here'}, {}, sample_key)
        failed.append({'description': 'Rejects existing __msd', 'error': 'Should have raised ValueError'})
    except ValueError:
        pass  # expected
    except Exception as e:
        failed.append({'description': 'Rejects existing __msd', 'error': f'Wrong exception type: {type(e).__name__}: {e}'})
    
    # Test: verify with unrecognized input
    try:
        msd.verify({'random': 'dict', 'no_type': True})
        failed.append({'description': 'Rejects unrecognized input', 'error': 'Should have raised ValueError'})
    except ValueError:
        pass  # expected
    except Exception as e:
        failed.append({'description': 'Rejects unrecognized input', 'error': f'Wrong exception type: {type(e).__name__}: {e}'})
    
    return failed


# ============================================================================
# Run all test groups
# ============================================================================

all_groups = [
    ("Sign & Verify round-trip", run_sign_verify_tests, test_cases_sign_verify),
    ("Tamper detection", run_tamper_tests, test_cases_tamper),
    ("Extract metadata", run_extract_metadata_tests, test_cases_extract_meta),
    ("Extract signature", run_extract_signature_tests, test_cases_extract_sig),
    ("JSON round-trip", run_json_roundtrip_tests, test_cases_json),
    ("Error handling", run_error_tests, test_cases_errors),
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
