#%%
"""
Test file for create_granule function.

NOTE: This function is NON-DETERMINISTIC because it uses zef.now() internally.
Each call produces a different signature_time and therefore a different signature.

This means we CANNOT use the standard test pattern with pre-computed expected values.
To properly test this function deterministically, we would need:
- An FX system with deterministic replay capability
- The ability to mock/inject the time value

Current approach: We test the structure and verify the granule passes verification.
"""

from zef import *
import msd_sdk as msd


# Sample key from README.md for testing
sample_key = {
  '__type': 'ET.Ed25519KeyPair',
  '__uid': '🍃-8d1dc8766070c87a4bb1',
  'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
  'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284'
}


# Test cases for create_granule(data, metadata, key)
# Note: create_granule uses zef.now() internally, so we test the granule structure
# and verify it passes verification
test_cases = [
  ET.UnitTest(
    description='Create granule with string data',
    args=['Hello, Meta Structured Data!', {'creator': 'Alice', 'description': 'sample data'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with empty string',
    args=['', {'creator': 'Test'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with integer data',
    args=[42, {'type': 'number'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with float data',
    args=[3.14159, {'type': 'pi'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with boolean True',
    args=[True, {'type': 'boolean'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with boolean False',
    args=[False, {'type': 'boolean'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with None/nil',
    args=[nil, {'type': 'null'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with simple dict data',
    args=[{'message': 'Hello'}, {'creator': 'Bob'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with nested dict data',
    args=[{'outer': {'inner': 'value', 'count': 42}}, {'schema': 'v1'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with list data',
    args=[[1, 2, 3], {'type': 'array'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with mixed list',
    args=[[1, 'two', 3.0, True, nil], {'type': 'mixed'}, sample_key],
  ),
  ET.UnitTest(
    description='Create granule with empty metadata',
    args=['data', {}, sample_key],
  ),
]


#%%
# ============================================================================
# Test Execution - using Python loops since msd functions can't be used in ops
# For create_granule we test:
# 1. The granule has the correct structure
# 2. The data and metadata match input
# 3. The granule passes verification
# ============================================================================

def run_tests(test_cases):
    """Run all tests and report results."""
    failed_tests = []
    
    for test in test_cases:
        args = test['args']
        data, metadata, key = args
        
        granule = msd.create_granule(data, metadata, key)
        
        # Check structure
        required_keys = {'__type', 'data', 'metadata', 'signature_time', 'signature', 'key'}
        actual_keys = set(granule.keys())
        if not required_keys.issubset(actual_keys):
            failed_tests.append({
                'description': test['description'],
                'error': f'Missing keys: {required_keys - actual_keys}',
            })
            continue
        
        # Check __type
        if granule['__type'] != 'ET.SignedGranule':
            failed_tests.append({
                'description': test['description'],
                'error': f'Wrong __type: {granule["__type"]}',
            })
            continue
        
        # Check data matches input
        # Normalize nil → None since SDK returns native Python types
        expected_data = None if data == nil else data
        if granule['data'] != expected_data:
            failed_tests.append({
                'description': test['description'],
                'error': f'Data mismatch: expected {data}, got {granule["data"]}',
            })
            continue
        
        # Check metadata matches input
        if granule['metadata'] != metadata:
            failed_tests.append({
                'description': test['description'],
                'error': f'Metadata mismatch: expected {metadata}, got {granule["metadata"]}',
            })
            continue
        
        # Check it verifies correctly
        is_valid = msd.verify(granule)
        if not is_valid:
            failed_tests.append({
                'description': test['description'],
                'error': 'Granule failed verification',
            })
            continue
    
    return failed_tests


failed_tests = run_tests(test_cases)

if len(failed_tests) == 0:
    print(f"✅ All {len(test_cases)} tests passed!")
else:
    print(f"❌ {len(failed_tests)} test(s) failed:")
    for test in failed_tests:
        print("\n================================")
        print(f"  - {test['description']}")
        print(f"    Error: {test['error']}")
