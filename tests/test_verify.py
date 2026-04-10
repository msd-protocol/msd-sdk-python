#%%
from zef import *
import msd_sdk as msd


# Test cases for verify() - takes a signed data dict and returns a rich dict
# All hardcoded test data uses ET.SignedData (not ET.SignedGranule)
test_cases = [
  ET.UnitTest('🍃-d0b48b579907088f75eb',
    description='Verify valid signed data with string data (complete metadata)',
    args=[
      {
        '__type': 'ET.SignedData',
        'data': 'hello signable world',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775708365'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-ab36b3ddecac1278322795f255a6a3d2f5ba5b58894c7ab4c6f1dc0df0ea2bd9'
            '67415c5ccda7913a636438cc6fb7d78d6e6c20d74ca7ac1301e3856ab077e507'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-ab3a364813a652eb45f9',
          'public_key': '🔑-c824bfc53647a6eb2aceca5eecf5cb96bf039983758a3e04c9f0891645cc6862'
        }
      }
    ],
    expected=True
  ),
  ET.UnitTest('🍃-86639ad287701cc4df6a',
    description='Verify tampered data (data modified)',
    args=[
      {
        '__type': 'ET.SignedData',
        'data': 'TAMPERED DATA',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775708365'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-ab36b3ddecac1278322795f255a6a3d2f5ba5b58894c7ab4c6f1dc0df0ea2bd9'
            '67415c5ccda7913a636438cc6fb7d78d6e6c20d74ca7ac1301e3856ab077e507'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-ab3a364813a652eb45f9',
          'public_key': '🔑-c824bfc53647a6eb2aceca5eecf5cb96bf039983758a3e04c9f0891645cc6862'
        }
      }
    ],
    expected=False
  ),
  ET.UnitTest('🍃-feba3f8a03f1e373273a',
    description='Verify tampered metadata',
    args=[
      {
        '__type': 'ET.SignedData',
        'data': 'hello signable world',
        'metadata': {'creator': 'Eve'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775708365'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-ab36b3ddecac1278322795f255a6a3d2f5ba5b58894c7ab4c6f1dc0df0ea2bd9'
            '67415c5ccda7913a636438cc6fb7d78d6e6c20d74ca7ac1301e3856ab077e507'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-ab3a364813a652eb45f9',
          'public_key': '🔑-c824bfc53647a6eb2aceca5eecf5cb96bf039983758a3e04c9f0891645cc6862'
        }
      }
    ],
    expected=False
  ),
  ET.UnitTest('🍃-f4f3bda5e8c1f6db6301',
    description='Verify valid signed data with dict data',
    args=[
      {
        '__type': 'ET.SignedData',
        'data': {'message': 'hello', 'count': 42, 'nested': {'a': 1}},
        'metadata': {'author': 'test-suite'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775708365'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-2e7fd8c339cfa68944ff9a8001813f6889c223df157f73dfdd96d434aff587ed'
            '1a47c8dd0fe48c93d45659f2f7af59e53c0ca31f96483ef7656c822a6434000f'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-ab3a364813a652eb45f9',
          'public_key': '🔑-c824bfc53647a6eb2aceca5eecf5cb96bf039983758a3e04c9f0891645cc6862'
        }
      }
    ],
    expected=True
  ),
  ET.UnitTest('🍃-e30e177347d120fb5277',
    description='Verify tampered signature (invalid signature bytes)',
    args=[
      {
        '__type': 'ET.SignedData',
        'data': 'hello signable world',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775708365'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-000000000000000000000000000000000000000000000000000000000000000000000000000'
            '00000000000000000000000000000000000000000000000000000'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-ab3a364813a652eb45f9',
          'public_key': '🔑-c824bfc53647a6eb2aceca5eecf5cb96bf039983758a3e04c9f0891645cc6862'
        }
      }
    ],
    expected=False
  ),
  ET.UnitTest('🍃-177bafc341f1ffef3a74',
    description='Verify wrong public key',
    args=[
      {
        '__type': 'ET.SignedData',
        'data': 'hello signable world',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775708365'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-ab36b3ddecac1278322795f255a6a3d2f5ba5b58894c7ab4c6f1dc0df0ea2bd9'
            '67415c5ccda7913a636438cc6fb7d78d6e6c20d74ca7ac1301e3856ab077e507'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-ab3a364813a652eb45f9',
          'public_key': '🔑-0000000000000000000000000000000000000000000000000000000000000000'
        }
      }
    ],
    expected=False
  ),
  ET.UnitTest('🍃-aefb998b6c9a6dfeb8d7',
    description='Verify tampered timestamp',
    args=[
      {
        '__type': 'ET.SignedData',
        'data': 'hello signable world',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '9999999999'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-ab36b3ddecac1278322795f255a6a3d2f5ba5b58894c7ab4c6f1dc0df0ea2bd9'
            '67415c5ccda7913a636438cc6fb7d78d6e6c20d74ca7ac1301e3856ab077e507'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-ab3a364813a652eb45f9',
          'public_key': '🔑-c824bfc53647a6eb2aceca5eecf5cb96bf039983758a3e04c9f0891645cc6862'
        }
      }
    ],
    expected=False
  )
]


#%%
# ============================================================================
# Test Execution
# ============================================================================

def run_tests(test_cases):
    """Run all tests and report results."""
    failed_tests = []
    
    for test in test_cases:
        args = test['args']
        result = msd.verify(*args)
        expected = test['expected']
        
        # Result must be a dict
        if not isinstance(result, dict):
            failed_tests.append({
                'description': test['description'],
                'expected': expected,
                'error': f'Expected dict, got {type(result).__name__}',
            })
            continue
        
        # Must have signature_is_valid key
        if 'signature_is_valid' not in result:
            failed_tests.append({
                'description': test['description'],
                'expected': expected,
                'error': 'Missing signature_is_valid key',
            })
            continue
        
        evaluated = result['signature_is_valid']
        if expected != evaluated:
            failed_tests.append({
                'description': test['description'],
                'expected': expected,
                'evaluated': evaluated,
            })
            continue
        
        # Check structure of result dict
        required_keys = {
            'is_verified_and_trusted', 'signature_is_valid', 'signature_is_trusted',
            'data_hash', 'metadata_hash', 'signature_timestamp', 'signing_key',
            'signing_key_trust_chain', 'trust_chain_breaches'
        }
        missing = required_keys - set(result.keys())
        if missing:
            failed_tests.append({
                'description': test['description'],
                'error': f'Missing keys in result: {missing}',
            })
            continue
        
        # is_verified_and_trusted must match: ✅ only when valid AND trusted
        expected_emoji = '✅' if (expected and result.get('signature_is_trusted', False)) else '❌'
        if result['is_verified_and_trusted'] != expected_emoji:
            failed_tests.append({
                'description': test['description'],
                'error': f'is_verified_and_trusted should be {expected_emoji!r}, got {result["is_verified_and_trusted"]!r}',
            })
            continue
        
        # Trust fields must be hardcoded values
        if result['signature_is_trusted'] is not False:
            failed_tests.append({
                'description': test['description'],
                'error': f'signature_is_trusted should be False, got {result["signature_is_trusted"]}',
            })
        if result['signing_key_trust_chain'] != []:
            failed_tests.append({
                'description': test['description'],
                'error': f'signing_key_trust_chain should be [], got {result["signing_key_trust_chain"]}',
            })
        if result['trust_chain_breaches'] != []:
            failed_tests.append({
                'description': test['description'],
                'error': f'trust_chain_breaches should be [], got {result["trust_chain_breaches"]}',
            })
    
    return failed_tests


# Also test that ET.SignedGranule is rejected
def run_reject_test():
    """Test that verify() rejects ET.SignedGranule with a clear error."""
    try:
        msd.verify({
            '__type': 'ET.SignedGranule',
            'data': 'test',
            'metadata': {},
        })
        return [{'description': 'Reject ET.SignedGranule', 'error': 'Should have raised ValueError'}]
    except ValueError as e:
        if 'ET.SignedGranule' in str(e) and 'no longer supported' in str(e):
            return []  # expected
        return [{'description': 'Reject ET.SignedGranule', 'error': f'Wrong error message: {e}'}]
    except Exception as e:
        return [{'description': 'Reject ET.SignedGranule', 'error': f'Wrong exception: {type(e).__name__}: {e}'}]


#%%
failed = run_tests(test_cases)
reject_failed = run_reject_test()
all_failed = failed + reject_failed
total = len(test_cases) + 1  # +1 for reject test
passed = total - len(all_failed)

if all_failed:
    print(f"❌ {len(all_failed)}/{total} tests failed:")
    for f in all_failed:
        desc = f.get('description', '?')
        err = f.get('error', f'expected {f.get("expected")}, got {f.get("evaluated")}')
        print(f"  - {desc}: {err}")
else:
    print(f"✅ All {total} tests passed!")

print(f"\n{'✅' if not all_failed else '❌'} All {total} tests: {passed} passed, {len(all_failed)} failed")
