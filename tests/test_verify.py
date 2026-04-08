#%%
from zef import *
import msd_sdk as msd


# Test cases for verify() - takes a granule dict and returns True/False
test_cases = [
  ET.UnitTest('🍃-d0b48b579907088f75eb',
    description='Verify valid granule with string data (complete metadata)',
    args=[
      {
        '__type': 'ET.SignedGranule',
        'data': 'hello signable world',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775632796'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-f5802869281af8cb065199f585bcff421e21a8d3421ea3406682ff428c1a7a89bea86b7bb7eeb5'
            'e5d181e43d3c98544ce25aeba15fd08360d681803cef058403'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-a3fe2c45e2b59d0c2220',
          'public_key': '🔑-3b1c90f06a5361b118bb7799e8386ecaacacec706cd7b6e2eade8c1ad32e9c26'
        }
      }
    ],
    expected=True
  ),
  ET.UnitTest('🍃-86639ad287701cc4df6a',
    description='Verify tampered granule (data modified)',
    args=[
      {
        '__type': 'ET.SignedGranule',
        'data': 'TAMPERED DATA',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775632796'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-f5802869281af8cb065199f585bcff421e21a8d3421ea3406682ff428c1a7a89bea86b7bb7eeb5'
            'e5d181e43d3c98544ce25aeba15fd08360d681803cef058403'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-a3fe2c45e2b59d0c2220',
          'public_key': '🔑-3b1c90f06a5361b118bb7799e8386ecaacacec706cd7b6e2eade8c1ad32e9c26'
        }
      }
    ],
    expected=False
  ),
  ET.UnitTest('🍃-feba3f8a03f1e373273a',
    description='Verify tampered granule (metadata modified)',
    args=[
      {
        '__type': 'ET.SignedGranule',
        'data': 'hello signable world',
        'metadata': {'creator': 'Eve'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775632796'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-f5802869281af8cb065199f585bcff421e21a8d3421ea3406682ff428c1a7a89bea86b7bb7eeb5'
            'e5d181e43d3c98544ce25aeba15fd08360d681803cef058403'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-a3fe2c45e2b59d0c2220',
          'public_key': '🔑-3b1c90f06a5361b118bb7799e8386ecaacacec706cd7b6e2eade8c1ad32e9c26'
        }
      }
    ],
    expected=False
  ),
  ET.UnitTest('🍃-f4f3bda5e8c1f6db6301',
    description='Verify valid granule with dict data',
    args=[
      {
        '__type': 'ET.SignedGranule',
        'data': {'message': 'hello', 'count': 42, 'nested': {'a': 1}},
        'metadata': {'author': 'test-suite'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775632796'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-4035792d925fb2d5e5af072be0e7768edf8e6bd781ca41dc389e9a27b858f40a5d4f8436e55569'
            'e0f3cab50f42ddb4233b194c3c4840d1e41cff23d059765106'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-a3fe2c45e2b59d0c2220',
          'public_key': '🔑-3b1c90f06a5361b118bb7799e8386ecaacacec706cd7b6e2eade8c1ad32e9c26'
        }
      }
    ],
    expected=True
  ),
  ET.UnitTest('🍃-e30e177347d120fb5277',
    description='Verify tampered signature (invalid signature bytes)',
    args=[
      {
        '__type': 'ET.SignedGranule',
        'data': 'hello signable world',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775632796'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-000000000000000000000000000000000000000000000000000000000000000000000000000'
            '00000000000000000000000000000000000000000000000000000'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-a3fe2c45e2b59d0c2220',
          'public_key': '🔑-3b1c90f06a5361b118bb7799e8386ecaacacec706cd7b6e2eade8c1ad32e9c26'
        }
      }
    ],
    expected=False
  ),
  ET.UnitTest('🍃-177bafc341f1ffef3a74',
    description='Verify wrong public key',
    args=[
      {
        '__type': 'ET.SignedGranule',
        'data': 'hello signable world',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '1775632796'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-f5802869281af8cb065199f585bcff421e21a8d3421ea3406682ff428c1a7a89bea86b7bb7eeb5'
            'e5d181e43d3c98544ce25aeba15fd08360d681803cef058403'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-a3fe2c45e2b59d0c2220',
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
        '__type': 'ET.SignedGranule',
        'data': 'hello signable world',
        'metadata': {'author': 'test-suite', 'version': '1.0', 'description': 'A test document for signature verification'},
        'signature_time': {'__type': 'Time', 'zef_unix_time': '9999999999'},
        'signature': {
          '__type': 'ET.Ed25519Signature',
          'signature': (
            '🔏-f5802869281af8cb065199f585bcff421e21a8d3421ea3406682ff428c1a7a89bea86b7bb7eeb5'
            'e5d181e43d3c98544ce25aeba15fd08360d681803cef058403'
          )
        },
        'key': {
          '__type': 'ET.Ed25519KeyPair',
          '__uid': '🍃-a3fe2c45e2b59d0c2220',
          'public_key': '🔑-3b1c90f06a5361b118bb7799e8386ecaacacec706cd7b6e2eade8c1ad32e9c26'
        }
      }
    ],
    expected=False
  )
]


#%%
# ============================================================================
# Test Execution - using Python loops since msd functions can't be used in ops
# ============================================================================

def run_tests(test_cases):
    """Run all tests and report results."""
    failed_tests = []
    
    for test in test_cases:
        args = test['args']
        evaluated = msd.verify(*args)
        expected = test['expected']
        
        if expected != evaluated:
            failed_tests.append({
                'description': test['description'],
                'args': args,
                'expected': expected,
                'evaluated': evaluated,
            })
    
    return failed_tests


failed_tests = run_tests(test_cases)

if len(failed_tests) == 0:
    print(f"✅ All {len(test_cases)} tests passed!")
else:
    print(f"❌ {len(failed_tests)} test(s) failed:")
    for test in failed_tests:
        print("\n================================")
        print(f"  - {test['description']}")
        print(f"    Expected: {test['expected']}")
        print(f"    Got: {test['evaluated']}")


#%%
# ============================================================================
# Generation pipeline - uncomment to generate UIDs and expected values
# ============================================================================

# def generate_test_cases_with_expected():
#     """Generate test cases with UIDs and expected values filled in."""
#     updated_cases = []
#     for test in test_cases:
#         # Add UID if missing
#         if not has_uid(test):
#             test = test | set_uid(generate_uid) | collect
        
#         # Calculate expected value
#         args = test['args']
#         expected = msd.verify(*args)
        
#         # Build new UnitTest with expected value
#         test = ET.UnitTest(
#             uid(test),
#             description=test['description'],
#             args=args,
#             expected=expected
#         )
#         updated_cases.append(test)
    
#     # Print for copy-paste back into test_cases
#     print(updated_cases | repr_ | collect)
#     return updated_cases

# # Uncomment to generate:
# generate_test_cases_with_expected() | repr_ | to_clipboard | run
