#%%
from zef import *
import msd_sdk as msd


# Test data for content_hash - following declarative test pattern
# UIDs and expected values will be filled in automatically
test_cases = [
  ET.UnitTest('🍃-954c268be37c6d28bea1',
    description='Hash a simple string',
    args=['Hello, Meta Structured Data!'],
    expected='523d1d9f304a40f30aa741cbdd66cad80f65b9db6c6cba66f2e149e0c2907f29'
  ),
  ET.UnitTest('🍃-7fc83d7e65977233182c',
    description='Hash an empty string',
    args=[''],
    expected='928d2f9f582b4423e27990762d3ce78ab9106a1aa7001f998b0378a941850f38'
  ),
  ET.UnitTest('🍃-af54b232d86e1cb30d54',
    description='Hash an integer',
    args=[42],
    expected='b80d336df28a0d02f8301151f8a3b04fd44e0752cccf15ec92547bd814a7e627'
  ),
  ET.UnitTest('🍃-170f056baf8e7881528f',
    description='Hash a float',
    args=[3.14159],
    expected='cab1a4466c089183744562c8ffc9311c982bfb1d50cb0a67d1478f4ab70d8a5a'
  ),
  ET.UnitTest('🍃-2eb390db04bf52c61b6c',
    description='Hash a boolean True',
    args=[True],
    expected='16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720'
  ),
  ET.UnitTest('🍃-bcf454714385dd0b8652',
    description='Hash a boolean False',
    args=[False],
    expected='768c1694acfd4d0c29e174ac43d7e91ff36d412439c3c872eaba6a8d80accf33'
  ),
  ET.UnitTest('🍃-014c8cba4838e979ce0c',
    description='Hash None',
    args=[nil],
    expected='97ef5c3b3452890d7657a3743094f7a11a2074d9887d166f3e740b56e07c23e9'
  ),
  ET.UnitTest('🍃-ebff94bff303ba9422dc',
    description='Hash a simple dict',
    args=[{'key': 'value'}],
    expected='ff824e137450fdbcaa175421fc3907f8634091a2351dd8fa5c20e3ae2f50b339'
  ),
  ET.UnitTest('🍃-9999a5c6f6dc70c4293a',
    description='Hash a nested dict',
    args=[{'outer': {'inner': 'value', 'count': 42}}],
    expected='69b37c316b98cf9e952e983ba33aecff9ec834358377afbba7edd0fd8c28c381'
  ),
  ET.UnitTest('🍃-d3d31f59d4cdc416268a',
    description='Hash a simple list',
    args=[[1, 2, 3]],
    expected='1afe5a19db3df5991fdca782768351bb1618179e10b9d6ddfd92a449d3925599'
  ),
  ET.UnitTest('🍃-5c74a3aaac1981703687',
    description='Hash a mixed list',
    args=[[1, 'two', 3.0, True, nil]],
    expected='ff0624d4132f833dcd93c93062320dcfec6fe32f8ac9f5bcc44b4ac18a789357'
  ),
  ET.UnitTest('🍃-c8b9c6d6f29e9a388e31',
    description='Hash an empty dict',
    args=[{}],
    expected='0400000000000000000000000000000000000000000000000000000000000000'
  ),
  ET.UnitTest('🍃-1226b2afaccfd5e58223',
    description='Hash an empty list',
    args=[[]],
    expected='0200000000000000000000000000000000000000000000000000000000000000'
  )
]

# ============================================================================
# Test Execution - using Python loops since msd functions can't be used in ops
# ============================================================================

def run_tests(test_cases):
    """Run all tests and report results."""
    failed_tests = []
    
    for test in test_cases:
        # Get the args and unpack them to call msd.content_hash
        args = test['args']
        evaluated = msd.content_hash(*args)
        
        # content_hash returns {'__type': 'MsdHash', 'hash': '<hex>'}
        expected = test['expected']
        matches = (evaluated['__type'] == 'MsdHash' and evaluated['hash'] == expected)
        if not matches:
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
        print(f"    Args: {test['args']}")
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
#         # Create a copy with UID if missing
#         if not has_uid(test):
#             test = test | set_uid(generate_uid) | collect
        
#         # Calculate expected value if missing
#         if 'expected' not in test:
#             args = test['args']
#             expected = msd.content_hash(*args)
#             print(test)
#             print(expected)
#             test = test | insert({'expected': expected}) | collect
        
#         updated_cases.append(test)
    
#     # Print as repr for copy-paste
#     result = updated_cases | repr_ | collect
#     print(result)
#     return updated_cases

# generate_test_cases_with_expected() | repr_ | to_clipboard | run


