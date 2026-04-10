"""Tests for compact key encoding/decoding."""

import pytest
from msd_sdk._compact_key import encode_compact_key, decode_compact_key


# Known test vector — matches cross-language TS test output
TEST_KEY = {
    '__type': 'ET.Ed25519KeyPair',
    '__uid': '🍃-8d1dc8766070c87a4bb1',
    'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
    'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284',
}

KNOWN_COMPACT = 'msd-key-8d1dc8766070c87a4bb1-hhTRALPNtf9sN8hGdg3RmQ9jeZS9mF2UhvISEzv9YoRhJQr2v4uTMr5cK4pId8VhiYZ8iEDM5UGrf76ScLubbLNasw'


class TestRoundtrip:
    def test_encode_produces_known_output(self):
        assert encode_compact_key(TEST_KEY) == KNOWN_COMPACT

    def test_decode_produces_known_key(self):
        result = decode_compact_key(KNOWN_COMPACT)
        assert result['__type'] == TEST_KEY['__type']
        assert result['__uid'] == TEST_KEY['__uid']
        assert result['public_key'] == TEST_KEY['public_key']
        assert result['private_key'] == TEST_KEY['private_key']

    def test_roundtrip_encode_decode(self):
        compact = encode_compact_key(TEST_KEY)
        decoded = decode_compact_key(compact)
        assert decoded == TEST_KEY

    def test_roundtrip_with_different_key(self):
        key = {
            '__type': 'ET.Ed25519KeyPair',
            '__uid': '🍃-0000000000ffffffffff',
            'private_key': '🗝️-' + 'ab' * 32,
            'public_key': '🔑-' + 'cd' * 32,
        }
        compact = encode_compact_key(key)
        assert compact.startswith('msd-key-0000000000ffffffffff-')
        decoded = decode_compact_key(compact)
        assert decoded == key


class TestFormat:
    def test_length_is_119(self):
        assert len(encode_compact_key(TEST_KEY)) == 119

    def test_starts_with_prefix(self):
        assert encode_compact_key(TEST_KEY).startswith('msd-key-')

    def test_uid_visible_in_string(self):
        compact = encode_compact_key(TEST_KEY)
        assert '8d1dc8766070c87a4bb1' in compact

    def test_pure_ascii(self):
        compact = encode_compact_key(TEST_KEY)
        assert compact.isascii()

    def test_no_whitespace(self):
        compact = encode_compact_key(TEST_KEY)
        assert ' ' not in compact
        assert '\n' not in compact


class TestDecodeErrors:
    def test_wrong_prefix(self):
        with pytest.raises(ValueError, match="Invalid compact key format"):
            decode_compact_key('bad-key-8d1dc8766070c87a4bb1-AAAA')

    def test_missing_prefix(self):
        with pytest.raises(ValueError, match="Invalid compact key format"):
            decode_compact_key('8d1dc8766070c87a4bb1-AAAA')

    def test_short_uid(self):
        with pytest.raises(ValueError, match="Invalid compact key format"):
            decode_compact_key('msd-key-8d1dc876-AAAA')

    def test_bad_checksum(self):
        # Flip one character in the base64 payload
        corrupted = KNOWN_COMPACT[:-1] + ('A' if KNOWN_COMPACT[-1] != 'A' else 'B')
        with pytest.raises(ValueError, match="Checksum mismatch"):
            decode_compact_key(corrupted)

    def test_truncated_payload(self):
        # Truncate the base64 payload to make it too short
        parts = KNOWN_COMPACT.split('-', 3)
        parts[3] = parts[3][:10]
        truncated = '-'.join(parts)
        with pytest.raises(ValueError, match="Expected 67-byte payload"):
            decode_compact_key(truncated)

    def test_strips_whitespace(self):
        result = decode_compact_key(f'  {KNOWN_COMPACT}  \n')
        assert result == TEST_KEY
