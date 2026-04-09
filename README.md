# MSD SDK

Python SDK for Meta Structured Data.

📖 **[Read the full SDK overview](docs/overview.md)** for architecture, design decisions, and detailed documentation.

🔑 **[Key Management Guide](docs/key-management.md)** for generating keys, trust hierarchies, and security best practices.

📁 **[Typed Data Guide](docs/typed-data.md)** for working with images, PDFs, and documents.

## Installation

```bash
pip install msd-sdk
```

This installs `msd-sdk` and its runtime dependency `zef` (a compiled Rust library) from PyPI.

### What is zef?

`zef` is a compiled (Rust) runtime library that provides the cryptographic primitives and data structures used by the MSD SDK.

## Development: Building from Source

When developing locally, you must build and install from the local wheel to avoid pip installing the (older) PyPI version.

```bash
# 1. Build the wheel
uv build

# 2. Install from local dist (not from PyPI!)
#    Use --no-index to prevent PyPI fallback
python -m pip install --no-index --find-links=./dist msd-sdk

# Or with explicit path to avoid version conflicts:
python -m pip install ./dist/msd_sdk-*.whl --force-reinstall
```

**Common Pitfall**: Running `pip install .` may reinstall the published PyPI version if it has the same version number. Always use `--no-index` or install the wheel directly when developing.

## Development Setup with Zef

Since `msd-sdk` requires `zef` (which must be installed from source), you need to install msd-sdk into the same virtual environment where zef is installed:

```bash
# 1. Activate the venv where zef is already installed
source /path/to/zef/dev_venv/bin/activate

# 2. Install msd-sdk in editable mode from your local clone
pip install -e /path/to/msd-sdk-python

# 3. Verify both are available
python -c "import zef; import msd_sdk; print('✓ Both packages installed')"
```

## Running the Examples

The `examples/` folder contains working examples with sample files:

```bash
# Make sure you're in the venv with both zef and msd-sdk installed
source /path/to/zef/dev_venv/bin/activate

# Run the examples
python examples/sign_and_embed_example.py
```

The example demonstrates:
- Loading PNG, JPG, PDF, DOCX, XLSX, PPTX files
- Signing and embedding metadata
- Saving signed files to disk
- Extracting metadata from signed files
- Stripping metadata to recover original content

See [examples/README.md](examples/README.md) for more details.

## Usage

MSD lets you sign data in two ways:

- **As signed structures** — `sign()` creates a self-contained cryptographic envelope. Integrate into APIs, databases, and pipelines for systematic provenance tracking.
- **Embedded in files** — `embed()` folds the signature into the data itself: PDFs, Word docs, spreadsheets, images, JSON dicts. The data looks the same — the proof is inside.

Both produce data that `verify()` can check. The choice depends on where the data goes.

### 1. Keys — Valid vs. Trusted

A signature is only as trustworthy as the key behind it. Anyone can generate a key pair locally — and the SDK will happily sign with it. But a valid signature from an unknown key tells a verifier nothing about *who* signed the data.

For production use, **generate your keys in [MSD Explorer](https://network.msd-protocol.org/dashboard)**. Keys generated there are:

- **Linked to your identity** — verifiers can see who signed the data
- **Endorsed by the platform** — a trust chain from the MSD root to your key
- **Discoverable** — others can find your public key and add you to their trust network

This is the difference between `signature_is_valid` and `signature_is_trusted` in the verify result. Cryptographic validity is table stakes. Trust requires identity.

> For testing and development, `msd.generate_key_pair(unendorsed=True)` creates a local key that works for signing but can't be trusted by anyone outside your machine.

#### Loading a Key from Environment

```python
import msd_sdk as msd

my_key = msd.key_from_env("MSD_PRIVATE_KEY")
```

See the [Key Management Guide](docs/key-management.md) for storage best practices and the two-tier key model.

### 2. Sign Data

`sign()` creates a signed data envelope — data + metadata + timestamp + Ed25519 signature.

- `data` can be **any plain data type**: string, dict, list, number, boolean, or a typed file dict
- `metadata` must always be a **dictionary**

```python
signed = msd.sign(
    data="Hello, Meta Structured Data!",
    metadata={'creator': 'Alice', 'description': 'sample data'},
    key=my_key
)
```

**Signed data structure returned:**
```python
{
  '__type': 'ET.SignedData',
  'data': 'Hello, Meta Structured Data!',
  'metadata': {'creator': 'Alice', 'description': 'sample data'},
  'signature_time': {'__type': 'Time', 'zef_unix_time': '1775708365'},
  'signature': {
    '__type': 'ET.Ed25519Signature',
    'signature': '🔏-ab36b3ddecac1278...'
  },
  'key': {
    '__type': 'ET.Ed25519KeyPair',
    '__uid': '🍃-ab3a364813a652eb45f9',
    'public_key': '🔑-c824bfc53647a6eb2aceca5eecf5cb96bf039983758a3e04c9f0891645cc6862'
  }
}
```

Dict data works the same way:

```python
signed = msd.sign(
    data={"message": "Hello", "count": 42, "nested": {"key": "value"}},
    metadata={'creator': 'Bob', 'schema': 'v1.0'},
    key=my_key
)
```

### 3. Embed Signatures

`embed()` takes signed data and embeds the signature into the data itself — either via Unicode steganography (dicts) or binary embedding (files).

#### Embedding in Dicts

The signature is hidden in an `__msd` key using **Unicode steganography** — invisible variation selectors carry the full cryptographic payload inside a single `🔏` emoji. The dict stays clean and human-readable.

```python
signed = msd.sign(
    data={"message": "Hello", "count": 42},
    metadata={"creator": "Alice", "version": "1.0"},
    key=my_key
)
embedded = msd.embed(signed)
# => {"message": "Hello", "count": 42, "__msd": "🔏..."}
```

The embedded dict survives JSON round-trips and can be stored in databases or transmitted over APIs.

#### Embedding in Files

For typed file data (images, PDFs, etc.), `embed()` embeds the signature directly into the file's binary format:

```python
import base64

signed = msd.sign(
    data={'__type': 'PngImage', 'data': base64.b64encode(png_bytes).decode()},
    metadata={'author': 'Alice', 'description': 'sample image'},
    key=my_key
)
embedded = msd.embed(signed)
# => {'__type': 'PngImage', 'data': '<base64 with embedded signature>'}
```

Supported `__type` values: `PngImage`, `JpgImage`, `WebpImage`, `SvgImage`, `PDF`, `WordDocument`, `ExcelDocument`, `PowerpointDocument`.

See the **[Typed Data Guide](docs/typed-data.md)** for details.

### 4. Verify a Signature

`verify()` checks whether a signature is valid. It returns a **rich result dict** with detailed information:

```python
result = msd.verify(signed)
result['signature_is_valid']  # True or False
```

**Result dict structure:**
```python
{
  'signature_is_valid': True,       # core validity check
  'signature_is_trusted': False,    # trust chain (not yet implemented)
  'data_hash': {...},               # BLAKE3 hash of the data
  'metadata_hash': {...},           # BLAKE3 hash of the metadata
  'signature_timestamp': {...},     # when the signature was created
  'signing_key': {...},             # public key used for signing
  'signing_key_trust_chain': [],    # trust chain (not yet implemented)
  'trust_chain_breaches': [],       # trust chain (not yet implemented)
}
```

`verify()` works on all signed data types: `ET.SignedData`, dicts with `__msd` key, and typed file dicts with embedded signatures.

```python
# Verify signed data directly
result = msd.verify(signed)

# Verify embedded dict
result = msd.verify(embedded_dict)

# Verify signed file
result = msd.verify(signed_png)

# Tamper detection
embedded_dict["count"] = 999
result = msd.verify(embedded_dict)
result['signature_is_valid']  # False
```

- Raises `ValueError` if the input format is not recognized or has no embedded signature

#### Extracting Metadata and Signature

```python
metadata = msd.extract_metadata(signed_data)
sig_info = msd.extract_signature(signed_data)
```

Both work on dicts with `__msd` and typed file dicts with embedded signatures.

#### Removing Embedded Signatures

```python
clean_image = msd.strip_metadata_and_signature(signed_png)
```

### 5. Content Hash (without signature)

```python
my_content_hash = msd.content_hash(data)
# Returns: {'__type': 'MsdHash', 'hash': '523d1d9f304a40f30aa741cbdd66cad80f65b9db6c6cba66f2e149e0c2907f29'}
```

`content_hash` uses BLAKE3 Merkle hashing for aggregate data types. This enables structural sharing, content-addressed storage, and deduplication.



## Writing Tests

See [docs/writing-tests.md](docs/writing-tests.md) for the test pattern and guide.




## License

Licensed under either of:

- MIT license ([LICENSE](LICENSE) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.


