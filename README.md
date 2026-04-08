# MSD SDK

Python SDK for Meta Structured Data.

📖 **[Read the full SDK overview](docs/overview.md)** for architecture, design decisions, and detailed documentation.

🔑 **[Key Management Guide](docs/key-management.md)** for generating keys, trust hierarchies, and security best practices.

📁 **[Typed Data Guide](docs/typed-data.md)** for working with images, PDFs, and documents.

## Installation

```bash
pip install msd-sdk
```

> **Note**: This SDK requires `zef-core` which is not yet publicly available. The import will fail until zef-core is installed.

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

### 1. Load Key from Environment

The key must be stored as a JSON string in an environment variable:

```python
import msd_sdk as msd

my_key = msd.key_from_env("MSD_PRIVATE_KEY")
```

**Key structure returned:**
```python
{
  '__type': 'ET.Ed25519KeyPair',
  '__uid': '🍃-8d1dc8766070c87a4bb1',
  'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
  'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284'
}
```

### 2. Create a Signed Granule

**Important:**
- `data` can be **any plain data type**: string, dict, list, number, boolean, etc.
- `metadata` must always be a **dictionary**

#### Example 1: String data

```python
data = "Hello, Meta Structured Data!"
metadata = {
    'creator': 'Alice',
    'description': 'sample data',
}

my_granule = msd.create_granule(data, metadata, my_key)
```

**Granule structure returned:**
```python
{
  '__type': 'ET.SignedGranule',
  'data': 'Hello, Meta Structured Data!',
  'metadata': {'creator': 'Alice', 'description': 'sample data'},
  'signature_time': {'__type': 'Time', 'zef_unix_time': '1769253762'},
  'signature': {
    '__type': 'ET.Ed25519Signature',
    'signature': '🔏-9f3a8c29e9784fe63ccc7ebc3e1f394e9dcdf9a7d51bc6fa314dac8a902e9aff6a4e64619bae5a4f674980fcba77877d8a0131e8dfa7976cc23cf1d526ab0c07'
  },
  'key': {
    '__type': 'ET.Ed25519KeyPair',
    '__uid': '🍃-8d1dc8766070c87a4bb1',
    'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284'
  }
}
```

#### Example 2: Dict data (nested structures supported)

```python
data = {"message": "Hello", "count": 42, "nested": {"key": "value"}}
metadata = {'creator': 'Bob', 'schema': 'v1.0'}

my_granule = msd.create_granule(data, metadata, my_key)
```

**Granule structure returned:**
```python
{
  '__type': 'ET.SignedGranule',
  'data': {'message': 'Hello', 'count': 42, 'nested': {'key': 'value'}},
  'metadata': {'creator': 'Bob', 'schema': 'v1.0'},
  'signature_time': {'__type': 'Time', 'zef_unix_time': '1769253762'},
  'signature': {
    '__type': 'ET.Ed25519Signature',
    'signature': '🔏-04ae2907139456ea20a5d0812dfb14ff90abe010113142cbdfd1b8703aea0fc5bd2791249049789983d39f8c63851fb4175fec52993f7ea500931fd7eac32506'
  },
  'key': {
    '__type': 'ET.Ed25519KeyPair',
    '__uid': '🍃-8d1dc8766070c87a4bb1',
    'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284'
  }
}
```

### 3. Verify a Signature

`verify()` checks whether a signature is valid — i.e., whether the data has been tampered with since signing. It works on all three signed data types:

#### Verifying a Granule

```python
granule = msd.create_granule(data, metadata, my_key)

is_valid = msd.verify(granule)  # returns True or False
```

#### Verifying a Signed Dict

```python
signed_dict = msd.sign_and_embed_dict(
    {"message": "Hello", "count": 42},
    {"creator": "Alice"},
    my_key
)

is_valid = msd.verify(signed_dict)  # True

# Tamper with the data — verification fails
signed_dict["count"] = 99
is_valid = msd.verify(signed_dict)  # False
```

#### Verifying a Signed File

```python
import base64

signed_png = msd.sign_and_embed(
    {'__type': 'PngImage', 'data': base64.b64encode(png_bytes).decode()},
    {'author': 'Alice'},
    my_key
)

is_valid = msd.verify(signed_png)  # True
```

This works for all supported file types: PngImage, JpgImage, WebpImage, SvgImage, PDF, WordDocument, ExcelDocument, PowerpointDocument.

#### Behavior

- Returns `True` if the signature is valid for the data
- Returns `False` if the data has been modified since signing
- Raises `ValueError` if the input format is not recognized or has no embedded signature

### 4. Content Hash (without signature)

```python
my_content_hash = msd.content_hash(data)
# Returns: {'__type': 'MsdHash', 'hash': '523d1d9f304a40f30aa741cbdd66cad80f65b9db6c6cba66f2e149e0c2907f29'}
```

**About Merkle Hashing**

`content_hash` uses BLAKE3 Merkle hashing for aggregate data types (Dict, Array/List, Set) and Entity types. This enables:

- **Structural sharing**: Reused sub-structures have the same hash
- **Interoperability with signatures**: Shared data can be verified independently  
- **Specifying aggregates by hashes**: A dict's hash depends on the hashes of its keys and values

The mapping from hash → full value can be maintained via hash stores (dicts/maps), enabling content-addressed storage and deduplication.

### Signing and Embedding in Dicts

You can sign a plain Python dictionary and embed the metadata + signature directly in an `__msd` key using **Unicode steganography** — the signature data is hidden inside invisible Unicode variation selectors attached to a single emoji character. To the naked eye, `__msd` looks like `🔏`, but it carries the full cryptographic payload. This keeps the dict clean and human-readable: the metadata and signature are often much larger than the data itself, and steganography ensures they never clutter the output.

```python
data = {"message": "Hello", "count": 42}
metadata = {"creator": "Alice", "version": "1.0"}

signed_dict = msd.sign_and_embed_dict(data, metadata, my_key)
# => {"message": "Hello", "count": 42, "__msd": "🔏..."}
```

The signed dict can be serialized to JSON, stored in databases, or transmitted over APIs — the steganographic `__msd` value survives JSON round-trips.

#### Extracting Metadata and Signature from Dicts

```python
# Extract just the metadata
metadata = msd.extract_metadata(signed_dict)
# => {"creator": "Alice", "version": "1.0"}

# Extract the full signature information
sig_info = msd.extract_signature(signed_dict)
# => {"signature": {...}, "signature_time": {...}, "key": {...}}
```

Both `extract_metadata` and `extract_signature` automatically detect whether the input is a signed dict (has `__msd` key) or a signed file (has `__type` matching a supported file type) and handle both cases.

#### Verifying a Signed Dict

```python
is_valid = msd.verify(signed_dict)  # True — signature matches data

# If someone tampers with the data, verification fails:
signed_dict["count"] = 999
is_valid = msd.verify(signed_dict)  # False
```

### Embedding Signatures in Images, PDFs and other Documents
- Granules are container data structures which contain data, metadata, and signature alongside each other
- Granules can be saved in `.msd` files and provide an efficient binary format for storage and transmission. But your system and existing programs do not know how to interpret them.
- Sometimes you want to attach metadata and signatures to existing file formats like images (PNG, JPEG), PDFs, audio files, video files and send them to other people or systems.
- For these cases, MSD also provides tools to embed metadata and signatures **into** certain file formats, while keeping the original file content intact and viewable by standard programs.
- Supported formats: 
  - PNG images
  - JPG images
  - PDF documents
  - Word documents (DOCX)
  - Excel spreadsheets (XLSX)
  - PowerPoint presentations (PPTX)

#### ⚠️ Warning ⚠️
- Some programs or platforms may strip out the attached metadata when re-saving or re-exporting the files.
- A MSD signature applies to exactly one fixed content version of a document. Editing the content in the slightest way invalidates the signature

```python
import base64

signed_png_image = msd.sign_and_embed(
  data={'__type': 'PngImage', 'data': base64.b64encode(png_binary_data).decode()},
  metadata={'creator': 'Alice', 'description': 'sample image'},
  key=my_msd_key
)
```

The returned image with the embedded signature is also of the form
```python
{'__type': 'PngImage', 'data': '<base64-encoded signed bytes>'}
```

Supported `__type` values:
- `PngImage`
- `JpgImage`
- `WebpImage`
- `SvgImage`
- `PDF`
- `WordDocument`
- `ExcelDocument`
- `PowerpointDocument`

See the **[Typed Data Guide](docs/typed-data.md)** for details and examples.

#### Extracting and Verifying Embedded Signatures

```python
extracted_metadata = msd.extract_metadata(signed_png_image)
extracted_signature = msd.extract_signature(signed_png_image)
```

```python
# Verify signature
is_valid = msd.verify(signed_png_image)
```


#### Removing Embedded Signatures and Metadata

```python
clean_image = msd.strip_metadata_and_signature(signed_png_image)
```



## Writing Tests

See [docs/writing-tests.md](docs/writing-tests.md) for the test pattern and guide.




## License

Licensed under either of:

- MIT license ([LICENSE](LICENSE) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.


