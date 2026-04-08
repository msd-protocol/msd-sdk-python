# Changelog

All notable changes to the MSD SDK are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Breaking Changes

- **`content_hash()` now returns a dict instead of a plain hex string.**

  Before (0.1.7):
  ```python
  msd.content_hash("hello")
  # '928d2f9f582b4423e27990762d3ce78ab9106a1aa7001f998b0378a941850f38'
  ```

  After:
  ```python
  msd.content_hash("hello")
  # {'__type': 'MsdHash', 'hash': '928d2f9f582b4423e27990762d3ce78ab9106a1aa7001f998b0378a941850f38'}
  ```

  **Migration:** Replace `msd.content_hash(x)` with `msd.content_hash(x)['hash']` where a plain hex string is needed.

- **File data now uses typed dicts with `__type` instead of `{'type': ..., 'content': bytes}`.**

  Before (0.1.7):
  ```python
  msd.sign_and_embed({'type': 'png', 'content': png_bytes}, metadata, key)
  # returned: {'type': 'png', 'content': signed_bytes}
  ```

  After:
  ```python
  import base64
  msd.sign_and_embed({'__type': 'PngImage', 'data': base64.b64encode(png_bytes).decode()}, metadata, key)
  # returns: {'__type': 'PngImage', 'data': '<base64>'}
  ```

  All file functions (`sign_and_embed`, `verify`, `extract_metadata`, `extract_signature`, `strip_metadata_and_signature`, `content_hash`, `create_granule`) now use the typed dict format. Supported types: `PngImage`, `JpgImage`, `WebpImage`, `SvgImage`, `PDF`, `WordDocument`, `ExcelDocument`, `PowerpointDocument`.

  See [docs/typed-data.md](docs/typed-data.md) for the full guide.

---

## [0.1.7] — 2026-02-19

Initial published version.

- `create_granule` — sign data + metadata into a granule
- `verify` — verify granules, signed dicts, and signed files
- `content_hash` — BLAKE3 Merkle hash (returned plain hex string)
- `sign_and_embed_dict` — sign a dict with Unicode steganography
- `sign_and_embed` — embed signature in PNG/JPG/PDF/DOCX/XLSX/PPTX
- `extract_metadata` / `extract_signature` — read embedded data
- `strip_metadata_and_signature` — recover original file content
- `generate_key_pair` / `save_key` / `load_key` / `key_from_env` — key management
