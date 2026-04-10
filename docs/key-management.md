# 🔑 Key Management Guide

A practical guide to generating, managing, and using cryptographic keys in the MSD SDK.

---

## Valid vs. Trusted — Why Key Generation Matters

A signature proves the data hasn't been tampered with. But it doesn't tell you *who signed it*. A valid signature from an unknown key is like a handwritten signature from a stranger — mathematically correct, but not meaningful.

This is the distinction between `signature_is_valid` and `signature_is_trusted` in the verify result:

| | `signature_is_valid` | `signature_is_trusted` |
|---|---|---|
| **What it checks** | Ed25519 math + BLAKE3 hashes | Identity behind the key |
| **Requires network** | No | Depends on trust config |
| **Local key** | ✓ | ✗ (key is unknown to others) |
| **Platform key** | ✓ | ✓ (key is endorsed and discoverable) |

**For anything others will verify, generate your keys in [MSD Explorer](https://network.msd-protocol.org/dashboard).** Keys generated there are endorsed by the platform and linked to your identity — so verifiers can see who signed the data and decide whether to trust it.

`generate_key_pair(unendorsed=True)` is for testing and local development only.

---

## Key Types: Two-Tier Model

MSD uses a **two-tier key model** that mirrors real-world trust relationships:

| Tier | Key Type | Expires? | Protection | Use Case |
|------|----------|----------|------------|----------|
| **1** | Identity Key | Never | High (password manager, HSM) | Long-term identity, root of trust |
| **2** | Working Key | Yes (hours-days) | Standard | Day-to-day signing, automation |

```mermaid
graph TD
    Root[🏛️ MSD Platform Root] -->|endorses| I1[👤 Alice Identity Key]
    Root -->|endorses| I2[🏢 Acme Corp Key]
    I1 -->|endorses| W1[⚙️ CI Pipeline Key<br/>expires: 24h]
    I1 -->|endorses| W2[📝 Document Signing Key<br/>expires: 7d]
    I2 -->|endorses| W3[🤖 API Service Key<br/>expires: 1h]
    
    style Root fill:#1a1a2e,stroke:#4a4a6a,color:#e0e0e0
    style I1 fill:#16213e,stroke:#4a4a6a,color:#e0e0e0
    style I2 fill:#16213e,stroke:#4a4a6a,color:#e0e0e0
    style W1 fill:#0f3460,stroke:#4a4a6a,color:#e0e0e0
    style W2 fill:#0f3460,stroke:#4a4a6a,color:#e0e0e0
    style W3 fill:#0f3460,stroke:#4a4a6a,color:#e0e0e0
```

---

## Key Structure

A key is **plain data** represented as a Python dictionary. Keys have **no internal labels** — naming is external (the relationship between your namespace and the key value).

### Key UIDs

Every key has a unique identifier of the form `🍃-8d1dc8766070c87a4bb1`. This UID is:
- **Shorter** than the full public key (20 chars vs 64 chars)
- **Globally unique** — can be used to reference keys in logs, configs, and trust chains
- **Immutable** — assigned at key creation, never changes

Use UIDs when:
- Displaying keys in UIs or logs (more readable)
- Referencing keys in configuration files
- Trust chain displays (compact representation)

Use full public keys when:
- Cryptographic verification is required
- Interoperating with external systems
- Storing trust anchors

### Basic Key (Local Only)

```python
{
    '__type': 'ET.Ed25519KeyPair',
    '__uid': '🍃-8d1dc8766070c87a4bb1',
    'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
    'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284'
}
```

### Platform-Endorsed Key (With Certificate)

When registered with the MSD platform, the key includes a certificate:

```python
{
    '__type': 'ET.Ed25519KeyPair',
    '__uid': '🍃-8d1dc8766070c87a4bb1',
    'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
    'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284',
    'platform_certificate': {
        '__type': 'ET.PlatformCertificate',
        'endorsed_public_key': '🔑-c914d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd8155',
        'platform_signature': '🔏-3a7f9c2e1d4b8a6f5c0e9d8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f',
        'issued_at': {'__type': 'Time', 'zef_unix_time': '1737849600'},
        'expires_at': {'__type': 'Time', 'zef_unix_time': '1769385600'}
    }
}
```

### Endorsed Working Key

Working keys are endorsed by an identity key and include expiry:

```python
{
    '__type': 'ET.Ed25519KeyPair',
    '__uid': '🍃-a2b3c4d5e6f78901bcde',
    'private_key': '🗝️-f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7',
    'public_key': '🔑-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    'endorsement': {
        '__type': 'ET.KeyEndorsement',
        'endorsed_by': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284',
        'endorsement_signature': '🔏-9f3a8c29e9784fe63ccc7ebc3e1f394e9dcdf9a7d51bc6fa314dac8a902e9aff6a4e64619bae5a4f674980fcba77877d8a0131e8dfa7976cc23cf1d526ab0c07',
        'issued_at': {'__type': 'Time', 'zef_unix_time': '1737849600'},
        'expires_at': {'__type': 'Time', 'zef_unix_time': '1737936000'}
    }
}
```

---

## Quick Start

### Recommended: Generate Keys in MSD Explorer

The easiest way to create a properly endorsed key is through [MSD Explorer](https://network.msd-protocol.org/dashboard):

1. Create an account (links your identity to your keys)
2. Generate a key pair (endorsed by the platform automatically)
3. Export the private key and store it securely

The key you get is already part of the trust network — anyone who verifies data signed with it can trace the key back to your identity.

### Programmatic Key Generation

For CI/CD pipelines and automation, you can generate keys in code:

```python
import msd_sdk as msd

# Generate and register with MSD platform (recommended)
identity_key = msd.generate_key_pair()

# The key is a plain dict - you manage naming externally
print(identity_key)
# {
#     '__type': 'ET.Ed25519KeyPair',
#     '__uid': '🍃-8d1dc8766070c87a4bb1',
#     'private_key': '🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c',
#     'public_key': '🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284',
#     'platform_certificate': {...}
# }
```

### Generate a Working Key

Working keys are time-limited and endorsed by an identity key:

```python
# Generate a working key with explicit expiry
ci_key = msd.generate_key_pair(
    expires_in="30d",           # Valid for 30 days
    endorsed_by=identity_key     # Endorsed by identity key
)
```

**Duration units:**

| Unit | Example | Typical Use Case |
|------|---------|------------------|
| `h` (hours) | `"24h"` | Short CI jobs |
| `d` (days) | `"7d"`, `"30d"` | Development, staging |
| `m` (months) | `"3m"`, `"6m"` | Production services |

### Sign Data

```python
# Works with either key type
signed = msd.sign(
    data={"report": "Q4 Results"},
    metadata={"author": "finance@company.com"},
    key=ci_key  # or identity_key
)
```

---

## Key Storage

Keys are plain JSON data. The recommended storage approach depends on your environment:

| Environment | Recommended Storage | Why |
|-------------|--------------------|----- |
| **Local development** | Files in default directory | Simple, persistent |
| **Production servers** | Secrets manager → env vars | Secure, auditable, rotatable |

### Default Storage Locations (Local Development)

For local development on personal machines, the SDK uses idiomatic default locations per operating system:

| OS | Default Path | Notes |
|----|--------------|-------|
| **macOS** | `~/.config/msd/keys/` | Following XDG convention |
| **Linux** | `~/.config/msd/keys/` | XDG Base Directory spec |
| **Windows** | `%APPDATA%\msd\keys\` | Roaming app data |

### Save and Load Keys

```python
import msd_sdk as msd

# Generate a key
my_key = msd.generate_key_pair()

# Save to default location (uses OS-appropriate path)
msd.save_key("alice-identity.json", my_key)
# Saved to: ~/.config/msd/keys/alice-identity.json

# Save to explicit path
msd.save_key("/secure/keys/alice.json", my_key)

# Load from default location
loaded_key = msd.load_key("alice-identity.json")

# Load from explicit path
loaded_key = msd.load_key("/secure/keys/alice.json")
```

### Key File Format

Keys are stored as plain JSON:

```json
{
    "__type": "ET.Ed25519KeyPair",
    "__uid": "🍃-8d1dc8766070c87a4bb1",
    "private_key": "🗝️-61250af6bf8b9332be5c2b8a4877c56189867c8840cce541ab7fbe9270bb9b6c",
    "public_key": "🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284",
    "platform_certificate": {
        "__type": "ET.PlatformCertificate",
        "endorsed_public_key": "🔑-8614d100b3cdb5ff6c37c846760dd1990f637994bd985d9486f212133bfd6284",
        "platform_signature": "🔏-3a7f9c2e1d4b8a6f5c0e9d8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f",
        "issued_at": {"__type": "Time", "zef_unix_time": "1737849600"},
        "expires_at": {"__type": "Time", "zef_unix_time": "1769385600"}
    }
}
```

### Load from Environment Variable (Production)

For production servers and CI/CD, set your key as an environment variable. The recommended format is the **compact key string** — a single 119-character ASCII string:

```python
# Reads MSD_SIGNING_KEY by default
my_key = msd.key_from_env()
```

```bash
# Set the compact key in your environment
export MSD_SIGNING_KEY=msd-key-8d1dc8766070c87a4bb1-hhTRALPNtf9sN8hGdg3RmQ9jeZS9mF2UhvISEzv9YoRhJQr2v4uTMr5cK4pId8VhiYZ8iEDM5UGrf76ScLubbLNasw
```

Generate your compact key in [MSD Explorer](https://network.msd-protocol.org/dashboard) during the working key setup.

`key_from_env()` auto-detects three formats:

| Format | Detected by | Example |
|--------|-------------|---------|
| **Compact string** | Starts with `msd-key-` | `msd-key-8d1dc876...LNasw` |
| **JSON** | Starts with `{` | `{"__type":"ET.Ed25519KeyPair",...}` |
| **Base64 JSON** | Anything else | `eyJfX3R5cGUiOi...` |

To convert an existing key dict to compact format:

```python
compact = msd.key_to_compact(my_key)
print(compact)
# msd-key-8d1dc8766070c87a4bb1-hhTRALPN...
```

#### Deployment Examples

```bash
# Docker
docker run -e MSD_SIGNING_KEY=msd-key-... my-app

# Docker Compose
environment:
  - MSD_SIGNING_KEY=msd-key-...

# Kubernetes Secret
kubectl create secret generic msd-key --from-literal=MSD_SIGNING_KEY=msd-key-...

# GitHub Actions (set MSD_SIGNING_KEY as a repository secret)
env:
  MSD_SIGNING_KEY: ${{ secrets.MSD_SIGNING_KEY }}

# AWS Secrets Manager
export MSD_SIGNING_KEY=$(aws secretsmanager get-secret-value --secret-id msd-signing-key --query SecretString --output text)
```

> **Legacy:** `MSD_PRIVATE_KEY` is also accepted as a fallback env var name when using the default.

---

## Trust Hierarchy

### How Trust is Established

```mermaid
sequenceDiagram
    participant User as You
    participant SDK as MSD SDK
    participant Platform as MSD Platform
    
    Note over User,Platform: One-time: Create Identity Key
    User->>SDK: generate_key_pair()
    SDK->>SDK: Generate Ed25519 locally
    SDK->>Platform: Register public key
    Platform->>SDK: Challenge nonce
    SDK->>SDK: Sign with private key
    SDK->>Platform: Proof of ownership
    Platform->>SDK: Platform endorsement
    SDK->>User: Endorsed identity key
    
    Note over User,Platform: Daily: Create Working Keys
    User->>SDK: generate_key_pair(endorsed_by=identity_key)
    SDK->>SDK: Generate + endorse with identity key
    SDK->>User: Endorsed working key
```

### Endorsement Chain

> **A key is valid if it is part of a chain of endorsements leading to a trusted root key.**

Anyone can verify signatures by tracing the endorsement chain:

```python
result = msd.verify(signed_data, return_details=True)

# Returns (using UIDs for compact display):
{
    'valid': True,
    'endorsement_chain': [
        {'type': 'MSD Platform Root', 'uid': '🍃-c2f7b7d4528c970d7a0a', 'status': 'trusted'},
        {'type': 'Identity Key', 'uid': '🍃-8d1dc8766070c87a4bb1', 'endorsed_by': '🍃-c2f7b7d4528c970d7a0a', 'status': 'active'},
        {'type': 'Working Key', 'uid': '🍃-a2b3c4d5e6f78901bcde', 'endorsed_by': '🍃-8d1dc8766070c87a4bb1', 'status': 'active', 'expires_at': '2026-02-25T00:00:00Z'}
    ]
}
```

The chain shows: **Root → endorses → Identity Key → endorses → Working Key**

---

## Configuring Trust Anchors

By default, the SDK trusts the MSD platform's root key. If required in future, additional trust anchors can be configured programmatically or via environment variables.


### Environment-Based Configuration

```bash
# Trust multiple roots via environment
export MSD_TRUST_ANCHORS='[
  {"name": "MSD Platform", "key": "🔑-msd_platform_root_key_64_hex_chars_here_0000000000000000"},
  {"name": "Acme Corp", "key": "🔑-a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890"}
]'
```

---

## Best Practices

### Identity Keys

| ✅ Do | ❌ Don't |
|-------|---------|
| Store in password manager or HSM | Store in plain text files in repos |
| Use for endorsing working keys | Use for routine signing |
| Back up securely | Share or transmit over network |
| One per person/organization | Multiple identity keys per entity |

### Working Keys

| ✅ Do | ❌ Don't |
|-------|---------|
| Set appropriate expiry (days to months) | Create without expiry |
| Scope to specific environments | Grant overly broad permissions |
| Rotate periodically (similar to TLS certs) | Reuse same key indefinitely |
| Let expire naturally | Keep long after use |

> **Note**: Working keys don't need to be generated per-signature. A typical pattern is issuing keys valid for days to months (similar to TLS certificates), managed by a key service or CI/CD system.

---

## API Reference

### Key Generation

```python
# Identity key (endorsed by MSD platform, never expires)
identity_key = msd.generate_key_pair()

# Working key (endorsed by identity key, has expiry)
working_key = msd.generate_key_pair(
    endorsed_by=identity_key,      # Identity key endorses this key
    expires_in="30d"               # Duration: "1h", "7d", "30d", "3m"
)

# Unendorsed key (testing/offline only - not recommended for production)
test_key = msd.generate_key_pair(unendorsed=True)
```

> **Note**: `generate_key_pair()` requires endorsement by default. Use `unendorsed=True` only for local testing.

> **Coming soon**: Key visibility controls for specifying which parties can discover keys.

### Key Storage

```python
# Save to file (default location or explicit path)
msd.save_key(name_or_path, key)

# Load from file  
key = msd.load_key(name_or_path)

# Load from environment (JSON format)
key = msd.key_from_env("MSD_PRIVATE_KEY")

# Get default key directory for current OS
msd.get_key_directory() -> str
# macOS/Linux: ~/.config/msd/keys/
# Windows: %APPDATA%\msd\keys\
```

### Trust Management

```python
# Check if key is endorsed by trusted root
msd.is_endorsed(key) -> bool

# Get full endorsement chain
msd.get_endorsement_chain(key) -> list
```

---

## Example: CI/CD Pipeline

```python
# ci_setup.py - Use pre-provisioned working key from secrets
import msd_sdk as msd
import os

# Load working key from CI secrets (pre-generated, valid for ~30 days)
# Key rotation is handled by your key management service
pipeline_key = msd.key_from_env("MSD_CI_SIGNING_KEY")

# Sign build artifacts
for artifact in build_artifacts:
    signed = msd.sign(
        data={'__type': artifact.type, 'data': artifact.content},
        metadata={'build_id': os.environ['BUILD_ID'], 'commit': os.environ['GIT_SHA']},
        key=pipeline_key
    )
    msd.save_file(f"{artifact.name}.msd", signed)
```

> **Tip**: Rather than generating keys per-pipeline-run, provision working keys with 30-90 day validity and rotate them periodically (similar to TLS certificate management).

---

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Key not endorsed by trusted root" | Add appropriate trust anchor |
| "Delegated key expired" | Generate new working key from identity key |
| "Cannot verify offline" | Ensure MSD root public key is bundled (default) |
| "Platform unreachable" | Use `register_with_platform=False` for local-only keys |
