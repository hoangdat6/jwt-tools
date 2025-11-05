# JWT Tool - Phase 2 Complete ✅

## Phase 2: Signature Verification

### New Features

✅ **HMAC Signature Verification** (HS256/HS384/HS512)
- Verify JWT signatures with secret keys
- Constant-time comparison for security
- Support for raw strings and file-based keys

✅ **RSA Signature Verification** (RS256/RS384/RS512)
- Verify with RSA public keys
- Support PEM and SSH key formats
- Key size detection

✅ **Enhanced CLI**
- New `verify` command
- File input support for tokens and keys
- Algorithm override option
- Colored output for verification results

✅ **Batch Verification**
- Test multiple secrets against a token
- Useful for brute-force preparation

## Installation

```bash
pip install -r requirements.txt
```

## Usage Examples

### Verify HS256 Token

```bash
# With secret string
python -m src.cli verify "eyJhbGc..." "my-secret-key"

# With secret from file
python -m src.cli verify "eyJhbGc..." -k secret.txt

# Force algorithm
python -m src.cli verify "eyJhbGc..." "secret" -a HS256
```

### Verify RS256 Token

```bash
# With public key file
python -m src.cli verify "eyJhbGc..." examples/test_keys/rsa_public.pem

# With key from file
python -m src.cli verify -t token.txt -k public_key.pem
```

### Example Output

```
======================================================================
JWT SIGNATURE VERIFICATION
======================================================================

Algorithm: HS256
Key Info: Secret length: 13 bytes

Status: ✓ VALID
Message: Signature verified successfully
```

## Testing

```bash
# Run verification tests
python tests/test_verifier.py

# Run all tests
python tests/test_parser.py
python tests/test_verifier.py
```

## Supported Algorithms

### Symmetric (HMAC)
- ✅ HS256 - HMAC with SHA-256
- ✅ HS384 - HMAC with SHA-384
- ✅ HS512 - HMAC with SHA-512

### Asymmetric (RSA)
- ✅ RS256 - RSA with SHA-256
- ✅ RS384 - RSA with SHA-384
- ✅ RS512 - RSA with SHA-512

### Coming Soon
- ES256/384/512 - ECDSA
- PS256/384/512 - RSA-PSS

## API Usage

```python
from src.verifier import JWTVerifier

verifier = JWTVerifier()

# Verify with single key
result = verifier.verify(token, "my-secret")
if result.valid:
    print("Token is valid!")
else:
    print(f"Verification failed: {result.message}")

# Try multiple secrets
secrets = ["secret1", "secret2", "secret3"]
result = verifier.verify_with_secret_list(token, secrets)
if result:
    print(f"Found valid secret!")
```

## Key Format Support

### HMAC Keys
- Raw string: `"my-secret-key"`
- File: `secret.txt` (plain text)
- Bytes: `b"my-secret-key"`

### RSA Public Keys
- PEM format: `-----BEGIN PUBLIC KEY-----`
- SSH format: `ssh-rsa AAAA...`
- File: `public_key.pem`

## Security Notes

⚠️ **Important**:
- Always use strong secrets (min 256 bits for HS256)
- Verify key sources - don't trust embedded keys
- Use constant-time comparison (built-in)
- Test keys are for development only

## Next Steps

Ready for **Phase 3: Brute-force Engine** 💪

Features to implement:
- Wordlist-based secret cracking
- Multiprocessing for performance
- Progress tracking
- Common weak secrets database
