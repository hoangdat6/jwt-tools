# JWT Tool - Phase 1 Complete ✅

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage

### Analyze a JWT token

```bash
# Analyze from command line
python -m src.cli analyze "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Analyze from file
python -m src.cli analyze -f token.txt

# Disable colors
python -m src.cli analyze --no-color "your.jwt.token"
```

### Run Tests

```bash
python tests/test_parser.py
```

## Features Implemented ✅

- [x] JWT parser with base64url decode
- [x] Header and payload JSON pretty-print
- [x] Timestamp humanization (exp/iat/nbf)
- [x] Weak pattern detection:
  - [x] `alg: none` detection (critical)
  - [x] Symmetric vs asymmetric algorithm classification
  - [x] Missing expiration warning
  - [x] Long token lifetime warning
  - [x] Sensitive data in payload detection
  - [x] Header security issues (jku, jwk, kid manipulation)
- [x] Colored CLI output
- [x] Basic tests

## Example Output

```
======================================================================
JWT SECURITY ANALYSIS
======================================================================

Algorithm: HS256 (symmetric)

HEADER:
{
  "alg": "HS256",
  "typ": "JWT"
}

PAYLOAD:
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

TIMESTAMPS:
  iat: 2018-01-18 01:30:22 UTC

SECURITY WARNINGS:

  1. [LOW] Algorithm
     Token uses symmetric algorithm (HS256) - vulnerable to brute-force if secret is weak
     → Use strong, random secrets (min 256 bits). Consider asymmetric algorithms for better key management.

  2. [MEDIUM] Payload
     Token has no expiration time ('exp' claim)
     → Always set expiration time for tokens to limit their lifetime.

======================================================================
```

## Next Steps

Ready for **Phase 2: Signature Verification** 🔐

Features to implement:
- HS256/HS384/HS512 signature verification
- Key input handling
- Verification reporting
