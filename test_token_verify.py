#!/usr/bin/env python3
"""Verify test token"""

import sys
sys.path.insert(0, '/home/dathv2004/Documents/BKDN/Learning/Pentest/jwt-tool')

from src.verifier import JWTVerifier
from src.parser import JWTParser

# Test token
test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dyt0CoTl4WoVjAHI9Q_CwSKhl6d_9rhM3NrXuJttkao"

# Parse
parser = JWTParser()
parsed = parser.parse(test_token)
print("Parsed token:")
print(f"  Header: {parsed.header}")
print(f"  Payload: {parsed.payload}")

# Test some secrets
verifier = JWTVerifier()
secrets_to_test = ["secret", "secret123", "password", ""]

print("\nTesting secrets:")
for secret in secrets_to_test:
    result = verifier.verify(test_token, secret)
    print(f"  '{secret}': {result.valid}")
