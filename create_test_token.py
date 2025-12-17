#!/usr/bin/env python3
"""Create a test token with known secret"""

import os
import sys

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.forger import JWTForger
from src.verifier import JWTVerifier

# Create a token with known secret
forger = JWTForger()
header = {'alg': 'HS256', 'typ': 'JWT'}
payload = {'sub': '1234567890', 'name': 'Test User', 'admin': False}
secret = 'secret123'

result = forger.forge_custom(header, payload, secret)
print(f"Created token with secret '{secret}':")
print(f"Token: {result.token}")

# Verify it works
verifier = JWTVerifier()
verify_result = verifier.verify(result.token, secret)
print(f"\nVerification with '{secret}': {verify_result.valid}")

# Also test with wrong secret
verify_result2 = verifier.verify(result.token, "wrong")
print(f"Verification with 'wrong': {verify_result2.valid}")
