"""Tests for JWT Forger"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import hmac
import hashlib
import json
from src.forger import JWTForger
from src.utils.base64url import base64url_encode
from src.verifier import JWTVerifier


def create_test_token(secret: str = "test-secret") -> str:
    """Create a test HS256 token"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user123", "role": "user", "admin": False}
    
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def test_forge_none_algorithm():
    """Test forging with none algorithm"""
    token = create_test_token()
    forger = JWTForger()
    
    result = forger.forge_none_algorithm(token)
    
    assert result.success == True
    assert result.token.endswith('.')  # No signature
    assert result.header['alg'] == 'none'


def test_forge_modify_claims():
    """Test modifying claims"""
    token = create_test_token()
    forger = JWTForger()
    
    modifications = {"role": "admin", "admin": True}
    result = forger.forge_modify_claims(token, modifications)
    
    assert result.success == True
    assert result.payload['role'] == 'admin'
    assert result.payload['admin'] == True


def test_forge_modify_and_resign():
    """Test modifying claims and re-signing"""
    secret = "test-secret"
    token = create_test_token(secret)
    forger = JWTForger()
    
    modifications = {"role": "admin"}
    result = forger.forge_modify_claims(token, modifications, secret)
    
    assert result.success == True
    
    # Verify the forged token
    verifier = JWTVerifier()
    verify_result = verifier.verify(result.token, secret)
    assert verify_result.valid == True


def test_forge_custom_token():
    """Test creating custom token"""
    forger = JWTForger()
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "hacker", "role": "superadmin"}
    secret = "my-secret"
    
    result = forger.forge_custom(header, payload, secret)
    
    assert result.success == True
    assert result.header == header
    assert result.payload == payload


def test_common_escalations():
    """Test getting common escalation scenarios"""
    forger = JWTForger()
    
    escalations = forger.get_common_escalations()
    
    assert "user_to_admin" in escalations
    assert "elevate_permissions" in escalations
    assert len(escalations) >= 5


def test_forge_privilege_escalation():
    """Test privilege escalation attack"""
    token = create_test_token("secret")
    forger = JWTForger()
    
    # Get user_to_admin escalation
    escalations = forger.get_common_escalations()
    modifications = escalations["user_to_admin"]["modifications"]
    
    result = forger.forge_modify_claims(token, modifications, "secret")
    
    assert result.success == True
    assert result.payload.get('role') == 'admin' or result.payload.get('isAdmin') == True


if __name__ == '__main__':
    # Run tests
    test_forge_none_algorithm()
    print("✓ test_forge_none_algorithm")
    
    test_forge_modify_claims()
    print("✓ test_forge_modify_claims")
    
    test_forge_modify_and_resign()
    print("✓ test_forge_modify_and_resign")
    
    test_forge_custom_token()
    print("✓ test_forge_custom_token")
    
    test_common_escalations()
    print("✓ test_common_escalations")
    
    test_forge_privilege_escalation()
    print("✓ test_forge_privilege_escalation")
    
    print("\nAll forger tests passed!")
