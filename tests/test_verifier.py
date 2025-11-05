"""Tests for JWT Verifier"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import hmac
import hashlib
import json
from src.verifier import JWTVerifier
from src.utils.base64url import base64url_encode


def create_signed_jwt(header: dict, payload: dict, secret: str, algorithm: str = 'HS256') -> str:
    """Create a properly signed JWT for testing"""
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    if algorithm == 'HS256':
        signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    elif algorithm == 'HS384':
        signature = hmac.new(secret.encode(), signing_input, hashlib.sha384).digest()
    elif algorithm == 'HS512':
        signature = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    signature_b64 = base64url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def test_verify_valid_hs256():
    """Test verifying valid HS256 token"""
    secret = "my-secret-key"
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user123", "name": "Test User"}
    
    token = create_signed_jwt(header, payload, secret, "HS256")
    
    verifier = JWTVerifier()
    result = verifier.verify(token, secret)
    
    assert result.valid == True
    assert result.algorithm == "HS256"
    assert "successfully" in result.message.lower()


def test_verify_invalid_secret():
    """Test verifying with wrong secret"""
    secret = "correct-secret"
    wrong_secret = "wrong-secret"
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user123"}
    
    token = create_signed_jwt(header, payload, secret, "HS256")
    
    verifier = JWTVerifier()
    result = verifier.verify(token, wrong_secret)
    
    assert result.valid == False
    assert "failed" in result.message.lower() or "invalid" in result.message.lower()


def test_verify_hs384():
    """Test verifying HS384 token"""
    secret = "my-secret-key-384"
    header = {"alg": "HS384", "typ": "JWT"}
    payload = {"sub": "user456"}
    
    token = create_signed_jwt(header, payload, secret, "HS384")
    
    verifier = JWTVerifier()
    result = verifier.verify(token, secret)
    
    assert result.valid == True
    assert result.algorithm == "HS384"


def test_verify_hs512():
    """Test verifying HS512 token"""
    secret = "my-secret-key-512"
    header = {"alg": "HS512", "typ": "JWT"}
    payload = {"sub": "user789"}
    
    token = create_signed_jwt(header, payload, secret, "HS512")
    
    verifier = JWTVerifier()
    result = verifier.verify(token, secret)
    
    assert result.valid == True
    assert result.algorithm == "HS512"


def test_verify_none_algorithm():
    """Test that 'none' algorithm returns invalid"""
    header = {"alg": "none"}
    payload = {"sub": "user123"}
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    token = f"{header_b64}.{payload_b64}."
    
    verifier = JWTVerifier()
    result = verifier.verify(token, "any-key")
    
    assert result.valid == False
    assert result.algorithm == "none"


def test_verify_with_secret_list():
    """Test verifying with list of secrets"""
    correct_secret = "the-right-secret"
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user123"}
    
    token = create_signed_jwt(header, payload, correct_secret, "HS256")
    
    secrets = ["wrong1", "wrong2", correct_secret, "wrong3"]
    
    verifier = JWTVerifier()
    result = verifier.verify_with_secret_list(token, secrets)
    
    assert result is not None
    assert result.valid == True


def test_verify_with_secret_list_no_match():
    """Test verifying with list when no secret matches"""
    correct_secret = "the-right-secret"
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user123"}
    
    token = create_signed_jwt(header, payload, correct_secret, "HS256")
    
    secrets = ["wrong1", "wrong2", "wrong3"]
    
    verifier = JWTVerifier()
    result = verifier.verify_with_secret_list(token, secrets)
    
    assert result is None


if __name__ == '__main__':
    # Run tests
    test_verify_valid_hs256()
    print("✓ test_verify_valid_hs256")
    
    test_verify_invalid_secret()
    print("✓ test_verify_invalid_secret")
    
    test_verify_hs384()
    print("✓ test_verify_hs384")
    
    test_verify_hs512()
    print("✓ test_verify_hs512")
    
    test_verify_none_algorithm()
    print("✓ test_verify_none_algorithm")
    
    test_verify_with_secret_list()
    print("✓ test_verify_with_secret_list")
    
    test_verify_with_secret_list_no_match()
    print("✓ test_verify_with_secret_list_no_match")
    
    print("\nAll verifier tests passed!")
