"""Tests for JWT Parser"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
from datetime import datetime, timezone, timedelta
from src.parser import JWTParser, AlgorithmType
from src.utils.base64url import base64url_encode


def create_test_jwt(header: dict, payload: dict) -> str:
    """Create a test JWT (unsigned)"""
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    return f"{header_b64}.{payload_b64}.fake_signature"


def test_parse_valid_jwt():
    """Test parsing a valid JWT"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user123", "name": "Test User"}
    token = create_test_jwt(header, payload)
    
    parser = JWTParser()
    analysis = parser.parse(token)
    
    assert analysis.header == header
    assert analysis.payload == payload
    assert analysis.algorithm == "HS256"
    assert analysis.algorithm_type == AlgorithmType.SYMMETRIC


def test_detect_none_algorithm():
    """Test detection of 'none' algorithm"""
    header = {"alg": "none"}
    payload = {"sub": "user123"}
    token = create_test_jwt(header, payload)
    
    parser = JWTParser()
    analysis = parser.parse(token)
    
    assert analysis.algorithm_type == AlgorithmType.NONE
    # Should have critical warning
    critical_warnings = [w for w in analysis.warnings if w.severity == "critical"]
    assert len(critical_warnings) > 0


def test_detect_missing_expiration():
    """Test detection of missing expiration"""
    header = {"alg": "HS256"}
    payload = {"sub": "user123"}  # No 'exp' claim
    token = create_test_jwt(header, payload)
    
    parser = JWTParser()
    analysis = parser.parse(token)
    
    # Should have warning about missing exp
    exp_warnings = [w for w in analysis.warnings 
                   if 'expiration' in w.message.lower()]
    assert len(exp_warnings) > 0


def test_timestamp_parsing():
    """Test timestamp humanization"""
    now = int(datetime.now(timezone.utc).timestamp())
    future = now + 3600  # 1 hour from now
    
    header = {"alg": "HS256"}
    payload = {
        "sub": "user123",
        "iat": now,
        "exp": future
    }
    token = create_test_jwt(header, payload)
    
    parser = JWTParser()
    analysis = parser.parse(token)
    
    assert 'iat' in analysis.timestamp_info
    assert 'exp' in analysis.timestamp_info
    assert not analysis.timestamp_info['exp']['expired']


def test_detect_sensitive_data():
    """Test detection of sensitive data in payload"""
    header = {"alg": "HS256"}
    payload = {
        "sub": "user123",
        "password": "secret123",  # Sensitive!
        "api_key": "abc123"  # Sensitive!
    }
    token = create_test_jwt(header, payload)
    
    parser = JWTParser()
    analysis = parser.parse(token)
    
    # Should have warning about sensitive data
    sensitive_warnings = [w for w in analysis.warnings 
                         if 'sensitive data' in w.message.lower()]
    assert len(sensitive_warnings) > 0


if __name__ == '__main__':
    # Run tests
    test_parse_valid_jwt()
    print("✓ test_parse_valid_jwt")
    
    test_detect_none_algorithm()
    print("✓ test_detect_none_algorithm")
    
    test_detect_missing_expiration()
    print("✓ test_detect_missing_expiration")
    
    test_timestamp_parsing()
    print("✓ test_timestamp_parsing")
    
    test_detect_sensitive_data()
    print("✓ test_detect_sensitive_data")
    
    print("\nAll tests passed!")
