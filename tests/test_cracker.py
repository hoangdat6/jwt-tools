"""Tests for JWT Cracker"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import hmac
import hashlib
import json
import tempfile
from src.cracker import JWTCracker, WordlistLoader
from src.utils.base64url import base64url_encode


def create_signed_jwt(secret: str) -> str:
    """Create a signed JWT for testing"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "test", "name": "Test User"}
    
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def test_load_common_secrets():
    """Test loading built-in common secrets"""
    secrets = WordlistLoader.load_common_secrets()
    
    assert len(secrets) > 0
    assert "secret" in secrets
    assert "password" in secrets
    assert "" in secrets  # Empty secret


def test_crack_with_common_secret():
    """Test cracking with common secret"""
    # Create token with common secret
    secret = "123456"
    token = create_signed_jwt(secret)
    
    cracker = JWTCracker(num_workers=2)
    result = cracker.crack(token, use_common=True)
    
    assert result.success == True
    assert result.secret == secret
    assert result.attempts > 0


def test_crack_with_wordlist():
    """Test cracking with wordlist file"""
    secret = "myspecialsecret"
    token = create_signed_jwt(secret)
    
    # Create temporary wordlist
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("wrong1\n")
        f.write("wrong2\n")
        f.write(f"{secret}\n")
        f.write("wrong3\n")
        wordlist_path = f.name
    
    try:
        cracker = JWTCracker(num_workers=2)
        result = cracker.crack(token, wordlist_path=wordlist_path, use_common=False)
        
        assert result.success == True
        assert result.secret == secret
    finally:
        Path(wordlist_path).unlink()


def test_crack_not_found():
    """Test when secret is not in wordlist"""
    secret = "impossiblesecret12345"
    token = create_signed_jwt(secret)
    
    # Create small wordlist without the secret
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("wrong1\n")
        f.write("wrong2\n")
        f.write("wrong3\n")
        wordlist_path = f.name
    
    try:
        cracker = JWTCracker(num_workers=2)
        result = cracker.crack(token, wordlist_path=wordlist_path, use_common=False)
        
        assert result.success == False
        assert result.secret is None
        assert result.attempts > 0
    finally:
        Path(wordlist_path).unlink()


def test_wordlist_count():
    """Test counting wordlist lines"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("line1\n")
        f.write("line2\n")
        f.write("\n")  # Empty line
        f.write("line3\n")
        wordlist_path = f.name
    
    try:
        count = WordlistLoader.count_lines(wordlist_path)
        assert count == 3  # Should skip empty line
    finally:
        Path(wordlist_path).unlink()


def test_progress_callback():
    """Test progress callback during cracking"""
    secret = "secret"
    token = create_signed_jwt(secret)
    
    progress_updates = []
    
    def callback(progress):
        progress_updates.append(progress)
    
    cracker = JWTCracker(num_workers=2)
    result = cracker.crack(token, use_common=True, progress_callback=callback)
    
    assert result.success == True
    # Progress callback may or may not be called depending on speed
    # Just verify structure if called
    if progress_updates:
        p = progress_updates[0]
        assert hasattr(p, 'attempts')
        assert hasattr(p, 'elapsed_time')
        assert hasattr(p, 'attempts_per_second')


if __name__ == '__main__':
    # Run tests
    test_load_common_secrets()
    print("✓ test_load_common_secrets")
    
    test_crack_with_common_secret()
    print("✓ test_crack_with_common_secret")
    
    test_crack_with_wordlist()
    print("✓ test_crack_with_wordlist")
    
    test_crack_not_found()
    print("✓ test_crack_not_found")
    
    test_wordlist_count()
    print("✓ test_wordlist_count")
    
    test_progress_callback()
    print("✓ test_progress_callback")
    
    print("\nAll cracker tests passed!")
