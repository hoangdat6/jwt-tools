"""JWT Signature Verification"""

import hmac
import hashlib
from typing import Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from .utils.base64url import base64url_decode


@dataclass
class VerificationResult:
    """Result of signature verification"""
    valid: bool
    algorithm: str
    message: str
    key_info: Optional[str] = None


class JWTVerifier:
    """JWT Signature Verifier"""
    
    HMAC_ALGORITHMS = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512
    }
    
    RSA_ALGORITHMS = {
        'RS256': hashes.SHA256(),
        'RS384': hashes.SHA384(),
        'RS512': hashes.SHA512()
    }
    
    def __init__(self):
        self.backend = default_backend()
    
    def verify(self, token: str, key: str, algorithm: Optional[str] = None) -> VerificationResult:
        """
        Verify JWT signature with provided key.
        
        Args:
            token: JWT token string
            key: Secret key or path to key file
            algorithm: Force specific algorithm (optional)
            
        Returns:
            VerificationResult object
        """
        # Split token
        parts = token.strip().split('.')
        if len(parts) != 3:
            return VerificationResult(
                valid=False,
                algorithm='unknown',
                message='Invalid JWT format'
            )
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Decode header to get algorithm
        try:
            import json
            header_bytes = base64url_decode(header_b64)
            header = json.loads(header_bytes.decode('utf-8'))
            token_alg = header.get('alg', '').upper()
        except Exception as e:
            return VerificationResult(
                valid=False,
                algorithm='unknown',
                message=f'Failed to decode header: {e}'
            )
        
        # Use specified algorithm or token's algorithm
        alg = (algorithm or token_alg).upper()
        
        # Handle 'none' algorithm
        if alg == 'NONE':
            return VerificationResult(
                valid=False,
                algorithm='none',
                message="Cannot verify 'none' algorithm - no signature validation"
            )
        
        # Load key
        key_data, key_type = self._load_key(key, alg)
        
        # Verify based on algorithm type
        if alg in self.HMAC_ALGORITHMS:
            return self._verify_hmac(header_b64, payload_b64, signature_b64, key_data, alg)
        elif alg in self.RSA_ALGORITHMS:
            return self._verify_rsa(header_b64, payload_b64, signature_b64, key_data, alg)
        else:
            return VerificationResult(
                valid=False,
                algorithm=alg,
                message=f'Unsupported algorithm: {alg}'
            )
    
    def _load_key(self, key: str, algorithm: str) -> Tuple[bytes, str]:
        """
        Load key from string or file.
        
        Returns:
            Tuple of (key_data, key_type)
        """
        # Check if key is a file path
        key_path = Path(key)
        if key_path.exists() and key_path.is_file():
            try:
                key_data = key_path.read_bytes()
                return key_data, 'file'
            except Exception as e:
                raise ValueError(f"Failed to read key file: {e}")
        
        # Treat as raw key string
        if isinstance(key, str):
            return key.encode('utf-8'), 'string'
        
        return key, 'bytes'
    
    def _verify_hmac(self, header_b64: str, payload_b64: str, 
                     signature_b64: str, secret: bytes, algorithm: str) -> VerificationResult:
        """Verify HMAC signature (HS256/HS384/HS512)"""
        try:
            # Get hash function
            hash_func = self.HMAC_ALGORITHMS.get(algorithm)
            if not hash_func:
                return VerificationResult(
                    valid=False,
                    algorithm=algorithm,
                    message=f'Unknown HMAC algorithm: {algorithm}'
                )
            
            # Create signing input
            signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
            
            # Decode expected signature
            try:
                expected_signature = base64url_decode(signature_b64)
            except Exception as e:
                return VerificationResult(
                    valid=False,
                    algorithm=algorithm,
                    message=f'Invalid signature encoding: {e}'
                )
            
            # Compute actual signature
            actual_signature = hmac.new(
                secret,
                signing_input,
                hash_func
            ).digest()
            
            # Compare signatures (constant-time comparison)
            valid = hmac.compare_digest(actual_signature, expected_signature)
            
            if valid:
                return VerificationResult(
                    valid=True,
                    algorithm=algorithm,
                    message='Signature verified successfully',
                    key_info=f'Secret length: {len(secret)} bytes'
                )
            else:
                return VerificationResult(
                    valid=False,
                    algorithm=algorithm,
                    message='Signature verification failed - invalid secret',
                    key_info=f'Secret length: {len(secret)} bytes'
                )
                
        except Exception as e:
            return VerificationResult(
                valid=False,
                algorithm=algorithm,
                message=f'Verification error: {str(e)}'
            )
    
    def _verify_rsa(self, header_b64: str, payload_b64: str,
                    signature_b64: str, public_key_data: bytes, algorithm: str) -> VerificationResult:
        """Verify RSA signature (RS256/RS384/RS512)"""
        try:
            # Load public key
            try:
                # Try PEM format first
                public_key = serialization.load_pem_public_key(
                    public_key_data,
                    backend=self.backend
                )
            except Exception:
                try:
                    # Try SSH format
                    public_key = serialization.load_ssh_public_key(
                        public_key_data,
                        backend=self.backend
                    )
                except Exception as e:
                    return VerificationResult(
                        valid=False,
                        algorithm=algorithm,
                        message=f'Failed to load public key: {e}'
                    )
            
            # Verify it's an RSA key
            if not isinstance(public_key, rsa.RSAPublicKey):
                return VerificationResult(
                    valid=False,
                    algorithm=algorithm,
                    message=f'Expected RSA public key, got {type(public_key).__name__}'
                )
            
            # Get hash algorithm
            hash_alg = self.RSA_ALGORITHMS.get(algorithm)
            if not hash_alg:
                return VerificationResult(
                    valid=False,
                    algorithm=algorithm,
                    message=f'Unknown RSA algorithm: {algorithm}'
                )
            
            # Create signing input
            signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
            
            # Decode signature
            try:
                signature = base64url_decode(signature_b64)
            except Exception as e:
                return VerificationResult(
                    valid=False,
                    algorithm=algorithm,
                    message=f'Invalid signature encoding: {e}'
                )
            
            # Verify signature
            try:
                public_key.verify(
                    signature,
                    signing_input,
                    padding.PKCS1v15(),
                    hash_alg
                )
                
                key_size = public_key.key_size
                return VerificationResult(
                    valid=True,
                    algorithm=algorithm,
                    message='Signature verified successfully',
                    key_info=f'RSA key size: {key_size} bits'
                )
                
            except InvalidSignature:
                return VerificationResult(
                    valid=False,
                    algorithm=algorithm,
                    message='Signature verification failed - invalid signature or wrong public key'
                )
                
        except Exception as e:
            return VerificationResult(
                valid=False,
                algorithm=algorithm,
                message=f'Verification error: {str(e)}'
            )
    
    def verify_with_secret_list(self, token: str, secrets: list) -> Optional[VerificationResult]:
        """
        Try to verify with a list of secrets.
        Returns first successful verification or None.
        
        Args:
            token: JWT token
            secrets: List of secrets to try
            
        Returns:
            VerificationResult if any secret works, None otherwise
        """
        for secret in secrets:
            result = self.verify(token, secret)
            if result.valid:
                return result
        
        return None
