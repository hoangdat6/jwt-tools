"""JWT Parser and Analyzer"""

import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

from .utils.base64url import base64url_decode
from .utils.time_utils import humanize_timestamp, is_expired, time_until_expiry


class AlgorithmType(Enum):
    """JWT Algorithm Types"""
    NONE = "none"
    SYMMETRIC = "symmetric"  # HS256, HS384, HS512
    ASYMMETRIC = "asymmetric"  # RS256, RS384, RS512, ES256, PS256, etc.
    UNKNOWN = "unknown"


@dataclass
class SecurityWarning:
    """Security warning found in JWT"""
    severity: str  # "critical", "high", "medium", "low"
    category: str
    message: str
    recommendation: str


@dataclass
class JWTAnalysis:
    """Complete JWT analysis result"""
    raw_token: str
    header: Dict
    payload: Dict
    signature: str
    algorithm: str
    algorithm_type: AlgorithmType
    warnings: List[SecurityWarning]
    timestamp_info: Dict


class JWTParser:
    """JWT Parser and Security Analyzer"""
    
    SYMMETRIC_ALGORITHMS = ['HS256', 'HS384', 'HS512']
    ASYMMETRIC_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 
                             'PS256', 'PS384', 'PS512']
    
    def __init__(self):
        self.warnings: List[SecurityWarning] = []
    
    def parse(self, token: str) -> JWTAnalysis:
        """
        Parse and analyze a JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            JWTAnalysis object with all parsed information
            
        Raises:
            ValueError: If token format is invalid
        """
        self.warnings = []
        
        # Split token into parts
        parts = token.strip().split('.')
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Decode header
        try:
            header_bytes = base64url_decode(header_b64)
            header = json.loads(header_bytes.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Failed to decode header: {e}")
        
        # Decode payload
        try:
            payload_bytes = base64url_decode(payload_b64)
            payload = json.loads(payload_bytes.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Failed to decode payload: {e}")
        
        # Get algorithm
        algorithm = header.get('alg', 'unknown').upper()
        algorithm_type = self._detect_algorithm_type(algorithm)
        
        # Analyze security
        self._analyze_algorithm(algorithm, algorithm_type)
        self._analyze_header(header)
        self._analyze_payload(payload)
        
        # Parse timestamps
        timestamp_info = self._parse_timestamps(payload)
        
        return JWTAnalysis(
            raw_token=token,
            header=header,
            payload=payload,
            signature=signature_b64,
            algorithm=algorithm,
            algorithm_type=algorithm_type,
            warnings=self.warnings,
            timestamp_info=timestamp_info
        )
    
    def _detect_algorithm_type(self, algorithm: str) -> AlgorithmType:
        """Detect the type of JWT algorithm"""
        alg_upper = algorithm.upper()
        
        if alg_upper == 'NONE':
            return AlgorithmType.NONE
        elif alg_upper in self.SYMMETRIC_ALGORITHMS:
            return AlgorithmType.SYMMETRIC
        elif alg_upper in self.ASYMMETRIC_ALGORITHMS:
            return AlgorithmType.ASYMMETRIC
        else:
            return AlgorithmType.UNKNOWN
    
    def _analyze_algorithm(self, algorithm: str, alg_type: AlgorithmType):
        """Analyze algorithm security"""
        alg_upper = algorithm.upper()
        
        # Critical: None algorithm
        if alg_type == AlgorithmType.NONE:
            self.warnings.append(SecurityWarning(
                severity="critical",
                category="Algorithm",
                message="Token uses 'none' algorithm - signature verification is disabled!",
                recommendation="Never use 'none' algorithm in production. This allows token forgery."
            ))
        
        # Unknown algorithm
        if alg_type == AlgorithmType.UNKNOWN:
            self.warnings.append(SecurityWarning(
                severity="medium",
                category="Algorithm",
                message=f"Unknown or non-standard algorithm: {algorithm}",
                recommendation="Verify this algorithm is supported by your JWT library."
            ))
        
        # Weak symmetric algorithms (informational)
        if alg_upper in self.SYMMETRIC_ALGORITHMS:
            self.warnings.append(SecurityWarning(
                severity="low",
                category="Algorithm",
                message=f"Token uses symmetric algorithm ({algorithm}) - vulnerable to brute-force if secret is weak",
                recommendation="Use strong, random secrets (min 256 bits). Consider asymmetric algorithms for better key management."
            ))
    
    def _analyze_header(self, header: Dict):
        """Analyze JWT header for security issues"""
        
        # Check for 'jku' (JSON Web Key URL) - potential SSRF
        if 'jku' in header:
            self.warnings.append(SecurityWarning(
                severity="high",
                category="Header",
                message="Token contains 'jku' (JWK Set URL) header",
                recommendation="Validate 'jku' URL strictly. This can be exploited for SSRF or key confusion attacks."
            ))
        
        # Check for 'jwk' (embedded public key) - key confusion
        if 'jwk' in header:
            self.warnings.append(SecurityWarning(
                severity="high",
                category="Header",
                message="Token contains embedded 'jwk' (public key) in header",
                recommendation="Verify public keys from trusted sources only. Embedded keys can enable algorithm confusion attacks."
            ))
        
        # Check for 'kid' manipulation
        if 'kid' in header:
            kid = header['kid']
            # Check for path traversal attempts
            if '../' in str(kid) or '..\\' in str(kid):
                self.warnings.append(SecurityWarning(
                    severity="high",
                    category="Header",
                    message=f"Suspicious 'kid' value with path traversal characters: {kid}",
                    recommendation="Validate 'kid' parameter strictly to prevent path traversal attacks."
                ))
            # Check for SQL injection patterns
            if any(pattern in str(kid).lower() for pattern in ["'", '"', '--', ';', 'union']):
                self.warnings.append(SecurityWarning(
                    severity="high",
                    category="Header",
                    message=f"Suspicious 'kid' value with SQL injection patterns: {kid}",
                    recommendation="Sanitize 'kid' parameter to prevent SQL injection."
                ))
    
    def _analyze_payload(self, payload: Dict):
        """Analyze JWT payload for security issues"""
        
        # Check for missing expiration
        if 'exp' not in payload:
            self.warnings.append(SecurityWarning(
                severity="medium",
                category="Payload",
                message="Token has no expiration time ('exp' claim)",
                recommendation="Always set expiration time for tokens to limit their lifetime."
            ))
        
        # Check for very long expiration
        if 'exp' in payload and 'iat' in payload:
            lifetime = payload['exp'] - payload['iat']
            if lifetime > 86400 * 365:  # More than 1 year
                self.warnings.append(SecurityWarning(
                    severity="medium",
                    category="Payload",
                    message=f"Token has very long lifetime: {lifetime // 86400} days",
                    recommendation="Use shorter token lifetimes (hours to days) for better security."
                ))
        
        # Check for sensitive data in payload
        sensitive_keys = ['password', 'secret', 'api_key', 'private_key', 'ssn', 
                         'credit_card', 'card_number']
        found_sensitive = [key for key in payload.keys() 
                          if any(sensitive in key.lower() for sensitive in sensitive_keys)]
        
        if found_sensitive:
            self.warnings.append(SecurityWarning(
                severity="high",
                category="Payload",
                message=f"Token may contain sensitive data: {', '.join(found_sensitive)}",
                recommendation="Never store sensitive data in JWT payload - it's only base64 encoded, not encrypted."
            ))
    
    def _parse_timestamps(self, payload: Dict) -> Dict:
        """Parse and humanize timestamp claims"""
        timestamp_info = {}
        
        # exp - Expiration Time
        if 'exp' in payload:
            exp = payload['exp']
            timestamp_info['exp'] = {
                'value': exp,
                'human': humanize_timestamp(exp),
                'expired': is_expired(exp),
                'time_remaining': time_until_expiry(exp)
            }
        
        # iat - Issued At
        if 'iat' in payload:
            iat = payload['iat']
            timestamp_info['iat'] = {
                'value': iat,
                'human': humanize_timestamp(iat)
            }
        
        # nbf - Not Before
        if 'nbf' in payload:
            nbf = payload['nbf']
            timestamp_info['nbf'] = {
                'value': nbf,
                'human': humanize_timestamp(nbf),
                'active': nbf <= datetime.now(timezone.utc).timestamp()
            }
        
        return timestamp_info
    
    def format_analysis(self, analysis: JWTAnalysis, colors: bool = True) -> str:
        """
        Format analysis result as human-readable string.
        
        Args:
            analysis: JWTAnalysis object
            colors: Whether to use ANSI colors
            
        Returns:
            Formatted string
        """
        from colorama import Fore, Style, init
        if colors:
            init()
        
        lines = []
        
        # Header
        lines.append("=" * 70)
        lines.append("JWT SECURITY ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        
        # Algorithm Info
        lines.append(f"Algorithm: {analysis.algorithm} ({analysis.algorithm_type.value})")
        lines.append("")
        
        # Header
        lines.append("HEADER:")
        lines.append(json.dumps(analysis.header, indent=2))
        lines.append("")
        
        # Payload
        lines.append("PAYLOAD:")
        lines.append(json.dumps(analysis.payload, indent=2))
        lines.append("")
        
        # Timestamps
        if analysis.timestamp_info:
            lines.append("TIMESTAMPS:")
            for claim, info in analysis.timestamp_info.items():
                if claim == 'exp':
                    status = f"[{'EXPIRED' if info['expired'] else info['time_remaining']}]"
                    if colors:
                        status = (Fore.RED if info['expired'] else Fore.GREEN) + status + Style.RESET_ALL
                    lines.append(f"  {claim}: {info['human']} {status}")
                elif claim == 'iat':
                    lines.append(f"  {claim}: {info['human']}")
                elif claim == 'nbf':
                    status = f"[{'ACTIVE' if info['active'] else 'NOT YET ACTIVE'}]"
                    if colors:
                        status = (Fore.GREEN if info['active'] else Fore.YELLOW) + status + Style.RESET_ALL
                    lines.append(f"  {claim}: {info['human']} {status}")
            lines.append("")
        
        # Security Warnings
        if analysis.warnings:
            lines.append("SECURITY WARNINGS:")
            for i, warning in enumerate(analysis.warnings, 1):
                severity_color = {
                    'critical': Fore.RED,
                    'high': Fore.MAGENTA,
                    'medium': Fore.YELLOW,
                    'low': Fore.CYAN
                }
                
                if colors:
                    severity_text = severity_color.get(warning.severity, '') + \
                                  f"[{warning.severity.upper()}]" + Style.RESET_ALL
                else:
                    severity_text = f"[{warning.severity.upper()}]"
                
                lines.append(f"\n  {i}. {severity_text} {warning.category}")
                lines.append(f"     {warning.message}")
                lines.append(f"     → {warning.recommendation}")
            lines.append("")
        else:
            lines.append("✓ No security warnings found")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# Import datetime for timestamp parsing
from datetime import datetime, timezone
