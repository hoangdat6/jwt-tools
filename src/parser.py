"""JWT Parser and Analyzer - Simplified with Security Analyzer"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone

from .utils.base64url import base64url_decode
from .utils.time_utils import humanize_timestamp, is_expired, time_until_expiry
from .security_analyzer import JWTSecurityAnalyzer, SecurityWarning


class AlgorithmType(Enum):
    """JWT Algorithm Types"""
    NONE = "none"
    SYMMETRIC = "symmetric"  # HS256, HS384, HS512
    ASYMMETRIC = "asymmetric"  # RS256, RS384, RS512, ES256, PS256, etc.
    UNKNOWN = "unknown"


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
    security_score: int  # 0-100, lower is worse


class JWTParser:
    """JWT Parser and Security Analyzer"""
    
    SYMMETRIC_ALGORITHMS = ['HS256', 'HS384', 'HS512']
    ASYMMETRIC_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 
                             'PS256', 'PS384', 'PS512', 'EdDSA']
    
    def __init__(self):
        self.security_analyzer = JWTSecurityAnalyzer()
    
    def parse(self, token: str) -> JWTAnalysis:
        """
        Parse and analyze a JWT token with comprehensive security checks.
        
        Args:
            token: JWT token string
            
        Returns:
            JWTAnalysis object with all parsed information
            
        Raises:
            ValueError: If token format is invalid
        """
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
        
        # Security analysis (delegated to SecurityAnalyzer)
        warnings, security_score = self.security_analyzer.analyze(
            header=header,
            payload=payload,
            signature=signature_b64,
            algorithm=algorithm,
            algorithm_type=algorithm_type.value
        )
        
        # Parse timestamps
        timestamp_info = self._parse_timestamps(payload)
        
        return JWTAnalysis(
            raw_token=token,
            header=header,
            payload=payload,
            signature=signature_b64,
            algorithm=algorithm,
            algorithm_type=algorithm_type,
            warnings=warnings,
            timestamp_info=timestamp_info,
            security_score=security_score
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
                'human': humanize_timestamp(iat),
                'time_remaining': self._time_since(iat)
            }
        
        # nbf - Not Before
        if 'nbf' in payload:
            nbf = payload['nbf']
            current_time = datetime.now(timezone.utc).timestamp()
            timestamp_info['nbf'] = {
                'value': nbf,
                'human': humanize_timestamp(nbf),
                'active': nbf <= current_time,
                'time_remaining': self._time_until(nbf) if nbf > current_time else f"active since {self._time_since(nbf)}"
            }
        
        return timestamp_info
    
    def _time_since(self, timestamp: int) -> str:
        """Calculate time since timestamp"""
        current_time = datetime.now(timezone.utc).timestamp()
        diff = int(current_time - timestamp)
        
        if diff < 60:
            return f"{diff} seconds ago"
        elif diff < 3600:
            return f"{diff // 60} minutes ago"
        elif diff < 86400:
            return f"{diff // 3600} hours ago"
        else:
            return f"{diff // 86400} days ago"
    
    def _time_until(self, timestamp: int) -> str:
        """Calculate time until timestamp"""
        current_time = datetime.now(timezone.utc).timestamp()
        diff = int(timestamp - current_time)
        
        if diff < 60:
            return f"in {diff} seconds"
        elif diff < 3600:
            return f"in {diff // 60} minutes"
        elif diff < 86400:
            return f"in {diff // 3600} hours"
        else:
            return f"in {diff // 86400} days"
    
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
        
        # Security Score
        score_color = Fore.GREEN if analysis.security_score >= 80 else \
                     Fore.YELLOW if analysis.security_score >= 60 else \
                     Fore.RED
        if colors:
            score_text = score_color + f"Security Score: {analysis.security_score}/100" + Style.RESET_ALL
        else:
            score_text = f"Security Score: {analysis.security_score}/100"
        lines.append(score_text)
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
                    lines.append(f"  {claim}: {info['human']} ({info['time_remaining']})")
                elif claim == 'nbf':
                    status = f"[{'ACTIVE' if info['active'] else 'NOT YET ACTIVE'}]"
                    if colors:
                        status = (Fore.GREEN if info['active'] else Fore.YELLOW) + status + Style.RESET_ALL
                    lines.append(f"  {claim}: {info['human']} {status}")
            lines.append("")
        
        # Security Warnings
        if analysis.warnings:
            lines.append(f"SECURITY WARNINGS ({len(analysis.warnings)} found):")
            for i, warning in enumerate(analysis.warnings, 1):
                severity_color = {
                    'critical': Fore.RED,
                    'high': Fore.MAGENTA,
                    'medium': Fore.YELLOW,
                    'low': Fore.CYAN,
                    'info': Fore.BLUE
                }
                
                if colors:
                    severity_text = severity_color.get(warning.severity, '') + \
                                  f"[{warning.severity.upper()}]" + Style.RESET_ALL
                else:
                    severity_text = f"[{warning.severity.upper()}]"
                
                lines.append(f"\n  {i}. {severity_text} {warning.category}")
                lines.append(f"     {warning.message}")
                lines.append(f"     → {warning.recommendation}")
                if warning.cve:
                    lines.append(f"     CVE: {warning.cve}")
                if warning.owasp:
                    lines.append(f"     OWASP: {warning.owasp}")
            lines.append("")
        else:
            lines.append("✓ No security warnings found")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
